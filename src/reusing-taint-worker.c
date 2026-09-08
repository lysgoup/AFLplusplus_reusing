/*
   american fuzzy lop++ - reusing pool: external taint-analysis worker
   ---------------------------------------------------------------------

   Standalone driver, deliberately kept out of afl-fuzz's own process and
   source (branch policy for external-taint-worker: don't touch the
   fuzzer's own code). Watches a running campaign's <out_dir>/queue/
   directory and, for every newly appearing queue entry, runs it through
   a dtaint-instrumented binary and drops the resulting .dtaint track
   file into <out_dir>/dtaint_logs/ -- same directory, same naming
   convention (<queue_entry_basename>.dtaint) real-dfsan-vendor's own
   in-process log_dtaint_for_new_input() (src/afl-fuzz-dtaint.c on that
   branch) already uses, so whatever later reads those files back
   (reusing_ingest_dtaint() -- not ported to this branch yet, that's a
   separate step) doesn't care which process produced them.

   Protocol mirrors real-dfsan-vendor's include/dtaint.h exactly, kept as
   a couple of #defines here rather than pulling that whole header in --
   this step only *produces* .dtaint files, it doesn't parse the binary
   format at all:
     - AFL_DTAINT_TRACK_FILE points the dtaint binary at a *fixed*
       per-session scratch path, set once in the environment before the
       forkserver's one-time execve() -- the forkserver protocol forks
       already-running children for every later run and never re-execs
       or re-reads the environment, so this can't vary per call.
     - after each run, if that scratch file exists, it gets renamed to
       <out_dir>/dtaint_logs/<queue_entry_basename>.dtaint. No file means
       the target had nothing taint-worthy to report for that input, not
       an error.

   Two independent modes (see usage()/-h for the full flag reference):
     - Seed-scan (-S seed_dir): one-shot batch job, run once ahead of time
       per seed_dir, completely independent of any campaign. Dtaints every
       file in seed_dir and writes "<filename>.dtaint" into a flat cache
       dir (-o in this mode), then exits.
     - Live (default): watches a running campaign's queue/, same as
       before. Optional -c cache_dir points it at a seed-scan cache built
       for the *same* seed_dir this campaign's afl-fuzz -i uses -- since
       AFL++'s own dry run copies -i's files into the queue byte-for-byte
       (named "id:NNNNNN,...,orig:<seed's own filename>..."), a queue
       entry whose "orig:<name>" matches a cache entry is analyzing
       something already analyzed, so process_queue_entry() copies the
       cached result instead of re-deriving it.
   Kept as two genuinely separate modes (not one "-s then keep watching"
   flag) because they have different lifecycles: the cache is meant to
   outlive and be reused across many campaign runs against the same
   seed_dir, not rebuilt by whichever campaign happens to run first.

   Reuses AFL++'s own generic forkserver primitives completely unmodified
   (afl-forkserver.c/afl-common.c/afl-sharedmem.c/afl-performance.c) --
   the same building blocks afl-showmap/afl-tmin already link against,
   none of it fuzzer-orchestration-specific. Structurally this file is a
   trimmed-down afl-showmap.c: same option-parsing/forkserver-setup
   shape, swapping "read coverage bitmap" for "drive the dtaint binary
   and stash its track file."

   Known limitations (accepted for this step, not engineered around):
   - Detects new queue entries by polling + a monotonically increasing
     "highest id processed" watermark, not inotify. A queue file that
     fails to read cleanly (fuzzer still mid-write) is logged and
     skipped -- never retried. In practice AFL++ queue files are written
     start-to-finish in one syscall burst before appearing in a listing
     at their final name, so this window is not expected to matter.
   - No persistence of the watermark across restarts; restarting this
     tool re-processes the whole queue from id 0. Harmless (dtaint runs
     are idempotent, output is overwritten), just wasted recompute.
   - Only understands the default (non-SIMPLE_FILES, non-SHA1_FILENAMES)
     queue filename shapes: "id:NNNNNN,..." and the SIMPLE_FILES
     "id_NNNNNN" form. AFL_SHA1_FILENAMES mode carries no ordinal at all
     and isn't handled.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "forkserver.h"
#include "sharedmem.h"
#include "common.h"
#include "dtaint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* DTAINT_TRACK_ENV_VAR / DTAINT_SCRATCH_NAME now come straight from
   include/dtaint.h (vendored in from real-dfsan-vendor) -- this step
   only produces .dtaint files, never parses the rest of that header's
   record structs. */

/* Matches this project's own run.sh convention (tools/volume run.sh
   scripts set AFL_MAP_SIZE=256000) so the dtaint binary allocates the
   same map it always does under a real campaign. */
#define WORKER_MAP_SIZE 256000

static volatile u8 stop_soon;
static u8           quiet_mode = 0;

static void handle_stop_sig(int sig) {

  (void)sig;
  stop_soon = 1;
  afl_fsrv_killall();

}

static void worker_setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler = NULL;
#ifdef SA_RESTART
  sa.sa_flags = SA_RESTART;
#else
  sa.sa_flags = 0;
#endif
  sa.sa_sigaction = NULL;
  sigemptyset(&sa.sa_mask);

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

}

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -o out_dir -- /path/to/dtaint_binary [...]\n\n"

      "Two independent modes, one binary:\n\n"

      "  Seed-scan mode (-S): a one-shot batch job. Runs dtaint over every "
      "file\n"
      "  in seed_dir once, writes \"<filename>.dtaint\" into out_dir (a "
      "flat\n"
      "  cache dir, reusable across every future campaign that fuzzes this "
      "same\n"
      "  seed_dir), then exits. Run this once, ahead of time, per seed_dir "
      "-- it\n"
      "  does not watch anything and does not run alongside a campaign.\n"
      "  Example: %s -S /path/to/seeds -o /path/to/cache -- "
      "/d/p/.../dtaint/jq . @@\n\n"

      "  Live mode (default, no -S): watches out_dir's queue/ for a running "
      "AFL++\n"
      "  campaign, in parallel with it, and dtaint-analyzes each new entry "
      "as it\n"
      "  appears. Pass -c pointing at a seed-scan cache dir built for the "
      "same\n"
      "  seed_dir this campaign's afl-fuzz -i uses, and any queue entry "
      "that's\n"
      "  really just an unmutated dry-run seed copy is an instant cache "
      "hit\n"
      "  instead of redundant re-analysis.\n"
      "  Example: %s -o /path/to/campaign -c /path/to/cache -- "
      "/d/p/.../dtaint/jq . @@\n\n"

      "Required parameters:\n"
      "  -o out_dir    - seed-scan mode: flat dir to write the cache into.\n"
      "                  live mode: the fuzzer campaign's output dir (same "
      "path\n"
      "                  passed to afl-fuzz's own -o).\n\n"

      "Optional parameters:\n"
      "  -S seed_dir   - run in seed-scan mode against seed_dir (see "
      "above). Not\n"
      "                  combinable with -c.\n"
      "  -c cache_dir  - live mode only: consult a -S-built cache dir for "
      "orig:\n"
      "                  matches before running dtaint on a dry-run-seed "
      "queue\n"
      "                  entry.\n"
      "  -i seed_dir   - live mode only: the same dir afl-fuzz's own -i "
      "points\n"
      "                  at. On a -c cache miss, checks whether the entry "
      "is a\n"
      "                  real file in seed_dir (by key, not by guessing "
      "from the\n"
      "                  queue filename) -- if so, it's a seed the -S "
      "pre-pass\n"
      "                  itself couldn't finish in time, and it's skipped "
      "rather\n"
      "                  than retried live against a timeout we already "
      "know\n"
      "                  won't resolve.\n"
      "  -t msec       - timeout for each dtaint run (default: 5000)\n"
      "  -m megs       - memory limit for the dtaint binary, 'none' for "
      "unlimited\n"
      "                  (default: none)\n"
      "  -p sec        - live mode: queue poll interval in seconds "
      "(default: 2)\n"
      "  -Q            - quiet mode\n\n"

      "Always on, no flag needed, written once the run ends, next to "
      "wherever\n"
      "this run's own .dtaint outputs land (work_dir):\n"
      "  value_pool.dict      - every tainted value behind a NEW comparison "
      "\n"
      "                         outcome (a (site, context, condition) combo "
      "\n"
      "                         never seen before in this run), across both "
      "\n"
      "                         modes' full lifetime. Each line is a JSON-"
      "style\n"
      "                         array of quoted, \\xNN-escaped byte strings "
      "--\n"
      "                         [\"...\"] for a magic-byte chain or a "
      "single-\n"
      "                         segment value, [\"...\",\"...\"] for a "
      "multi-\n"
      "                         segment taint label (one element per "
      "segment,\n"
      "                         in order). NOT AFL++ -x syntax -- meant for "
      "a\n"
      "                         downstream reader of this tool's own. "
      "Anything\n"
      "                         shorter than 2 bytes is dropped unless it's "
      "part\n"
      "                         of a multi-segment label. Rows are sorted "
      "by\n"
      "                         segment-length pattern, annotated with "
      "\"# label\n"
      "                         pattern: [...]\" comments.\n"
      "  unsolved_condition   - every (cmpid, context) site whose "
      "condition has\n"
      "                         never gone more than one way across "
      "everything\n"
      "                         analyzed so far (a switch always counts as "
      "\n"
      "                         unsolved) -- just cmpid and context, meant "
      "as\n"
      "                         mutation targets still worth attacking.\n\n"

      "Use '@@' in the target command line to have it substituted with the "
      "path\n"
      "to the input file. Without '@@', input is fed via stdin, matching "
      "afl-fuzz's own convention.\n\n",
      argv0, argv0, argv0);

  exit(1);

}

/* Parses the ordinal out of a queue entry's basename. Handles both the
   default "id:NNNNNN,..." shape (describe_op(), src/afl-fuzz-bitmap.c)
   and the SIMPLE_FILES "id_NNNNNN" shape. Returns 0 on success. */
static u8 parse_queue_id(const char *name, u32 *id_out) {

  if (sscanf(name, "id:%u", id_out) == 1) return 0;
  if (sscanf(name, "id_%u", id_out) == 1) return 0;
  return 1;

}

/* Extracts the "orig:<name>" field AFL++ gives an unmutated dry-run seed's
   queue entry (afl-fuzz-init.c's seed-loading path -- distinct from
   describe_op()'s "src:NNNNNN,...op:..." shape for real havoc-derived
   discoveries, which never carries an "orig:" field). Returns a ck_alloc'd
   string the caller ck_free()s, or NULL if fname has no such field. */
static u8 *extract_orig_name(const char *fname) {

  const char *p = strstr(fname, "orig:");
  if (!p) return NULL;
  p += 5;

  const char *comma = strchr(p, ',');
  size_t      len = comma ? (size_t)(comma - p) : strlen(p);
  u8         *out = ck_alloc(len + 1);
  memcpy(out, p, len);
  out[len] = 0;

  return out;

}

typedef struct {

  u32 id;
  u8 *name;

} queue_entry_ref_t;

static int cmp_queue_entry_ref(const void *a, const void *b) {

  const queue_entry_ref_t *ea = a, *eb = b;
  if (ea->id < eb->id) return -1;
  if (ea->id > eb->id) return 1;
  return 0;

}

/* Scans queue_dir for entries with id > after_id, sorted ascending.
   Caller ck_free()s both the returned array and each ->name in it.

   ENOENT is not fatal here: afl-fuzz creates <out_dir>/default *before* it
   creates queue/ under it, and with a large seed corpus (a real one seen
   in testing: 10k+ files), the calibration/dry-run pass over every seed
   can easily take longer than the couple of seconds a launcher script
   sleeps before starting this worker -- so a poll landing before queue/
   exists yet is an expected, normal startup race, not an error. Any other
   opendir() failure (permissions, etc) still PFATALs -- that's a real
   problem worth surfacing loudly, not silently retried forever. */
static queue_entry_ref_t *scan_new_queue_entries(const char *queue_dir,
                                                 s64 after_id, u32 *n_out) {

  DIR *d = opendir(queue_dir);

  if (!d) {

    if (errno == ENOENT) {

      *n_out = 0;
      return NULL;

    }

    PFATAL("Unable to open queue dir '%s'", queue_dir);

  }

  queue_entry_ref_t *entries = NULL;
  u32                 n = 0, cap = 0;

  struct dirent *de;
  while ((de = readdir(d))) {

    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;

    /* Skip AFL++'s own bookkeeping subdirs (.state/, signal/, etc). We
       only care about the flat queue entry files sitting directly in
       queue/. */
#ifdef DT_DIR
    if (de->d_type == DT_DIR) continue;
#endif
    if (de->d_name[0] == '.') continue;

    u32 id;
    if (parse_queue_id(de->d_name, &id)) continue;
    if ((s64)id <= after_id) continue;

    if (n >= cap) {

      cap = cap ? cap * 2 : 16;
      entries = ck_realloc(entries, cap * sizeof(queue_entry_ref_t));

    }

    entries[n].id = id;
    entries[n].name = (u8 *)strdup(de->d_name);
    ++n;

  }

  closedir(d);

  if (n) qsort(entries, n, sizeof(queue_entry_ref_t), cmp_queue_entry_ref);

  *n_out = n;
  return entries;

}

/* Plain file copy (not rename()): used to pull a hit out of seed_cache_dir
   without disturbing the original -- that cache is meant to be reused
   across every campaign run against the same seed_dir, not consumed by the
   first one. Returns 0 on success. */
static u8 copy_file(const char *src, const char *dst) {

  s32 in_fd = open(src, O_RDONLY);
  if (in_fd < 0) return 1;

  s32 out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
  if (out_fd < 0) {

    close(in_fd);
    return 1;

  }

  u8      buf[65536];
  ssize_t rd;
  u8      err = 0;

  while ((rd = read(in_fd, buf, sizeof(buf))) > 0) {

    if (write(out_fd, buf, (size_t)rd) != rd) {

      err = 1;
      break;

    }

  }

  if (rd < 0) err = 1;

  close(in_fd);
  close(out_fd);
  return err;

}

/* Tries a cache lookup for `key`.dtaint, first under work_dir (an earlier
   entry in *this* run already covered it), then under seed_cache_dir (if
   given -- a previously-built -S cache). On a work_dir hit nothing needs
   copying (it's already exactly where it needs to be); on a
   seed_cache_dir hit, copies (never moves -- see copy_file()) it in under
   fname's own name. Returns 1 if it handled fname (caller should stop),
   0 on a full miss (caller should fall through to live analysis). */
static u8 try_seed_cache(const char *work_dir, const char *seed_cache_dir,
                         const char *key, const char *fname) {

  u8 *local_hit = alloc_printf("%s/%s.dtaint", work_dir, key);

  if (access((char *)local_hit, F_OK) == 0) {

    if (!quiet_mode) { OKF("dtaint: %s -> %s (seed cache hit)", fname, local_hit); }
    ck_free(local_hit);
    return 1;

  }

  ck_free(local_hit);

  if (seed_cache_dir) {

    u8 *cache_hit = alloc_printf("%s/%s.dtaint", seed_cache_dir, key);

    if (access((char *)cache_hit, F_OK) == 0) {

      u8 *dest = alloc_printf("%s/%s.dtaint", work_dir, fname);

      if (copy_file((char *)cache_hit, (char *)dest)) {

        WARNF("Could not copy seed cache hit '%s' -> '%s': %s", cache_hit,
              dest, strerror(errno));

      } else if (!quiet_mode) {

        OKF("dtaint: %s -> %s (seed cache hit, -c)", fname, dest);

      }

      ck_free(dest);
      ck_free(cache_hit);
      return 1;

    }

    ck_free(cache_hit);

  }

  return 0;

}

/* ---------------------------------------------------------------------- */
/* Interesting-value dictionary -- accumulated across every execution for  */
/* the life of the process (both -S batch mode and a live campaign),       */
/* written out once at exit via -D. A value is collected from ANY tainted  */
/* comparison, any op, whichever way it came out, the first time its       */
/* (cmpid, context, condition) combination is ever seen (see               */
/* novelty_check_and_mark() below) -- not gated on "matched" a constant.    */
/* Every output line is a JSON-style array of quoted, \xNN-escaped byte    */
/* strings: one element for a magic-byte chain or single-segment value,    */
/* one element per segment (in order) for a multi-segment taint label.     */
/* Not AFL++ dictionary syntax (see src/afl-fuzz-extras.c's                */
/* load_extras_file() for that format) -- meant for a downstream reader    */
/* of this tool's own that cares about per-segment structure.              */
/* ---------------------------------------------------------------------- */

#define WORKER_DICT_MAX_ENTRIES 10000
#define WORKER_DICT_MAX_ENTRY_LEN 32

typedef struct {

  u8 *data;
  u32 len;

} dict_entry_t;

/* One segment of a multi-segment taint label, kept distinct rather than
   concatenated: group_id ties every segment of the same label together.
   Entries sharing a group_id are always added contiguously (one
   dict_add_group() call writes a whole group before the next one starts),
   so dict_write() can render each run as a single `["...","..."]` line --
   not AFL dictionary syntax at all, meant purely for a downstream reader
   that cares which segments belonged to the same original taint label. */
typedef struct {

  u32 group_id;
  u8 *data;
  u32 len;

} group_entry_t;

typedef struct {

  dict_entry_t *entries;
  u32           count;
  u32           cap;

  group_entry_t *groups;
  u32            groups_count;
  u32            groups_cap;
  u32            next_group_id;

} worker_dict_t;

static void dict_init(worker_dict_t *d) {

  d->entries = NULL;
  d->count = 0;
  d->cap = 0;

  d->groups = NULL;
  d->groups_count = 0;
  d->groups_cap = 0;
  d->next_group_id = 0;

}

/* Dedup domain for plain standalone entries only -- group membership is a
   separate dedup domain (see dict_group_exists()), so a value already
   sitting inside a group doesn't block it from also being recorded as its
   own standalone entry, and vice versa. */
static u8 dict_contains(worker_dict_t *d, const u8 *data, u32 len) {

  for (u32 i = 0; i < d->count; i++) {

    if (d->entries[i].len == len && !memcmp(d->entries[i].data, data, len)) return 1;

  }

  return 0;

}

/* No-op if data/len is empty, absurdly long for a magic constant (32+
   bytes strongly suggests a mis-grouped run, not a real fixed value), the
   global cap is already hit, or this exact value is already in the set. */
static void dict_add(worker_dict_t *d, const u8 *data, u32 len) {

  if (!d || !data || !len || len > WORKER_DICT_MAX_ENTRY_LEN) return;
  if (d->count >= WORKER_DICT_MAX_ENTRIES) return;
  if (dict_contains(d, data, len)) return;

  if (d->count == d->cap) {

    d->cap = d->cap ? d->cap * 2 : 64;
    d->entries = ck_realloc(d->entries, d->cap * sizeof(dict_entry_t));

  }

  d->entries[d->count].data = ck_alloc(len);
  memcpy(d->entries[d->count].data, data, len);
  d->entries[d->count].len = len;
  d->count++;

}

/* Whole-group dedup: does an already-stored group consist of exactly
   these same n_segs segment values, in the same order? Partial matches
   don't count -- the group's identity is the complete ordered set, not
   any individual member. */
static u8 dict_group_exists(worker_dict_t *d, struct dtaint_tag_seg_wire *segs, u32 n_segs,
                            const u8 *orig_input, u32 orig_input_len) {

  u32 i = 0;

  while (i < d->groups_count) {

    u32 gid = d->groups[i].group_id;
    u32 start = i;

    while (i < d->groups_count && d->groups[i].group_id == gid) i++;

    if (i - start != n_segs) continue;

    u8 all_match = 1;

    for (u32 s = 0; s < n_segs && all_match; s++) {

      u32 b = segs[s].begin, e = segs[s].end;
      if (e > orig_input_len || d->groups[start + s].len != e - b ||
          memcmp(d->groups[start + s].data, orig_input + b, e - b)) {

        all_match = 0;

      }

    }

    if (all_match) return 1;

  }

  return 0;

}

/* Records every segment of a multi-segment taint label under a fresh
   shared group_id, so a downstream reader can later reconstruct "these N
   byte ranges came from the same label". Unlike dict_add(), a group is
   never partially stored: either every segment passes the bounds/size
   sanity check and the whole group is new (dict_group_exists() says no),
   in which case all n_segs segments go in together, or nothing does.
   No-op for a single-segment label (nothing to distinguish) or a
   pathologically wide one (a label combine()d from dozens of segments is
   almost certainly the MAX_COND_ORDER-style saturation case, not a
   meaningful structured value). */
static void dict_add_group(worker_dict_t *d, struct dtaint_tag_seg_wire *segs, u32 n_segs,
                           const u8 *orig_input, u32 orig_input_len) {

  if (!d || !segs || n_segs < 2 || n_segs > 64) return;

  for (u32 s = 0; s < n_segs; s++) {

    u32 b = segs[s].begin, e = segs[s].end;
    if (e <= b || e > orig_input_len || (e - b) > WORKER_DICT_MAX_ENTRY_LEN) return;

  }

  if (dict_group_exists(d, segs, n_segs, orig_input, orig_input_len)) return;
  if (d->groups_count + n_segs > WORKER_DICT_MAX_ENTRIES) return;

  u32 gid = d->next_group_id++;

  for (u32 s = 0; s < n_segs; s++) {

    u32 b = segs[s].begin, e = segs[s].end;

    if (d->groups_count == d->groups_cap) {

      d->groups_cap = d->groups_cap ? d->groups_cap * 2 : 64;
      d->groups = ck_realloc(d->groups, d->groups_cap * sizeof(group_entry_t));

    }

    d->groups[d->groups_count].group_id = gid;
    d->groups[d->groups_count].data = ck_alloc(e - b);
    memcpy(d->groups[d->groups_count].data, orig_input + b, e - b);
    d->groups[d->groups_count].len = e - b;
    d->groups_count++;

  }

}

/* AFL++ dictionary line escaping (mirrors load_extras_file()'s reader
   exactly, in reverse): printable ASCII passes through as-is; '\\' and
   '"' get backslash-escaped; everything else (including any embedded NUL,
   which a plain fgets()-based reader could never see past otherwise)
   becomes \xNN. */
static void dict_write_escaped(FILE *f, const u8 *data, u32 len) {

  for (u32 i = 0; i < len; i++) {

    u8 c = data[i];

    if (c == '\\' || c == '"') {

      fputc('\\', f);
      fputc(c, f);

    } else if (c >= 32 && c < 127) {

      fputc(c, f);

    } else {

      fprintf(f, "\\x%02x", c);

    }

  }

}

/* One output line's worth of segments -- a standalone entry is a
   1-segment row, a group is an n_segs-segment row. lens[] doubles as
   both "this row's label pattern" and each segment's actual byte length
   (they're the same number). datas[] points at existing storage (owned
   by d->entries/d->groups), never copied. */
typedef struct {

  u32   n_segs;
  u32  *lens;
  u8  **datas;

} dict_row_t;

/* Sort key: fewer segments first, then lexicographically by segment
   length in order (the first segment's size breaks ties before the
   second's, and so on) -- i.e. ascending by the label pattern itself. */
static int cmp_dict_row(const void *a, const void *b) {

  const dict_row_t *ra = a, *rb = b;

  if (ra->n_segs != rb->n_segs) return (ra->n_segs > rb->n_segs) - (ra->n_segs < rb->n_segs);

  for (u32 i = 0; i < ra->n_segs; i++) {

    if (ra->lens[i] != rb->lens[i]) return (ra->lens[i] > rb->lens[i]) - (ra->lens[i] < rb->lens[i]);

  }

  return 0;

}

static u8 dict_row_same_pattern(const dict_row_t *a, const dict_row_t *b) {

  if (a->n_segs != b->n_segs) return 0;

  for (u32 i = 0; i < a->n_segs; i++) {

    if (a->lens[i] != b->lens[i]) return 0;

  }

  return 1;

}

static void dict_write(worker_dict_t *d, const char *path) {

  if (!d || (!d->count && !d->groups_count)) return;

  FILE *f = fopen(path, "w");
  if (!f) {

    WARNF("Could not open '%s' for writing dictionary: %s", path, strerror(errno));
    return;

  }

  fprintf(f, "# extracted by reusing-taint-worker -- %u entries, %u grouped segments\n",
          d->count, d->groups_count);

  /* Count groups (contiguous group_id runs) first, to size the row array. */
  u32 n_groups = 0;

  for (u32 i = 0; i < d->groups_count; ) {

    u32 gid = d->groups[i].group_id;
    while (i < d->groups_count && d->groups[i].group_id == gid) i++;
    n_groups++;

  }

  u32         n_rows = d->count + n_groups;
  dict_row_t *rows = n_rows ? ck_alloc(n_rows * sizeof(dict_row_t)) : NULL;
  u32         ri = 0;

  for (u32 i = 0; i < d->count; i++) {

    rows[ri].n_segs = 1;
    rows[ri].lens = ck_alloc(sizeof(u32));
    rows[ri].lens[0] = d->entries[i].len;
    rows[ri].datas = ck_alloc(sizeof(u8 *));
    rows[ri].datas[0] = d->entries[i].data;
    ri++;

  }

  for (u32 i = 0; i < d->groups_count; ) {

    u32 gid = d->groups[i].group_id;
    u32 start = i;

    while (i < d->groups_count && d->groups[i].group_id == gid) i++;

    u32 n = i - start;
    rows[ri].n_segs = n;
    rows[ri].lens = ck_alloc(n * sizeof(u32));
    rows[ri].datas = ck_alloc(n * sizeof(u8 *));

    for (u32 s = 0; s < n; s++) {

      rows[ri].lens[s] = d->groups[start + s].len;
      rows[ri].datas[s] = d->groups[start + s].data;

    }

    ri++;

  }

  if (n_rows) qsort(rows, n_rows, sizeof(dict_row_t), cmp_dict_row);

  for (u32 i = 0; i < n_rows; i++) {

    if (i == 0 || !dict_row_same_pattern(&rows[i - 1], &rows[i])) {

      fprintf(f, "# label pattern: [");

      for (u32 s = 0; s < rows[i].n_segs; s++) {

        if (s) fputc(',', f);
        fprintf(f, "%u", rows[i].lens[s]);

      }

      fputs("]\n", f);

    }

    fputc('[', f);

    for (u32 s = 0; s < rows[i].n_segs; s++) {

      if (s) fputc(',', f);
      fputc('"', f);
      dict_write_escaped(f, rows[i].datas[s], rows[i].lens[s]);
      fputc('"', f);

    }

    fputs("]\n", f);

  }

  for (u32 i = 0; i < n_rows; i++) {

    ck_free(rows[i].lens);
    ck_free(rows[i].datas);

  }

  if (rows) ck_free(rows);

  fclose(f);

  if (!quiet_mode) {

    OKF("Wrote %u dictionary entries (%u grouped segments) to '%s'.",
        d->count, d->groups_count, path);

  }

}

/* ---------------------------------------------------------------------- */
/* Magic-byte grouping -- ported from Angora's own                         */
/* fuzzer/src/track/fparser.rs (is_magic_byte_cmp() lives in                */
/* common/src/cond_stmt_base.rs, group_adjacent_one_byte_magic_bytes() in   */
/* fparser.rs itself). Runs once per completed dtaint execution, right     */
/* after the run finishes, transcoding the runtime's raw v2 scratch file   */
/* into this tool's own v3 output format (include/dtaint.h) before it's    */
/* persisted or cached: a multi-byte magic constant that the compiler      */
/* split into several per-byte icmp comparisons (or an unrolled            */
/* memcmp/strcmp) shouldn't look like N independent 1-byte constraints to  */
/* anything consuming this file downstream.                                */
/* ---------------------------------------------------------------------- */

#define WORKER_ICMP_EQ 32U
#define WORKER_ICMP_NE 33U
#define WORKER_OP_BASIC_MASK 0xFFU

/* Mirrors CondStmtBase::is_magic_byte_cmp() exactly: either a
   strcmp/memcmp-family call (always magic-byte), or a plain equality/
   inequality compare where exactly one side is tainted (the other is a
   fixed constant -- if both sides are tainted it's an input-vs-input
   compare, not a constant check). */
static u8 is_magic_byte_cmp(u32 op, u32 lb1, u32 lb2) {

  if (op == DTAINT_COND_FN_OP) return 1;

  u32 basic = op & WORKER_OP_BASIC_MASK;
  if (basic != WORKER_ICMP_EQ && basic != WORKER_ICMP_NE) return 0;

  return (lb1 > 0) != (lb2 > 0);

}

/* Tracks, for the whole lifetime of the process (every input from every
   file this worker ever runs, live campaign or -S batch alike), which
   (cmpid, context, condition) outcomes have already been seen. A
   comparison site normally settles into one steady outcome once fuzzing
   converges on valid-ish inputs; the *first* time a given site+context
   produces a condition value that's never come up before -- true after
   nothing but false, a new switch-case branch, whatever -- that's a
   concrete sign this input made the site do something the corpus hasn't
   shown before, independent of which side "won". Open-addressing hash set
   with linear probing, since this can grow into the tens of thousands of
   distinct (site, context, outcome) triples over a long campaign. */

#define NOVELTY_INITIAL_CAP 4096

typedef struct {

  u32 cmpid;
  u32 context;
  u32 condition;
  u8  used;

} novelty_slot_t;

typedef struct {

  novelty_slot_t *slots;
  u32             cap;
  u32             count;

} novelty_set_t;

static void novelty_init(novelty_set_t *s) {

  s->cap = NOVELTY_INITIAL_CAP;
  s->slots = ck_alloc(s->cap * sizeof(novelty_slot_t));
  s->count = 0;

}

static u32 novelty_hash(u32 cmpid, u32 context, u32 condition) {

  u32 h = cmpid;
  h = h * 2654435761u ^ context;
  h = h * 2654435761u ^ condition;
  return h;

}

/* Raw insert, no duplicate check -- only ever called on keys already
   confirmed absent (a fresh table during grow, or right after
   novelty_check_and_mark's own probe already proved this key isn't
   there). */
static void novelty_raw_insert(novelty_set_t *s, u32 cmpid, u32 context, u32 condition) {

  u32 idx = novelty_hash(cmpid, context, condition) % s->cap;

  while (s->slots[idx].used) idx = (idx + 1) % s->cap;

  s->slots[idx].used = 1;
  s->slots[idx].cmpid = cmpid;
  s->slots[idx].context = context;
  s->slots[idx].condition = condition;
  s->count++;

}

static void novelty_grow(novelty_set_t *s) {

  novelty_slot_t *old_slots = s->slots;
  u32             old_cap = s->cap;

  s->cap *= 2;
  s->slots = ck_alloc(s->cap * sizeof(novelty_slot_t));
  s->count = 0;

  for (u32 i = 0; i < old_cap; i++) {

    if (old_slots[i].used) {

      novelty_raw_insert(s, old_slots[i].cmpid, old_slots[i].context, old_slots[i].condition);

    }

  }

  ck_free(old_slots);

}

/* Returns 1 (and marks it seen) the first time this exact (cmpid, context,
   condition) triple is encountered; 0 every time after. */
static u8 novelty_check_and_mark(novelty_set_t *s, u32 cmpid, u32 context, u32 condition) {

  if ((u64)(s->count + 1) * 4 >= (u64)s->cap * 3) novelty_grow(s);

  u32 idx = novelty_hash(cmpid, context, condition) % s->cap;

  while (s->slots[idx].used) {

    if (s->slots[idx].cmpid == cmpid && s->slots[idx].context == context &&
        s->slots[idx].condition == condition) {

      return 0;

    }

    idx = (idx + 1) % s->cap;

  }

  novelty_raw_insert(s, cmpid, context, condition);
  return 1;

}

/* ---------------------------------------------------------------------- */
/* Unsolved-condition tracking -- for every (cmpid, context) site that has */
/* taint, remembers which distinct `condition` outcomes have been seen     */
/* across every input this process has ever analyzed (live campaign or -S  */
/* batch alike), so a downstream reader knows which sites have never gone  */
/* more than one way. A site counts as "solved" once 2+ distinct outcomes  */
/* have been observed -- except a switch (DTAINT_COND_SW_OP), which has no */
/* fixed "the other side": it's always reported, no matter how many cases  */
/* have fired.                                                             */
/* ---------------------------------------------------------------------- */

#define COND_STATUS_INITIAL_CAP 4096

typedef struct {

  u32           cmpid;
  u32           context;
  u32           op;
  u32           n_distinct;
  u32           seen_conditions[2];
  u8            used;

} cond_status_slot_t;

typedef struct {

  cond_status_slot_t *slots;
  u32                  cap;
  u32                  count;

} cond_status_set_t;

static void cond_status_init(cond_status_set_t *s) {

  s->cap = COND_STATUS_INITIAL_CAP;
  s->slots = ck_alloc(s->cap * sizeof(cond_status_slot_t));
  s->count = 0;

}

static u32 cond_status_hash(u32 cmpid, u32 context) {

  u32 h = cmpid;
  h = h * 2654435761u ^ context;
  return h;

}

static cond_status_slot_t *cond_status_raw_insert(cond_status_set_t *s, u32 cmpid, u32 context) {

  u32 idx = cond_status_hash(cmpid, context) % s->cap;

  while (s->slots[idx].used) idx = (idx + 1) % s->cap;

  memset(&s->slots[idx], 0, sizeof(cond_status_slot_t));
  s->slots[idx].used = 1;
  s->slots[idx].cmpid = cmpid;
  s->slots[idx].context = context;
  s->count++;

  return &s->slots[idx];

}

static void cond_status_grow(cond_status_set_t *s) {

  cond_status_slot_t *old_slots = s->slots;
  u32                  old_cap = s->cap;

  s->cap *= 2;
  s->slots = ck_alloc(s->cap * sizeof(cond_status_slot_t));
  s->count = 0;

  for (u32 i = 0; i < old_cap; i++) {

    if (old_slots[i].used) {

      cond_status_slot_t *ns = cond_status_raw_insert(s, old_slots[i].cmpid, old_slots[i].context);
      *ns = old_slots[i];

    }

  }

  ck_free(old_slots);

}

static cond_status_slot_t *cond_status_find_or_create(cond_status_set_t *s, u32 cmpid, u32 context) {

  if ((u64)(s->count + 1) * 4 >= (u64)s->cap * 3) cond_status_grow(s);

  u32 idx = cond_status_hash(cmpid, context) % s->cap;

  while (s->slots[idx].used) {

    if (s->slots[idx].cmpid == cmpid && s->slots[idx].context == context) return &s->slots[idx];
    idx = (idx + 1) % s->cap;

  }

  return cond_status_raw_insert(s, cmpid, context);

}

/* Records one more sighting of (cmpid, context): updates op, adds
   `condition` to the distinct-outcomes set if it's not already there (only
   the first two distinct values are kept -- that's all "solved" needs),
   and overwrites the stored offsets with this sighting's (so the report
   reflects the most recent occurrence, not necessarily the first). */
static void cond_status_update(cond_status_set_t *s, u32 cmpid, u32 context, u32 op,
                               u32 condition) {

  if (!s) return;

  cond_status_slot_t *slot = cond_status_find_or_create(s, cmpid, context);
  slot->op = op;

  u8 known = 0;

  for (u32 i = 0; i < slot->n_distinct; i++) {

    if (slot->seen_conditions[i] == condition) known = 1;

  }

  if (!known && slot->n_distinct < 2) slot->seen_conditions[slot->n_distinct++] = condition;

}

static void unsolved_write(cond_status_set_t *s, const char *path) {

  if (!s || !s->count) return;

  FILE *f = fopen(path, "w");
  if (!f) {

    WARNF("Could not open '%s' for writing unsolved conditions: %s", path, strerror(errno));
    return;

  }

  u32 n_unsolved = 0;

  for (u32 i = 0; i < s->cap; i++) {

    if (!s->slots[i].used) continue;

    u8 is_switch = (s->slots[i].op & WORKER_OP_BASIC_MASK) == DTAINT_COND_SW_OP;
    u8 solved = !is_switch && s->slots[i].n_distinct >= 2;
    if (!solved) n_unsolved++;

  }

  fprintf(f, "# unsolved conditions -- %u of %u tracked site(s) never seen both ways "
             "(cmpid, context)\n", n_unsolved, s->count);

  for (u32 i = 0; i < s->cap; i++) {

    if (!s->slots[i].used) continue;

    cond_status_slot_t *slot = &s->slots[i];
    u8 is_switch = (slot->op & WORKER_OP_BASIC_MASK) == DTAINT_COND_SW_OP;
    u8 solved = !is_switch && slot->n_distinct >= 2;
    if (solved) continue;

    fprintf(f, "cmpid=%u context=%u\n", slot->cmpid, slot->context);

  }

  fclose(f);

  if (!quiet_mode) {

    OKF("Wrote %u unsolved condition(s) (of %u tracked) to '%s'.", n_unsolved, s->count, path);

  }

}

typedef struct {

  u32                         label;
  u32                         n_segs;
  struct dtaint_tag_seg_wire *segs;

} worker_tag_lookup_t;

static int cmp_tag_lookup(const void *a, const void *b) {

  u32 la = ((const worker_tag_lookup_t *)a)->label;
  u32 lb = ((const worker_tag_lookup_t *)b)->label;
  return (la > lb) - (la < lb);

}

static worker_tag_lookup_t *find_tag(worker_tag_lookup_t *tags, u32 n_tags, u32 label) {

  if (!label || !n_tags) return NULL;
  worker_tag_lookup_t key = { .label = label, .n_segs = 0, .segs = NULL };
  return bsearch(&key, tags, n_tags, sizeof(worker_tag_lookup_t), cmp_tag_lookup);

}

/* Mirrors fparser.rs::get_offsets_and_variables()'s side-selection rule:
   prefer whichever of lb1/lb2 resolves to fewer taint segments (simpler,
   more specific provenance), falling back to lb1 if lb2 has none at all.
   Returns NULL if neither side has any segments. */
static worker_tag_lookup_t *pick_primary_side(worker_tag_lookup_t *tags, u32 n_tags,
                                              u32 lb1, u32 lb2) {

  worker_tag_lookup_t *t1 = find_tag(tags, n_tags, lb1);
  worker_tag_lookup_t *t2 = find_tag(tags, n_tags, lb2);

  if (!t2 || !t2->n_segs) return t1;
  if (t1 && t1->n_segs && t1->n_segs <= t2->n_segs) return t1;
  return t2;

}

typedef struct {

  u32 idx;      /* index into the file's cond_list */
  u32 context;
  u32 begin;
  u32 end;
  u8  is_fn;

} magic_candidate_t;

static int cmp_magic_candidate(const void *a, const void *b) {

  const magic_candidate_t *ca = a, *cb = b;
  if (ca->context != cb->context)
    return (ca->context > cb->context) - (ca->context < cb->context);
  return (ca->begin > cb->begin) - (ca->begin < cb->begin);

}

/* Reads a raw v2 scratch file written by dfsan_legacy's runtime, computes
   magic-byte groups, and writes the augmented v3 file to dest_path.
   Returns 0 on success, 1 if the input wasn't recognized as a plain v2
   file (caller should fall back to a plain rename instead of losing the
   run's output), -1 on a real I/O error. Never touches scratch_path
   itself -- the caller decides whether to unlink or keep it.

   orig_input/orig_input_len is the exact buffer this run was fed. dict,
   novelty, and cond_status (all always non-NULL, see main()) drive the
   value_pool.dict / unsolved_condition extraction pass further down. */
static int transcode_dtaint_with_magic_groups(const char *scratch_path,
                                              const char *dest_path,
                                              const u8 *orig_input,
                                              u32 orig_input_len,
                                              worker_dict_t *dict,
                                              novelty_set_t *novelty,
                                              cond_status_set_t *cond_status) {

  s32 fd = open(scratch_path, O_RDONLY);
  if (fd < 0) return -1;

  struct stat st;
  if (fstat(fd, &st)) { close(fd); return -1; }

  u32 raw_len = (u32)st.st_size;
  u8 *raw = ck_alloc(raw_len ? raw_len : 1);
  ssize_t rd = read(fd, raw, raw_len);
  close(fd);

  if (rd != (ssize_t)raw_len || raw_len < sizeof(struct dtaint_file_header)) {

    ck_free(raw);
    return -1;

  }

  struct dtaint_file_header hdr;
  memcpy(&hdr, raw, sizeof(hdr));

  if (hdr.magic != DTAINT_FILE_MAGIC || hdr.version != DTAINT_FILE_VERSION) {

    /* Always a freshly written runtime scratch file in practice -- if it
       ever isn't, don't lose the run's output over it, just skip grouping. */
    ck_free(raw);
    return 1;

  }

  u64 need = (u64)sizeof(hdr) + (u64)hdr.n_conds * sizeof(struct dtaint_cond_record);
  if (need > raw_len) { ck_free(raw); return 1; }

  u32 off = sizeof(hdr);
  struct dtaint_cond_record *conds = (struct dtaint_cond_record *)(raw + off);
  off += hdr.n_conds * sizeof(struct dtaint_cond_record);

  u32 tags_section_off = off;
  worker_tag_lookup_t *tags =
      hdr.n_tags ? ck_alloc(hdr.n_tags * sizeof(worker_tag_lookup_t)) : NULL;

  for (u32 i = 0; i < hdr.n_tags; i++) {

    if (off + sizeof(struct dtaint_tag_record) > raw_len) { ck_free(raw); ck_free(tags); return 1; }

    struct dtaint_tag_record rec;
    memcpy(&rec, raw + off, sizeof(rec));
    off += sizeof(rec);

    if ((u64)off + (u64)rec.n_segs * sizeof(struct dtaint_tag_seg_wire) > raw_len) {

      ck_free(raw);
      ck_free(tags);
      return 1;

    }

    tags[i].label = rec.label;
    tags[i].n_segs = rec.n_segs;
    tags[i].segs = (struct dtaint_tag_seg_wire *)(raw + off);
    off += rec.n_segs * sizeof(struct dtaint_tag_seg_wire);

  }

  if (hdr.n_tags) qsort(tags, hdr.n_tags, sizeof(worker_tag_lookup_t), cmp_tag_lookup);

  /* --- find every single-byte magic-byte comparison, for the grouping
     pass below (this is purely a v3-format concern: gluing an unrolled
     multi-byte constant check back into one span -- see the top-of-file
     comment on DTAINT_FILE_VERSION_GROUPED). --- */

  magic_candidate_t *cand =
      hdr.n_conds ? ck_alloc(hdr.n_conds * sizeof(magic_candidate_t)) : NULL;
  u32 n_cand = 0;

  for (u32 i = 0; i < hdr.n_conds; i++) {

    if (!is_magic_byte_cmp(conds[i].op, conds[i].lb1, conds[i].lb2)) continue;

    worker_tag_lookup_t *primary =
        pick_primary_side(tags, hdr.n_tags, conds[i].lb1, conds[i].lb2);
    if (!primary || primary->n_segs != 1) continue;
    if (primary->segs[0].end - primary->segs[0].begin != 1) continue;

    cand[n_cand].idx = i;
    cand[n_cand].context = conds[i].context;
    cand[n_cand].begin = primary->segs[0].begin;
    cand[n_cand].end = primary->segs[0].end;
    cand[n_cand].is_fn = conds[i].op == DTAINT_COND_FN_OP;
    n_cand++;

  }

  if (n_cand) qsort(cand, n_cand, sizeof(magic_candidate_t), cmp_magic_candidate);

  /* group_begin[i]/group_end[i] stay 0/0 (ck_alloc zeroes) for any cond
     record not part of a multi-member group. */
  u32 *group_begin = hdr.n_conds ? ck_alloc(hdr.n_conds * sizeof(u32)) : NULL;
  u32 *group_end   = hdr.n_conds ? ck_alloc(hdr.n_conds * sizeof(u32)) : NULL;

  u32 k = 0;
  while (k < n_cand) {

    u32 j = k;
    while (j + 1 < n_cand &&
           cand[j].is_fn == cand[j + 1].is_fn &&
           cand[j].context == cand[j + 1].context &&
           cand[j + 1].begin == cand[j].end) {

      j++;

    }

    if (j > k) {

      u32 span_begin = cand[k].begin, span_end = cand[j].end;
      for (u32 m = k; m <= j; m++) {

        group_begin[cand[m].idx] = span_begin;
        group_end[cand[m].idx] = span_end;

      }

    }

    k = j + 1;

  }

  if (cand) ck_free(cand);

  /* --- interesting-value extraction, and unsolved-condition tracking --
     for every tainted comparison, regardless of op or outcome, that
     produced a (cmpid, context, condition) combination never seen before
     in this process's lifetime: (1) feed value_pool.dict, and (2) update
     unsolved_condition's per-(cmpid, context) outcome history (see
     cond_status_update()) -- both gated on the same novelty check, so a
     site that's already fully explored doesn't cost anything on repeat
     sightings.

     For the dict: a grouped byte-chain (see above) becomes one combined
     value, since it's already established as one genuinely contiguous
     span. Otherwise this uses whichever of lb1/lb2 is the "primary" side
     (see pick_primary_side()): a single-segment tag stores that one span
     (dropped if it's only 1 byte -- rarely meaningful alone); a multi-
     segment tag stores each segment on its own (same 1-byte drop, applied
     per segment) *and*, separately, every segment of that same label
     under one shared group_id (see dict_add_group()) so which segments
     co-occurred in the same label stays recoverable even though they're
     never concatenated into a single blob. */

  for (u32 i = 0; orig_input && i < hdr.n_conds; i++) {

    if (!conds[i].lb1 && !conds[i].lb2) continue;

    u8 is_novel = novelty_check_and_mark(novelty, conds[i].cmpid, conds[i].context,
                                         conds[i].condition);
    if (!is_novel) continue;

    if (group_end[i] > group_begin[i]) {

      cond_status_update(cond_status, conds[i].cmpid, conds[i].context, conds[i].op,
                         conds[i].condition);

      if (group_end[i] <= orig_input_len) {

        dict_add(dict, orig_input + group_begin[i], group_end[i] - group_begin[i]);

      }

      continue;

    }

    worker_tag_lookup_t *primary =
        pick_primary_side(tags, hdr.n_tags, conds[i].lb1, conds[i].lb2);
    if (!primary || !primary->n_segs) continue;

    cond_status_update(cond_status, conds[i].cmpid, conds[i].context, conds[i].op,
                       conds[i].condition);

    if (primary->n_segs > 1) {

      dict_add_group(dict, primary->segs, primary->n_segs, orig_input, orig_input_len);

    }

    for (u32 s = 0; s < primary->n_segs; s++) {

      u32 b = primary->segs[s].begin, e = primary->segs[s].end;
      if (e - b <= 1 || e > orig_input_len) continue;
      dict_add(dict, orig_input + b, e - b);

    }

  }

  /* --- write the augmented v3 file --- */

  FILE *out = fopen(dest_path, "wb");
  if (!out) {

    if (tags) ck_free(tags);
    if (group_begin) ck_free(group_begin);
    if (group_end) ck_free(group_end);
    ck_free(raw);
    return -1;

  }

  struct dtaint_file_header out_hdr = hdr;
  out_hdr.version = DTAINT_FILE_VERSION_GROUPED;
  fwrite(&out_hdr, sizeof(out_hdr), 1, out);

  for (u32 i = 0; i < hdr.n_conds; i++) {

    struct dtaint_cond_record_grouped g = {

        .cmpid = conds[i].cmpid, .context = conds[i].context,
        .order = conds[i].order, .belong = conds[i].belong,
        .condition = conds[i].condition, .level = conds[i].level,
        .op = conds[i].op, .size = conds[i].size,
        .lb1 = conds[i].lb1, .lb2 = conds[i].lb2,
        .arg1 = conds[i].arg1, .arg2 = conds[i].arg2,
        .magic_group_begin = group_begin[i], .magic_group_end = group_end[i],

    };

    fwrite(&g, sizeof(g), 1, out);

  }

  /* tags + magic_bytes sections are byte-identical to the raw file --
     everything from tags_section_off to EOF, verbatim, in one shot. */
  if (raw_len > tags_section_off)
    fwrite(raw + tags_section_off, 1, raw_len - tags_section_off, out);

  fclose(out);

  if (tags) ck_free(tags);
  if (group_begin) ck_free(group_begin);
  if (group_end) ck_free(group_end);
  ck_free(raw);

  return 0;

}

/* Runs one input through the dtaint forkserver and, if it produced a track
   file, files it away under work_dir as "<fname>.dtaint". Serves three
   callers with the same logic: live queue entries (src_dir = queue_dir,
   fname = the full AFL++-assigned queue basename, seed_cache_dir = whatever
   -c gave, if anything), and seed-scan mode (src_dir = seed_dir, fname =
   the seed's own plain filename, seed_cache_dir = NULL).

   Before doing any real work, tries a cache hit under two possible keys, in
   order:
     1. fname's "orig:<name>" field (afl-fuzz-init.c's normal seed-loading
        path tags a dry-run seed's queue entry with the seed's own original
        filename -- never present on a real havoc-derived discovery).
     2. fname itself, verbatim. Covers a real gap found in testing: when a
        seed file's own name already looks like an AFL++ queue entry (e.g.
        a "saturated_seed" corpus that's itself a prior campaign's leftover
        queue, plain "id:NNNNNN" names, no ",orig:" suffix), afl-fuzz-init.c
        treats that as a resume and preserves the name *verbatim* -- no
        "orig:" field gets added at all (see its own read_testcases(),
        the branch guarded by CASE_PREFIX/orig_id matching). In that case
        the live queue entry's fname already *is* the exact seed filename
        the -S pass cached under, so trying fname itself is not a
        redundant check, it's the only one that can ever hit for this
        (common, given this project's saturation-mode workflow) shape of
        seed corpus.
   Either way a hit already covers this input byte-for-byte (AFL++ copies
   dry-run seeds into the queue unmodified), so this skips the forkserver
   entirely rather than redundantly re-deriving an identical result.

   Best-effort: a short/failed read just skips this input (see file
   header's "Known limitations"). */
static void process_queue_entry(afl_forkserver_t *fsrv, const char *src_dir,
                                const char *work_dir,
                                const char *seed_cache_dir,
                                const char *input_seed_dir,
                                worker_dict_t *dict,
                                novelty_set_t *novelty,
                                cond_status_set_t *cond_status,
                                const char *fname) {

  u8 *orig_name = extract_orig_name(fname);
  const char *key = orig_name ? (char *)orig_name : fname;
  u8 hit = try_seed_cache(work_dir, seed_cache_dir, key, fname);

  if (orig_name && !hit) {

    hit = try_seed_cache(work_dir, seed_cache_dir, fname, fname);

  }

  /* Ground truth for "is this an untouched dry-run seed, not a fuzzer
     discovery": does a file by this exact key already exist in the -i
     seed directory? This works regardless of how AFL++ chose to name the
     queue entry (`orig:`-tagged, or the queue filename preserved
     byte-for-byte verbatim when the seed's own filename already looked
     like an AFL id -- see read_testcases() in afl-fuzz-init.c; the
     saturated_seed corpora this was found against are entirely the
     latter, so a check keyed on the literal string "orig:" would never
     fire for them at all). Checked only on a cache miss, since a hit
     already means "handled" above -- if input_seed_dir was given and it
     really is a seed, it's one the -S pre-pass itself couldn't finish in
     time (real-DFSan timing out on an oversized/pathological seed; see
     run_seed_scan()). Retrying it here would just burn the same timeout
     again, competing with afl-fuzz for CPU for a result we already know
     won't materialize -- skip instead of falling through to a live run. */
  u8 is_known_seed = 0;

  if (!hit && input_seed_dir != NULL) {

    u8 *seed_probe = alloc_printf("%s/%s", input_seed_dir, key);
    is_known_seed = access((char *)seed_probe, F_OK) == 0;
    ck_free(seed_probe);

  }

  if (orig_name) ck_free(orig_name);
  if (hit) return;

  if (is_known_seed) {

    if (!quiet_mode)
      WARNF("skip: '%s' is an unmutated seed with no cache entry (likely "
            "timed out during -S scan) -- not retrying live", fname);
    return;

  }

  u8 *in_path = alloc_printf("%s/%s", src_dir, fname);

  s32 fd = open((char *)in_path, O_RDONLY);
  if (fd < 0) {

    WARNF("Could not open queue entry '%s': %s", in_path, strerror(errno));
    ck_free(in_path);
    return;

  }

  struct stat st;
  if (fstat(fd, &st)) {

    WARNF("Could not stat '%s': %s", in_path, strerror(errno));
    close(fd);
    ck_free(in_path);
    return;

  }

  u32 len = (u32)st.st_size;
  u8 *buf = ck_alloc(len ? len : 1);

  if (len) {

    ssize_t rd = read(fd, buf, len);
    close(fd);

    if (rd != (ssize_t)len) {

      WARNF(
          "Short read on '%s' (%zd/%u bytes) -- fuzzer may still be "
          "writing it, skipping (will not retry)",
          in_path, rd, len);
      ck_free(buf);
      ck_free(in_path);
      return;

    }

  } else {

    close(fd);

  }

  afl_fsrv_write_to_testcase(fsrv, buf, len);
  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, fsrv->exec_tmout, &stop_soon);

  if (res == FSRV_RUN_ERROR) {

    WARNF("Error running dtaint binary on '%s'", in_path);

  }

  u8 *scratch_path = alloc_printf("%s/%s", work_dir, DTAINT_SCRATCH_NAME);

  if (access((char *)scratch_path, F_OK) == 0) {

    u8 *dest_path = alloc_printf("%s/%s.dtaint", work_dir, fname);
    int tc = transcode_dtaint_with_magic_groups((char *)scratch_path, (char *)dest_path,
                                                buf, len, dict, novelty, cond_status);

    if (tc == 0) {

      unlink((char *)scratch_path);
      if (!quiet_mode) { OKF("dtaint: %s -> %s", fname, dest_path); }

    } else {

      /* Transcode failed, or the scratch file wasn't the plain v2 format
         it's always expected to be -- fall back to the old plain rename
         rather than lose the run's output over a grouping bug. */
      if (rename((char *)scratch_path, (char *)dest_path)) {

        WARNF("Could not rename dtaint scratch file to '%s': %s", dest_path,
              strerror(errno));

      } else if (!quiet_mode) {

        OKF("dtaint: %s -> %s (ungrouped)", fname, dest_path);

      }

    }

    ck_free(dest_path);

  }

  ck_free(scratch_path);
  ck_free(buf);
  ck_free(in_path);

}

/* -S seed_dir mode's whole job: run dtaint once over every plain file in
   seed_dir and drop "<filename>.dtaint" into out_dir (the flat cache dir a
   later -c out_dir on a live-mode run will point back at). No queue/, no
   poll loop, no "orig:" involved (a raw seed filename never contains it) --
   process_queue_entry()'s cache-hit check is simply a no-op here, it just
   runs the forkserver on every file and files away whatever comes out. */
static void run_seed_scan(afl_forkserver_t *fsrv, const char *seed_dir,
                          const char *out_dir, worker_dict_t *dict,
                          novelty_set_t *novelty, cond_status_set_t *cond_status) {

  DIR *d = opendir(seed_dir);
  if (!d) { PFATAL("Unable to open seed dir '%s'", seed_dir); }

  if (!quiet_mode) { ACTF("Seed scan: scanning '%s'...", seed_dir); }

  u32            n = 0;
  struct dirent *de;

  while (!stop_soon && (de = readdir(d))) {

    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
#ifdef DT_DIR
    if (de->d_type == DT_DIR) continue;
#endif
    if (de->d_name[0] == '.') continue;

    process_queue_entry(fsrv, seed_dir, out_dir, NULL, NULL, dict, novelty, cond_status, de->d_name);
    ++n;

  }

  closedir(d);

  if (!quiet_mode) {

    OKF("Seed scan done: %u file(s) from '%s' -> '%s'.", n, seed_dir, out_dir);

  }

}

int main(int argc, char **argv_orig, char **envp) {

  (void)envp;

  s32  opt;
  u8  *out_dir = NULL;
  u8  *seed_scan_dir = NULL;
  u8  *seed_cache_dir = NULL;
  u8  *input_seed_dir = NULL;
  u32  exec_tmout = 5000;
  u64  mem_limit = 0;
  u32  poll_interval_sec = 2;

  char **argv = argv_cpy_dup(argc, argv_orig);

  if (getenv("AFL_QUIET") != NULL) { quiet_mode = 1; }

  while ((opt = getopt(argc, argv, "+o:S:c:i:t:m:p:Qh")) > 0) {

    switch (opt) {

      case 'o':
        if (out_dir) { FATAL("Multiple -o options not supported"); }
        out_dir = (u8 *)optarg;
        break;

      case 'S':
        if (seed_scan_dir) { FATAL("Multiple -S options not supported"); }
        seed_scan_dir = (u8 *)optarg;
        break;

      case 'c':
        if (seed_cache_dir) { FATAL("Multiple -c options not supported"); }
        seed_cache_dir = (u8 *)optarg;
        break;

      case 'i':
        /* Live mode only: the same directory afl-fuzz's own -i points at
           -- lets a cache-miss on what looks like a seed be confirmed
           against the real corpus instead of guessed from the queue
           filename (see process_queue_entry()'s is_known_seed check). */
        if (input_seed_dir) { FATAL("Multiple -i options not supported"); }
        input_seed_dir = (u8 *)optarg;
        break;

      case 't':
        if (sscanf(optarg, "%u", &exec_tmout) != 1 || !exec_tmout) {

          FATAL("Bad syntax used for -t");

        }

        break;

      case 'm':
        if (!strcmp(optarg, "none")) {

          mem_limit = 0;

        } else if (sscanf(optarg, "%llu", &mem_limit) != 1) {

          FATAL("Bad syntax used for -m");

        }

        break;

      case 'p':
        if (sscanf(optarg, "%u", &poll_interval_sec) != 1 ||
            !poll_interval_sec) {

          FATAL("Bad syntax used for -p");

        }

        break;

      case 'Q':
        quiet_mode = 1;
        break;

      case 'h':
      default:
        usage((u8 *)argv[0]);

    }

  }

  if (!out_dir || optind == argc) { usage((u8 *)argv[0]); }
  if (seed_scan_dir && seed_cache_dir) {

    FATAL("-S (seed-scan mode) and -c (live-mode cache dir) don't combine "
          "-- -S itself IS the tool that builds a -c-ready cache dir.");

  }

  if (seed_scan_dir && input_seed_dir) {

    FATAL("-i is live-mode only -- -S already takes the seed dir directly "
          "as its argument.");

  }

  u8 *queue_dir = NULL;    /* live mode only */
  u8 *work_dir;            /* scratch/cur_input + final .dtaint location */

  if (seed_scan_dir) {

    /* Scan mode: -o is a flat directory, not a campaign out_dir -- no
       queue/, no "default" instance nesting, just "<out_dir>/<seed
       filename>.dtaint" per seed. */
    work_dir = (u8 *)strdup((char *)out_dir);

    if (mkdir((char *)work_dir, 0755) && errno != EEXIST) {

      PFATAL("Could not create '%s'", work_dir);

    }

  } else {

    /* Live mode. AFL++ nests the actual campaign under a "default" instance
       dir even in single-instance mode (no -M/-S) -- <out_dir>/default/
       queue, not <out_dir>/queue directly. Same dual-path check start.sh's
       watch_dryrun() already does for the same reason: this lets -o point
       at exactly the same path passed to afl-fuzz's own -o, with no need
       to know about the "default" naming quirk. dtaint_logs/ is created as
       a sibling of wherever queue/ actually is, matching
       log_dtaint_for_new_input()'s own convention (both live directly
       under afl->out_dir on the real-dfsan-vendor branch). */
    u8 *campaign_dir;
    u8 *probe = alloc_printf("%s/queue", out_dir);

    if (!access((char *)probe, F_OK)) {

      campaign_dir = (u8 *)strdup((char *)out_dir);
      ck_free(probe);

    } else {

      ck_free(probe);
      u8 *default_probe = alloc_printf("%s/default/queue", out_dir);

      if (!access((char *)default_probe, F_OK)) {

        campaign_dir = alloc_printf("%s/default", out_dir);

      } else {

        /* Neither exists yet (afl-fuzz hasn't started or hasn't finished
           its dry run) -- default to the "default" instance dir, the
           common case, and let the poll loop's own PFATAL surface a clear
           error if it's still missing once we actually try to watch it. */
        campaign_dir = alloc_printf("%s/default", out_dir);

      }

      ck_free(default_probe);

    }

    queue_dir = alloc_printf("%s/queue", campaign_dir);
    work_dir = alloc_printf("%s/dtaint_logs", campaign_dir);

    /* This can run before afl-fuzz itself has ever started (that's the
       point of a -S-built cache: it's ready before the campaign begins),
       so campaign_dir ("<out_dir>/default") may not exist yet either.
       Plain mkdir() isn't recursive, so create each level. AFL++ itself
       creates out_dir/campaign_dir the normal way once it starts; these
       calls just tolerate getting there first -- and AFL++ doesn't care
       that dtaint_logs/ (an entry it doesn't recognize) is already
       sitting in campaign_dir when it does (see handle_existing_out_dir()
       in afl-fuzz-init.c: it only ever checks for its own fuzzer_stats). */
    if (mkdir((char *)out_dir, 0755) && errno != EEXIST) {

      PFATAL("Could not create '%s'", out_dir);

    }

    if (mkdir((char *)campaign_dir, 0755) && errno != EEXIST) {

      PFATAL("Could not create '%s'", campaign_dir);

    }

    if (mkdir((char *)work_dir, 0755) && errno != EEXIST) {

      PFATAL("Could not create '%s'", work_dir);

    }

  }

  /* Always on, always alongside wherever the .dtaint outputs themselves
     land (work_dir) -- value_pool.dict and unsolved_condition, fixed
     names, no CLI knob. */
  worker_dict_t        dict_storage;
  novelty_set_t        novelty_storage;
  cond_status_set_t    cond_status_storage;
  worker_dict_t        *dict = &dict_storage;
  novelty_set_t        *novelty = &novelty_storage;
  cond_status_set_t    *cond_status = &cond_status_storage;

  dict_init(dict);
  novelty_init(novelty);
  cond_status_init(cond_status);

  u8 *dict_out_path = alloc_printf("%s/value_pool.dict", work_dir);
  u8 *unsolved_out_path = alloc_printf("%s/unsolved_condition", work_dir);

  worker_setup_signal_handlers();

  afl_forkserver_t fsrv_var = {0};
  afl_forkserver_t *fsrv = &fsrv_var;
  afl_fsrv_init(fsrv);

  fsrv->target_path = find_binary(argv[optind]);
  fsrv->exec_tmout = exec_tmout;
  fsrv->mem_limit = mem_limit;

  configure_afl_kill_signals(fsrv, NULL, NULL, SIGTERM);

  sharedmem_t shm = {0};
  setenv("AFL_MAP_SIZE", STRINGIFY(WORKER_MAP_SIZE), 1);
  fsrv->trace_bits = afl_shm_init(&shm, WORKER_MAP_SIZE, 0, DEFAULT_PERMISSION, -1);
  fsrv->map_size = WORKER_MAP_SIZE;
  fsrv->child_sync_offset = shm.child_sync_offset;

  /* Must contain the literal substring "cur_input" -- dfsan_legacy's
     io_func.c only taints reads through its wrapped fopen/open when the
     opened path matches IS_FUZZING_FILE() (a plain strstr() against
     FUZZING_INPUT_FILE, dfsan_legacy/include/defs.h), mirroring how real
     AFL++ names its own scratch file (.cur_input) and how Angora's own
     runtime does the same gating. Without this, file-arg (@@) targets
     silently produce zero taint -- fd 0 (stdin) is pre-marked as the
     fuzzing input by default, which is why stdin-mode targets don't need
     this at all (see dtaint_legacy_compat.h's own comment). Found via a
     real A/B test: byte-identical content through a non-matching filename
     produced no .dtaint file, through stdin it did. */
  u8 *stdin_file =
      alloc_printf("%s/.reusing-taint-worker.cur_input.%u", work_dir,
                  (u32)getpid());
  unlink((char *)stdin_file);

  /* If '@@' is in the target args, this substitutes it and sets
     use_stdin=false; otherwise leaves use_stdin=true. */
  detect_file_args(argv + optind, stdin_file, &fsrv->use_stdin);

  fsrv->dev_null_fd = open("/dev/null", O_RDWR);
  if (fsrv->dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  fsrv->out_file = (u8 *)stdin_file;
  fsrv->out_fd =
      open((char *)stdin_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (fsrv->out_fd < 0) { PFATAL("Unable to create '%s'", stdin_file); }
  if (fsrv->use_stdin) { unlink((char *)stdin_file); }

  /* Set once, before the forkserver's one-time execve() -- see this
     file's header comment and real-dfsan-vendor's include/dtaint.h. */
  u8 *scratch_env_path =
      alloc_printf("%s/%s", work_dir, DTAINT_SCRATCH_NAME);
  setenv(DTAINT_TRACK_ENV_VAR, (char *)scratch_env_path, 1);
  ck_free(scratch_env_path);

  if (!quiet_mode) {

    ACTF("Starting dtaint forkserver for '%s'...", fsrv->target_path);

  }

  afl_fsrv_start(fsrv, argv + optind, &stop_soon, 0);

  if (seed_scan_dir) {

    /* -S is a one-shot job: scan, then exit -- no queue/ to watch, no
       campaign this invocation is part of. */
    if (!stop_soon) {

      run_seed_scan(fsrv, (char *)seed_scan_dir, (char *)work_dir, dict, novelty, cond_status);

    }

    dict_write(dict, (char *)dict_out_path);
    unsolved_write(cond_status, (char *)unsolved_out_path);

    if (fsrv->out_fd >= 0 && !fsrv->use_stdin) { unlink((char *)stdin_file); }
    ck_free(stdin_file);
    afl_shm_deinit(&shm);
    afl_fsrv_deinit(fsrv);
    return 0;

  }

  if (!quiet_mode) {

    OKF("Forkserver up. Watching '%s' every %u second(s).", queue_dir,
        poll_interval_sec);

  }

  s64 last_id = -1;

  while (!stop_soon) {

    u32                 n = 0;
    queue_entry_ref_t *entries = scan_new_queue_entries((char *)queue_dir,
                                                        last_id, &n);

    for (u32 i = 0; i < n && !stop_soon; ++i) {

      process_queue_entry(fsrv, (char *)queue_dir, (char *)work_dir,
                          (char *)seed_cache_dir, (char *)input_seed_dir,
                          dict, novelty, cond_status, (char *)entries[i].name);
      last_id = entries[i].id;
      free(entries[i].name);

    }

    if (entries) ck_free(entries);

    if (!stop_soon) sleep(poll_interval_sec);

  }

  if (!quiet_mode) { OKF("Stopping."); }

  dict_write(dict, (char *)dict_out_path);
  unsolved_write(cond_status, (char *)unsolved_out_path);

  if (fsrv->out_fd >= 0 && !fsrv->use_stdin) { unlink((char *)stdin_file); }
  ck_free(stdin_file);

  afl_shm_deinit(&shm);
  afl_fsrv_deinit(fsrv);

  return 0;

}
