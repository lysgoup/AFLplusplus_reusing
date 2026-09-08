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

    if (rename((char *)scratch_path, (char *)dest_path)) {

      WARNF("Could not rename dtaint scratch file to '%s': %s", dest_path,
            strerror(errno));

    } else if (!quiet_mode) {

      OKF("dtaint: %s -> %s", fname, dest_path);

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
                          const char *out_dir) {

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

    process_queue_entry(fsrv, seed_dir, out_dir, NULL, NULL, de->d_name);
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
    if (!stop_soon) { run_seed_scan(fsrv, (char *)seed_scan_dir, (char *)work_dir); }

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
                          (char *)entries[i].name);
      last_id = entries[i].id;
      free(entries[i].name);

    }

    if (entries) ck_free(entries);

    if (!stop_soon) sleep(poll_interval_sec);

  }

  if (!quiet_mode) { OKF("Stopping."); }

  if (fsrv->out_fd >= 0 && !fsrv->use_stdin) { unlink((char *)stdin_file); }
  ck_free(stdin_file);

  afl_shm_deinit(&shm);
  afl_fsrv_deinit(fsrv);

  return 0;

}
