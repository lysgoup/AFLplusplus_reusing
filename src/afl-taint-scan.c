/*
   american fuzzy lop++ - reusing pool: seed taint-analysis pre-pass
   ---------------------------------------------------------------------

   One-shot batch tool, run once ahead of a campaign. Takes a seed
   directory (-S), runs every file in it through a dtaint-instrumented
   binary, and writes into a flat output directory (-o):

     <seed filename>.dtaint  - per-seed taint track file (v3, see
                               include/dtaint.h)
     value_pool.dict         - value candidates accumulated across the
                               whole scan
     unsolved_condition      - (cmpid, context) sites never seen going
                               more than one way

   afl-fuzz reads that directory back via -r. It used to have a second,
   live mode that watched a running campaign's queue/ and analyzed new
   entries as they appeared; that is gone. Analyzing the entries a
   campaign discovers now belongs to afl-fuzz itself, where the taint data
   is guaranteed to exist before the entry is ever selected -- the poll
   loop could only ever produce it some time after, and measured on a real
   campaign only 100 of 2726 queue entries came from seeds at all, so
   everything else was racing. What stays here is the part that genuinely
   wants to be a pre-pass: seeds are analyzed once and the result is
   reused by every trial of every campaign against the same corpus.

   Protocol mirrors include/dtaint.h:
     - AFL_DTAINT_TRACK_FILE points the dtaint binary at a *fixed*
       per-session scratch path, set once in the environment before the
       forkserver's one-time execve() -- the forkserver protocol forks
       already-running children for every later run and never re-execs
       or re-reads the environment, so this can't vary per call.
     - after each run, if that scratch file exists, it is transcoded into
       the v3 format (magic-byte grouping) at <out_dir>/<name>.dtaint. No
       file means the target had nothing taint-worthy to report for that
       input, not an error.

   Reuses AFL++'s own generic forkserver primitives completely unmodified
   (afl-forkserver.c/afl-common.c/afl-sharedmem.c/afl-performance.c) --
   the same building blocks afl-showmap/afl-tmin already link against,
   none of it fuzzer-orchestration-specific. Structurally this file is a
   trimmed-down afl-showmap.c: same option-parsing/forkserver-setup
   shape, swapping "read coverage bitmap" for "drive the dtaint binary
   and stash its track file."

   Known limitations (accepted, not engineered around):
   - A seed that fails to read cleanly is logged and skipped, never
     retried.
   - Seeds are visited in name order (scandir), which is what makes
     value_pool.dict reproducible -- see run_seed_scan().

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
      "\n%s [ options ] -S seed_dir -o out_dir -- /path/to/dtaint_binary "
      "[...]\n\n"

      "One-shot pre-pass: runs dtaint over every file in seed_dir, then "
      "exits.\n"
      "Run it once per seed corpus, ahead of any campaign -- the output is "
      "read\n"
      "back by afl-fuzz's -r and is reusable across every campaign that "
      "fuzzes\n"
      "the same corpus.\n"
      "  Example: %s -S /path/to/seeds -o /path/to/cache -- "
      "/d/p/.../dtaint/jq . @@\n\n"

      "Required parameters:\n"
      "  -S seed_dir   - directory of seeds to analyze\n"
      "  -o out_dir    - flat directory to write the results into\n\n"

      "Optional parameters:\n"
      "  -t msec       - timeout for each dtaint run (default: 5000)\n"
      "  -m megs       - memory limit for the dtaint binary, 'none' for "
      "unlimited\n"
      "                  (default: none)\n"
      "  -Q            - quiet mode\n\n"

      "Written to out_dir alongside the per-seed .dtaint files:\n"
      "  value_pool.dict      - every tainted value behind a NEW comparison "
      "\n"
      "                         outcome (a (site, context, condition) combo "
      "\n"
      "                         never seen before in this run). Each line is "
      "a\n"
      "                         JSON-style array of quoted, \\xNN-escaped "
      "byte\n"
      "                         strings -- [\"...\"] for a magic-byte chain "
      "or a\n"
      "                         single-segment value, [\"...\",\"...\"] for "
      "a\n"
      "                         multi-segment taint label (one element per "
      "\n"
      "                         segment, in order). NOT AFL++ -x syntax. "
      "Anything\n"
      "                         shorter than 2 bytes is dropped unless it's "
      "part\n"
      "                         of a multi-segment label. Rows are sorted by "
      "\n"
      "                         segment-length pattern, annotated with "
      "\"# label\n"
      "                         pattern: [...]\" comments.\n"
      "  unsolved_condition   - every (cmpid, context) site whose condition "
      "has\n"
      "                         never gone more than one way across the "
      "whole\n"
      "                         scan (a switch always counts as unsolved) -- "
      "\n"
      "                         just cmpid and context, meant as mutation "
      "\n"
      "                         targets still worth attacking.\n\n"

      "Use '@@' in the target command line to have it substituted with the "
      "path\n"
      "to the input file. Without '@@', input is fed via stdin, matching "
      "afl-fuzz's own convention.\n\n",
      argv0, argv0);

  exit(1);

}

/* ---------------------------------------------------------------------- */
/* Interesting-value dictionary -- accumulated across every execution for  */
/* the life of the whole scan, written out once at the end. A value is    */
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

/* Longest single segment that goes into the dict. Deliberately far above
   what the targets measured so far actually produce (16-19 bytes at most),
   since the old value of 32 was itself the reason nothing longer ever
   showed up -- it was silently dropping wider spans rather than reporting
   them. afl-fuzz's reader is sized off the same number
   (REUSING_MAX_SEG_LEN in src/afl-fuzz-reusing.c); raising it here without
   raising that one would produce lines the fuzzer refuses to parse. */
#define WORKER_DICT_MAX_ENTRY_LEN 4096

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
   bytes strongly suggests a mis-grouped run, not a real fixed value), or
   this exact value is already in the set. No count cap -- individual
   values are cheap (<=32 bytes each) and the whole point is not to lose
   real data to an arbitrary ceiling. */
static void dict_add(worker_dict_t *d, const u8 *data, u32 len) {

  if (!d || !data || !len || len > WORKER_DICT_MAX_ENTRY_LEN) return;
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

  fprintf(f, "# extracted by afl-taint-scan -- %u entries, %u grouped segments\n",
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
   file this worker ever runs in one scan), which
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
/* across every input this process has analyzed in one scan.               */
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
  fprintf(f, "# seen = the one condition value ever produced here (%u false, "
             "%u true, %u done), or -1 if there was no single one\n",
          DTAINT_COND_FALSE_ST, DTAINT_COND_TRUE_ST, DTAINT_COND_DONE_ST);

  for (u32 i = 0; i < s->cap; i++) {

    if (!s->slots[i].used) continue;

    cond_status_slot_t *slot = &s->slots[i];
    u8 is_switch = (slot->op & WORKER_OP_BASIC_MASK) == DTAINT_COND_SW_OP;
    u8 solved = !is_switch && slot->n_distinct >= 2;
    if (solved) continue;

    /* Which way it went says which direction a mutation has to push. A
       switch is reported unsolved even after taking several cases, so it
       need not have a single direction. */
    s32 seen = slot->n_distinct == 1 ? (s32)slot->seen_conditions[0] : -1;

    fprintf(f, "cmpid=%u context=%u seen=%d\n", slot->cmpid, slot->context,
            seen);

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

/* The other half of get_offsets_and_variables(): whichever side
   pick_primary_side() did *not* return, i.e. Angora's `cond.offsets_opt`.
   Only meaningful when both operands are tainted under two *distinct*
   labels -- that same function guards its own offsets_opt assignment with
   `lb2 > 0 && lb1 != lb2` (one label sitting on both sides of a comparison
   describes one span, not two, so there is no second operand to attack).
   Returns NULL when there is no such side, so callers can just skip it.

   Angora feeds this side through create_record_for_offsets() exactly like
   the primary one (label_pattern_tracker.rs's add_dual_label_records ->
   two create_record_for_offsets calls, operand_num 1 and 2), and drives
   mutation from it as a distinct search stage (cond_state.rs's
   to_offsets_opt swaps offsets/offsets_opt, then to_offsets_all merges
   them) -- both spans are genuinely reusable, not one canonical span plus
   a redundant copy. */
static worker_tag_lookup_t *pick_secondary_side(worker_tag_lookup_t *tags, u32 n_tags,
                                                u32 lb1, u32 lb2,
                                                worker_tag_lookup_t *primary) {

  if (!lb1 || !lb2 || lb1 == lb2) return NULL;

  worker_tag_lookup_t *t1 = find_tag(tags, n_tags, lb1);
  worker_tag_lookup_t *t2 = find_tag(tags, n_tags, lb2);
  worker_tag_lookup_t *other = primary == t1 ? t2 : t1;

  return other && other->n_segs ? other : NULL;

}

/* One tainted operand's worth of dict entries: a single-segment tag stores
   that one span (dropped if it's only 1 byte -- rarely meaningful alone); a
   multi-segment tag stores each segment on its own (same 1-byte drop,
   applied per segment) *and*, separately, every segment of that same label
   under one shared group_id (dict_add_group()) so which segments co-occurred
   in the same label stays recoverable even though they're never
   concatenated into a single blob. Shared by the primary and the
   offsets_opt side so both get identical treatment. */
static void dict_add_side(worker_dict_t *d, worker_tag_lookup_t *side,
                          const u8 *orig_input, u32 orig_input_len) {

  if (side->n_segs > 1) {

    dict_add_group(d, side->segs, side->n_segs, orig_input, orig_input_len);

  }

  for (u32 s = 0; s < side->n_segs; s++) {

    u32 b = side->segs[s].begin, e = side->segs[s].end;
    if (e - b <= 1 || e > orig_input_len) continue;
    dict_add(d, orig_input + b, e - b);

  }

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
     span. Otherwise this emits both tainted operands, mirroring the two
     halves get_offsets_and_variables() fills in -- the "primary" side
     (pick_primary_side(), Angora's cond.offsets) always, plus the
     offsets_opt side (pick_secondary_side()) when the comparison has two
     distinct tainted operands. dict_add_side() documents what one side
     turns into. */

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

    dict_add_side(dict, primary, orig_input, orig_input_len);

    /* An input-vs-input comparison (`hdr->width == hdr->height`) is
       satisfiable from either operand's bytes, so the side pick_primary_side()
       passed over is a second, independent set of values -- emit it too
       rather than letting it fall on the floor. NULL for the overwhelmingly
       common single-tainted-operand case, so this costs nothing there. */
    worker_tag_lookup_t *secondary = pick_secondary_side(
        tags, hdr.n_tags, conds[i].lb1, conds[i].lb2, primary);

    if (secondary) {

      dict_add_side(dict, secondary, orig_input, orig_input_len);

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

/* Runs one seed through the dtaint forkserver and, if it produced a track
   file, transcodes it into work_dir as "<fname>.dtaint", accumulating this
   input's contribution to value_pool.dict and unsolved_condition on the way
   (see transcode_dtaint_with_magic_groups()).

   Best-effort: a short or failed read just skips this input (see the file
   header's "Known limitations"). */
static void process_input(afl_forkserver_t *fsrv, const char *src_dir,
                          const char *work_dir, worker_dict_t *dict,
                          novelty_set_t *novelty,
                          cond_status_set_t *cond_status, const char *fname) {

  u8 *in_path = alloc_printf("%s/%s", src_dir, fname);

  s32 fd = open((char *)in_path, O_RDONLY);
  if (fd < 0) {

    WARNF("Could not open input '%s': %s", in_path, strerror(errno));
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

/* scandir() comparator: plain byte order, deliberately NOT alphasort() --
   that one runs strcoll(), which would put the scan order (and with it both
   accumulated outputs, see run_seed_scan's comment) at the mercy of
   whatever LC_COLLATE the caller happens to have set. */
static int cmp_seed_dirent(const struct dirent **a, const struct dirent **b) {

  return strcmp((*a)->d_name, (*b)->d_name);

}

/* scandir() filter: same skips the readdir() loop this replaced did. The
   leading-dot test covers "." and ".." along with every other dotfile. */
static int keep_seed_dirent(const struct dirent *de) {

  if (de->d_name[0] == '.') return 0;
#ifdef DT_DIR
  if (de->d_type == DT_DIR) return 0;
#endif
  return 1;

}

/* -S seed_dir mode's whole job: run dtaint once over every plain file in
   seed_dir and drop "<filename>.dtaint" into out_dir (the flat cache dir a
   afl-fuzz's -r will point back at). Runs the forkserver on every file and
   files away whatever comes out.

   Files are visited in name order, via scandir(), not in raw readdir()
   order. The per-input .dtaint outputs don't care -- each is a pure
   function of its own input -- but value_pool.dict and unsolved_condition
   are accumulated across the whole scan behind a first-observation-wins
   novelty gate (novelty_check_and_mark(), see the extraction pass), so
   whichever input reaches a given (cmpid, context, condition) first is the
   one whose bytes land in the dict. Under readdir() order that made both
   outputs a property of the filesystem's directory layout rather than of
   the seed set: measured on 400 exiv2 seeds, re-scanning the same contents
   from a directory whose entries enumerated in a different order kept only
   61 of 119 value_pool.dict rows (unsolved_condition held up much better,
   323 of 325, since it accumulates sites and outcome directions rather
   than values). Sorting makes a given seed set produce one answer no
   matter which directory, filesystem, or machine it is scanned from --
   which is what makes two runs' pools comparable at all. */
static void run_seed_scan(afl_forkserver_t *fsrv, const char *seed_dir,
                          const char *out_dir, worker_dict_t *dict,
                          novelty_set_t *novelty, cond_status_set_t *cond_status) {

  struct dirent **list = NULL;
  int             n_ents = scandir(seed_dir, &list, keep_seed_dirent, cmp_seed_dirent);

  if (n_ents < 0) { PFATAL("Unable to open seed dir '%s'", seed_dir); }

  if (!quiet_mode) {

    ACTF("Seed scan: scanning '%s' (%d file(s), name order)...", seed_dir, n_ents);

  }

  u32 n = 0;

  for (int i = 0; i < n_ents; i++) {

    /* Keep draining the list even after a Ctrl-C so scandir()'s own
       allocations all get released -- just stop running the target. */
    if (!stop_soon) {

      process_input(fsrv, seed_dir, out_dir, dict, novelty, cond_status,
                    list[i]->d_name);
      ++n;

    }

    free(list[i]);

  }

  free(list);

  if (!quiet_mode) {

    OKF("Seed scan done: %u file(s) from '%s' -> '%s'.", n, seed_dir, out_dir);

  }

}

int main(int argc, char **argv_orig, char **envp) {

  (void)envp;

  s32  opt;
  u8  *out_dir = NULL;
  u8  *seed_scan_dir = NULL;
  u32  exec_tmout = 5000;
  u64  mem_limit = 0;

  char **argv = argv_cpy_dup(argc, argv_orig);

  if (getenv("AFL_QUIET") != NULL) { quiet_mode = 1; }

  while ((opt = getopt(argc, argv, "+o:S:t:m:Qh")) > 0) {

    switch (opt) {

      case 'o':
        if (out_dir) { FATAL("Multiple -o options not supported"); }
        out_dir = (u8 *)optarg;
        break;

      case 'S':
        if (seed_scan_dir) { FATAL("Multiple -S options not supported"); }
        seed_scan_dir = (u8 *)optarg;
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

      case 'Q':
        quiet_mode = 1;
        break;

      case 'h':
      default:
        usage((u8 *)argv[0]);

    }

  }

  if (!out_dir || !seed_scan_dir || optind == argc) { usage((u8 *)argv[0]); }

  /* -o is a flat directory: no queue/, no "default" instance nesting, just
     "<out_dir>/<seed filename>.dtaint" per seed, plus value_pool.dict and
     unsolved_condition alongside them. */
  u8 *work_dir = (u8 *)strdup((char *)out_dir);

  if (mkdir((char *)work_dir, 0755) && errno != EEXIST) {

    PFATAL("Could not create '%s'", work_dir);

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
      alloc_printf("%s/.afl-taint-scan.cur_input.%u", work_dir,
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

  /* One-shot: scan every seed, flush both outputs, exit. */
  if (!stop_soon) {

    run_seed_scan(fsrv, (char *)seed_scan_dir, (char *)work_dir, dict, novelty,
                  cond_status);

  }

  dict_write(dict, (char *)dict_out_path);
  unsolved_write(cond_status, (char *)unsolved_out_path);

  if (fsrv->out_fd >= 0 && !fsrv->use_stdin) { unlink((char *)stdin_file); }
  ck_free(stdin_file);

  afl_shm_deinit(&shm);
  afl_fsrv_deinit(fsrv);

  return 0;

}
