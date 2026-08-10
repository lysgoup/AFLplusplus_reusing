/*
   american fuzzy lop++ - reuse-candidate value filters
   -----------------------------------------------------------------

   Concrete filters + the registry/selection glue for
   include/reusing_filter.h's interface. See that header for the contract;
   this file is where new filter levels actually get added (one function +
   one line in kFilters), and nowhere else.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reusing_filter.h"

/* Level "none": every taint-derived candidate is kept as-is. Still a real
   baseline, not "no filtering at all" -- a candidate only exists because
   it came from a tainted operand of some tracked comparison in the first
   place (that gate happens upstream, in whatever walks the .dtaint file
   and builds candidates -- not here), so "none" means "trust taint alone,
   apply nothing further". */
static reusing_filter_result_t filter_none(const reusing_filter_ctx_t *ctx) {

  (void)ctx;
  return (reusing_filter_result_t){.keep = 1};

}

/* Level "diff": keep only if this candidate's byte range overlaps
   something that actually differs between parent and child. Taint alone
   says "this byte could matter"; this says "and it's part of what THIS
   specific mutation changed" -- filters out bytes that are tainted (feed
   some comparison) but happened to survive this mutation untouched, which
   taint-only pooling can't otherwise distinguish from bytes the mutation
   was actually responsible for.

   No parent (original -i seed, depth 0) means there's nothing to diff
   against -- passes the candidate through unfiltered rather than
   discarding every seed-derived candidate outright, since "no parent"
   isn't evidence of unimportance, just an unanswerable question. */
static reusing_filter_result_t filter_diff(const reusing_filter_ctx_t *ctx) {

  if (!ctx->parent_buf || !ctx->parent_len) {

    return (reusing_filter_result_t){.keep = 1};

  }

  for (u32 i = 0; i < ctx->n_segs; ++i) {

    u32 begin = ctx->segs[i].begin;
    u32 end = ctx->segs[i].end;

    for (u32 off = begin; off < end; ++off) {

      /* Out-of-range on either side (an insertion/deletion shifted or
         grew/shrank the buffer at this offset) counts as "differs" too --
         that's still this mutation's doing, not something to silently
         treat as equal by clamping. */
      if (off >= ctx->child_len || off >= ctx->parent_len ||
          ctx->child_buf[off] != ctx->parent_buf[off]) {

        return (reusing_filter_result_t){.keep = 1};

      }

    }

  }

  return (reusing_filter_result_t){.keep = 0};

}

/* Level "novel": keep only if (cond->cmpid, cond->condition) has never
   been seen before this campaign (include/reusing_seen.h) -- checked
   against every taint-tracked input so far, not just one parent, so
   strictly stronger evidence than filter_diff's "byte differs from THIS
   parent". Context is deliberately excluded from that key; see
   reusing_filter_ctx_t's own comment on is_novel_tuple for why. The
   check-and-mark itself always runs upstream regardless of which filter
   is active (see afl-fuzz-reusing-ingest.c) -- this just reads the
   result. */
static reusing_filter_result_t filter_novel(const reusing_filter_ctx_t *ctx) {

  return (reusing_filter_result_t){.keep = ctx->is_novel_tuple};

}

/* Matched against AFL_REUSING_VALUE_FILTER. Add a new level by writing a
   function above and one line here -- reusing_filter_select() and every
   call site stay untouched. */
static const reusing_filter_entry_t kFilters[] = {

    {"none", filter_none,
     "keep every taint-derived candidate, no extra filtering"},
    {"diff", filter_diff,
     "keep only candidates overlapping a byte range that differs from the "
     "parent input"},
    {"novel", filter_novel,
     "keep only candidates whose (cmpid, condition) has never been seen "
     "before this campaign (default)"},

};

#define N_FILTERS (sizeof(kFilters) / sizeof(kFilters[0]))

void reusing_filter_list(void) {

  printf("Available AFL_REUSING_VALUE_FILTER values:\n");
  for (u32 i = 0; i < N_FILTERS; ++i) {

    printf("  %-10s %s\n", kFilters[i].name, kFilters[i].description);

  }

}

reusing_filter_fn reusing_filter_select(void) {

  const char *want = getenv("AFL_REUSING_VALUE_FILTER");

  if (want && !strcmp(want, "list")) {

    reusing_filter_list();
    exit(0);

  }

  if (want) {

    for (u32 i = 0; i < N_FILTERS; ++i) {

      if (!strcmp(want, kFilters[i].name)) { return kFilters[i].fn; }

    }

    fprintf(stderr,
            "[-] Unknown AFL_REUSING_VALUE_FILTER '%s'. Run with "
            "AFL_REUSING_VALUE_FILTER=list to see available values.\n",
            want);
    exit(1);

  }

  /* Default is "novel" -- campaign-wide (cmpid, condition) history is a
     stronger signal than filter_diff's "differs from one parent" (see
     filter_novel's own comment), and plain taintedness alone ("none")
     isn't a strong enough signal at all. */
  for (u32 i = 0; i < N_FILTERS; ++i) {

    if (!strcmp("novel", kFilters[i].name)) { return kFilters[i].fn; }

  }

  return filter_none; /* unreachable unless kFilters loses "novel" itself */

}
