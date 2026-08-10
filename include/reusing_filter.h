/*
   american fuzzy lop++ - reuse-candidate value filter interface
   -----------------------------------------------------------------

   Pluggable "is this taint-derived candidate worth pooling for later
   reuse" decision point. A candidate is a (comparison, byte-offset-range)
   pair produced while scanning a newly-saved input's .dtaint log -- taint
   alone only says a byte *could* matter (it fed some tracked comparison);
   these filters narrow that down using additional signal (has this byte
   actually changed vs the parent input, did it flip a branch outcome,
   etc), each at a different cost/precision tradeoff. Selected once at
   startup via AFL_REUSING_VALUE_FILTER; adding a new one is one function
   plus one line in afl-fuzz-reusing-filter.c's kFilters table, no changes
   needed anywhere a filter gets called.

   This header is the interface only -- there is no pool-builder consuming
   it yet (that's the next slice: walking a .dtaint file's cond_list,
   resolving lb1/lb2 through the tags table to get segs, and calling
   through reusing_filter_select()'s chosen function per candidate before
   deciding whether to store it).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_FILTER_H
#define _AFL_REUSING_FILTER_H

#include "dtaint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Everything a filter might need to judge one candidate. Filters read
   this; they never mutate it or take ownership of any pointer inside it. */
typedef struct {

  /* The input the candidate was extracted from (the one whose .dtaint log
     is being walked right now). */
  const u8 *child_buf;
  u32       child_len;

  /* q->mother's bytes, if this queue entry has a parent -- NULL/0 for an
     original -i seed (depth 0) or if the parent's bytes couldn't be
     loaded. Filters that need a parent to say anything meaningful should
     pass the candidate through unfiltered in this case (see filter_diff),
     not discard it outright -- "no parent" isn't evidence the candidate
     is unimportant. */
  const u8 *parent_buf;
  u32       parent_len;

  /* The comparison this candidate's value(s) came from. */
  const struct dtaint_cond_record *cond;

  /* Resolved byte-offset range(s) the candidate's value covers -- already
     merged-continuous, i.e. exactly the ranges a reuse mutator would
     later splice a stored value back into. */
  const struct dtaint_tag_seg_wire *segs;
  u32                               n_segs;

  /* 1 if (cond->cmpid, cond->condition) has never been seen before this
     campaign (see include/reusing_seen.h) -- context deliberately left
     out of that key, since context differences trace back to an
     earlier call site's own choice, not this cmpid's. Always computed
     (and the seen-set always updated) regardless of which filter is
     active, so the set stays accurate even when switching filters. */
  u8 is_novel_tuple;

} reusing_filter_ctx_t;

/* A struct, not a bare bool, so new signals (a confidence score, a
   refined sub-range, ...) can be added later without changing every
   existing filter's signature -- designated-initializer callers like
   `(reusing_filter_result_t){.keep = 1}` leave new fields zero by
   default, so old filter bodies keep compiling unmodified. */
typedef struct {

  u8 keep; /* nonzero: candidate survives, gets pooled for reuse */

} reusing_filter_result_t;

typedef reusing_filter_result_t (*reusing_filter_fn)(
    const reusing_filter_ctx_t *ctx);

typedef struct {

  const char       *name; /* matched against AFL_REUSING_VALUE_FILTER */
  reusing_filter_fn fn;
  const char        *description; /* shown by AFL_REUSING_VALUE_FILTER=list */

} reusing_filter_entry_t;

/* Resolves AFL_REUSING_VALUE_FILTER once (fall back to a documented
   default if unset) and returns the chosen filter function. Exits the
   process on an unrecognized value or on AFL_REUSING_VALUE_FILTER=list
   (after printing the list) -- meant to be called once during startup,
   the same way AFL_DTAINT_BINARY gets read once in afl-fuzz.c, not
   per-candidate. */
reusing_filter_fn reusing_filter_select(void);

/* Prints all registered filters' names + descriptions to stdout. */
void reusing_filter_list(void);

#ifdef __cplusplus
}
#endif

#endif
