/*
   american fuzzy lop++ - reusing pool: pattern computation
   -----------------------------------------------------------------

   One shared function for turning a raw list of taint offset segments
   (however a caller resolved them -- lb1 alone, lb2 alone, lb1+lb2
   concatenated for a dual-tainted comparison, whatever) into the
   (merged segments, length-signature pattern) pair that both the reuse
   filters (include/reusing_filter.h) and the pool builder (not written
   yet) key off of. One implementation, so "how do we merge continuous
   segments" and "how do we turn that into a pattern" can't drift between
   call sites the way two independent copies would.

   No cap on segment count and no cap on how many distinct patterns exist
   -- both `reusing_pattern_t.lens` and the merged segment list are
   heap-allocated to whatever size the input actually has.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_PATTERN_H
#define _AFL_REUSING_PATTERN_H

#include "dtaint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A pattern is just the byte length of each merged segment, in order --
   the shape a candidate's value fills, independent of where in any
   particular input it came from. Two candidates with the same pattern are
   interchangeable at the byte-splicing level (see reusing_filter_ctx_t's
   own segs, which are the merged segments this same computation
   produces). */
typedef struct {

  u32 *lens;   /* heap-allocated, n_lens entries */
  u32  n_lens;

} reusing_pattern_t;

/* Sorts a *copy* of `segs` (n_segs of them) by begin, merges wherever
   consecutive ranges touch (prev.end == cur.begin), then measures the
   resulting merged ranges into a pattern. Sorting internally (not just
   documenting "caller must pre-sort") matters for more than tidiness: a
   caller building a dual-tainted candidate (lb1's segments concatenated
   with lb2's) hands in two label's worth of ranges that are each
   individually ordered but not jointly sorted against each other, and
   merging unsorted input would silently produce wrong (non-maximal or
   out-of-order) merged ranges instead of failing loudly.

   Writes the merged segments to merged_out / n_merged_out (heap-
   allocated; free with `free()`) and returns the pattern (also heap-
   allocated; free with reusing_pattern_free()). Both outputs always have
   the same length (n_lens == *n_merged_out) and are index-aligned --
   pattern.lens[i] is exactly merged_out[i].end - merged_out[i].begin --
   since they're computed together in one pass over the same merge
   result, not by two separate implementations that could disagree.

   segs with n_segs == 0 produces an empty pattern (n_lens == 0, lens ==
   NULL) and *merged_out == NULL -- callers should treat that as "no
   pattern to key off of", not an error. */
reusing_pattern_t reusing_compute_pattern(const struct dtaint_tag_seg_wire *segs,
                                          u32 n_segs,
                                          struct dtaint_tag_seg_wire **merged_out,
                                          u32 *n_merged_out);

void reusing_pattern_free(reusing_pattern_t *pattern);

#ifdef __cplusplus
}
#endif

#endif
