/*
   american fuzzy lop++ - reusing pool: pattern computation
   -----------------------------------------------------------------

   Implementation. See include/reusing_pattern.h for the contract.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdlib.h>
#include <string.h>

#include "reusing_pattern.h"

static int cmp_seg_begin(const void *a, const void *b) {

  const struct dtaint_tag_seg_wire *sa = a;
  const struct dtaint_tag_seg_wire *sb = b;

  if (sa->begin < sb->begin) return -1;
  if (sa->begin > sb->begin) return 1;
  return 0;

}

reusing_pattern_t reusing_compute_pattern(const struct dtaint_tag_seg_wire *segs,
                                          u32 n_segs,
                                          struct dtaint_tag_seg_wire **merged_out,
                                          u32 *n_merged_out) {

  reusing_pattern_t pattern = {.lens = NULL, .n_lens = 0};

  if (n_segs == 0 || !segs) {

    *merged_out = NULL;
    *n_merged_out = 0;
    return pattern;

  }

  /* Sort a copy -- never mutate what the caller handed in. */
  struct dtaint_tag_seg_wire *sorted =
      malloc((size_t)n_segs * sizeof(struct dtaint_tag_seg_wire));
  if (!sorted) { abort(); }
  memcpy(sorted, segs, (size_t)n_segs * sizeof(struct dtaint_tag_seg_wire));
  qsort(sorted, n_segs, sizeof(struct dtaint_tag_seg_wire), cmp_seg_begin);

  /* Merge in place within `sorted` -- at most n_segs merged ranges come
     out, so this never needs to grow past the input size. */
  struct dtaint_tag_seg_wire *merged =
      malloc((size_t)n_segs * sizeof(struct dtaint_tag_seg_wire));
  if (!merged) { abort(); }

  u32 n_merged = 0;
  merged[0] = sorted[0];
  n_merged = 1;

  for (u32 i = 1; i < n_segs; ++i) {

    struct dtaint_tag_seg_wire *last = &merged[n_merged - 1];

    if (sorted[i].begin <= last->end) {

      /* Touching or overlapping -- extend, don't start a new range.
         `<=` (not `==`) so overlapping ranges from two different labels
         (the dual-tainted-candidate case) merge too, not just exactly-
         adjacent ones. */
      if (sorted[i].end > last->end) { last->end = sorted[i].end; }

    } else {

      merged[n_merged++] = sorted[i];

    }

  }

  free(sorted);

  pattern.lens = malloc((size_t)n_merged * sizeof(u32));
  if (!pattern.lens) { abort(); }
  for (u32 i = 0; i < n_merged; ++i) {

    pattern.lens[i] = merged[i].end - merged[i].begin;

  }
  pattern.n_lens = n_merged;

  *merged_out = merged;
  *n_merged_out = n_merged;

  return pattern;

}

void reusing_pattern_free(reusing_pattern_t *pattern) {

  free(pattern->lens);
  pattern->lens = NULL;
  pattern->n_lens = 0;

}
