/*
   american fuzzy lop++ - reusing pool: .dtaint -> pool ingestion
   -----------------------------------------------------------------

   The glue between the other reusing_* pieces and the fuzzing loop:
   loads a just-written .dtaint file (include/reusing_dtaint_reader.h),
   walks its cond_list, and for every comparison where BOTH operands trace
   back to real input bytes (cond->lb1 and cond->lb2 both nonzero), pools
   up to three reuse candidates through afl->reusing_filter and
   afl->reusing_pool:

     - lb1's own segments alone
     - lb2's own segments alone
     - lb1's and lb2's segments merged into one

   so a later consumer can reuse either side independently or the
   observed pair together. Each candidate's pattern is computed fresh via
   reusing_compute_pattern() (include/reusing_pattern.h) from exactly the
   segments passed to it -- lb1 alone, lb2 alone, or both concatenated --
   since the pattern depends on which segments went in.

   cond_list entries with only ONE side tainted (comparing input bytes
   against a compile-time constant -- REUSING_SRC_MAGIC/REUSING_SRC_CMPFN
   in include/reusing_pool.h's enum) are read but deliberately not pooled
   here yet -- deferred by explicit request, not an oversight. Every
   candidate this file does insert is REUSING_SRC_TAINTED.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdlib.h>
#include <string.h>

#include "afl-fuzz.h"
#include "reusing_dtaint_reader.h"
#include "reusing_pattern.h"
#include "reusing_pool.h"

/* Computes the pattern for `segs`, runs it through `filter`, and -- if
   kept -- slices `child_buf` at the (merged) segment offsets and inserts
   the result into afl->reusing_pool as a REUSING_SRC_TAINTED candidate.
   Called once per side (lb1 alone, lb2 alone) and once for the merged
   pair by reusing_ingest_dtaint() below; kept as its own function so
   those three call sites can't drift into three slightly different
   pattern/filter/insert sequences. */
static void ingest_segs(afl_state_t *afl, const struct dtaint_cond_record *cond,
                        const struct dtaint_tag_seg_wire *segs, u32 n_segs,
                        const u8 *child_buf, u32 child_len,
                        const u8 *parent_buf, u32 parent_len) {

  if (n_segs == 0) return;

  struct dtaint_tag_seg_wire *merged = NULL;
  u32                         n_merged = 0;
  reusing_pattern_t pattern = reusing_compute_pattern(segs, n_segs, &merged, &n_merged);

  if (pattern.n_lens == 0) {

    reusing_pattern_free(&pattern);
    return;

  }

  /* Offsets are only meaningful against the exact bytes this run's dtaint
     pass just tainted -- should always fit within child_len by
     construction, but a truncated/corrupt .dtaint file is a routine,
     expected failure mode here (see reusing_dtaint_reader.h), so this is
     checked rather than trusted. */
  for (u32 i = 0; i < n_merged; i++) {

    if (merged[i].end > child_len || merged[i].begin > merged[i].end) {

      reusing_pattern_free(&pattern);
      free(merged);
      return;

    }

  }

  reusing_filter_ctx_t ctx = {

      .child_buf = child_buf,
      .child_len = child_len,
      .parent_buf = parent_buf,
      .parent_len = parent_len,
      .cond = cond,
      .segs = merged,
      .n_segs = n_merged,

  };

  reusing_filter_result_t result = afl->reusing_filter(&ctx);

  if (result.keep) {

    u32 value_len = 0;
    for (u32 i = 0; i < n_merged; i++) value_len += merged[i].end - merged[i].begin;

    u8 *value = malloc(value_len);
    if (!value) abort();

    u32 off = 0;
    for (u32 i = 0; i < n_merged; i++) {

      u32 seg_len = merged[i].end - merged[i].begin;
      memcpy(value + off, child_buf + merged[i].begin, seg_len);
      off += seg_len;

    }

    reusing_pool_insert(afl->reusing_pool, &pattern, cond->cmpid, cond->context,
                       REUSING_SRC_TAINTED, value, value_len);

    free(value);

  }

  reusing_pattern_free(&pattern);
  free(merged);

}

void reusing_ingest_dtaint(afl_state_t *afl, const u8 *dtaint_path,
                          const u8 *child_buf, u32 child_len,
                          const u8 *parent_buf, u32 parent_len) {

  if (!dtaint_path) return;

  dtaint_reader_t *reader = dtaint_reader_load((const char *)dtaint_path);
  if (!reader) return;

  u32                               n_conds = 0;
  const struct dtaint_cond_record *conds = dtaint_reader_conds(reader, &n_conds);

  for (u32 i = 0; i < n_conds; i++) {

    const struct dtaint_cond_record *cond = &conds[i];

    /* Single-tainted (comparison against a compile-time constant) --
       deferred, see this file's own header comment. */
    if (cond->lb1 == 0 || cond->lb2 == 0) continue;

    u32 n1 = 0, n2 = 0;
    const struct dtaint_tag_seg_wire *segs1 =
        dtaint_reader_resolve_label(reader, cond->lb1, &n1);
    const struct dtaint_tag_seg_wire *segs2 =
        dtaint_reader_resolve_label(reader, cond->lb2, &n2);

    /* Both labels are nonzero, so the writer's tags table should have an
       entry for each (save_tag() is called unconditionally for both
       before the cond record itself is ever pushed) -- missing here means
       a truncated file, which dtaint_reader_load() would normally have
       already caught. Skip defensively rather than trust it. */
    if (!segs1 || !segs2) continue;

    ingest_segs(afl, cond, segs1, n1, child_buf, child_len, parent_buf, parent_len);
    ingest_segs(afl, cond, segs2, n2, child_buf, child_len, parent_buf, parent_len);

    struct dtaint_tag_seg_wire *combined =
        malloc((size_t)(n1 + n2) * sizeof(struct dtaint_tag_seg_wire));
    if (!combined) abort();
    memcpy(combined, segs1, (size_t)n1 * sizeof(struct dtaint_tag_seg_wire));
    memcpy(combined + n1, segs2, (size_t)n2 * sizeof(struct dtaint_tag_seg_wire));

    ingest_segs(afl, cond, combined, n1 + n2, child_buf, child_len, parent_buf, parent_len);

    free(combined);

  }

  dtaint_reader_free(reader);

}
