/*
   american fuzzy lop++ - reusing pool: mutation stage
   -----------------------------------------------------------------

   The consumer side of the reusing pool -- placed in fuzz_one()
   (src/afl-fuzz-one.c) right next to input_to_state_stage() (the
   closest structural analog: use side info from tracked comparisons to
   try meaningful replacement values, rather than blind mutation),
   budgeted the same way custom_mutator_stage is (HAVOC_CYCLES *
   perf_score / havoc_div, floored at HAVOC_MIN) so it costs about as
   much as any other single stage, not a separate large budget on top.

   Mirrors reusing_ingest_dtaint()'s own walk of a .dtaint file (src/
   afl-fuzz-reusing-ingest.c) -- same lb1-alone/lb2-alone/merged shape --
   but in reverse: instead of extracting a candidate's value out of
   child_buf and inserting it into the pool, this looks each computed
   pattern up via reusing_pool_find_bucket() (read-only -- see include/
   reusing_pool.h) and, if matched, splices a pool-chosen value back into
   out_buf at the same offsets.

   Which sites to try and how many (include/reusing_site_select.h) and
   which record to use from a matched bucket (include/
   reusing_value_select.h) are both pluggable, same shape as include/
   reusing_filter.h. Resolved fresh each call (a couple of getenv()s,
   not per-byte) rather than cached on afl_state_t -- their ctx/result
   types need reusing_pool.h's bucket/record structs, which afl-fuzz.h
   deliberately doesn't pull in (see its own reusing_pool field
   comment), so keeping the resolve local to this file avoids that
   header growing a heavier dependency for every other .c file that
   includes it.

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
#include "reusing_site_select.h"
#include "reusing_value_select.h"

/* Computes the pattern for `segs` and, if afl->reusing_pool has a
   matching bucket with at least one record, appends a candidate site
   (growing *sites as needed). `segs` itself is only read here (the
   pattern computation sorts its own copy); the *merged* array
   reusing_compute_pattern() produces is what gets kept (ownership
   transferred into the new site), since that's what the splice step
   later needs -- the pattern itself is only needed for the lookup and
   is freed immediately after. */
static void add_site(afl_state_t *afl, const struct dtaint_cond_record *cond,
                     const struct dtaint_tag_seg_wire *segs, u32 n_segs,
                     reusing_site_t **sites, u32 *n_sites, u32 *cap_sites) {

  if (n_segs == 0) { return; }

  struct dtaint_tag_seg_wire *merged = NULL;
  u32                         n_merged = 0;
  reusing_pattern_t pattern = reusing_compute_pattern(segs, n_segs, &merged, &n_merged);

  if (pattern.n_lens == 0) {

    reusing_pattern_free(&pattern);
    free(merged);
    return;

  }

  reusing_bucket_t *bucket = reusing_pool_find_bucket(afl->reusing_pool, &pattern);
  reusing_pattern_free(&pattern); /* only needed for the lookup itself */

  if (!bucket || bucket->n_records == 0) {

    free(merged);
    return;

  }

  if (*n_sites >= *cap_sites) {

    u32 new_cap = *cap_sites ? *cap_sites * 2 : 16;
    reusing_site_t *grown = realloc(*sites, (size_t)new_cap * sizeof(reusing_site_t));
    if (!grown) { abort(); }
    *sites = grown;
    *cap_sites = new_cap;

  }

  (*sites)[*n_sites].cond = cond;
  (*sites)[*n_sites].segs = merged; /* ownership moves here */
  (*sites)[*n_sites].n_segs = n_merged;
  (*sites)[*n_sites].bucket = bucket;
  ++*n_sites;

}

u8 reusing_mutation_stage(afl_state_t *afl, u8 *in_buf, u8 *out_buf, u32 len) {

  if (!afl->reusing_pool) { return 0; }

  /* This input's own .dtaint file -- same naming convention as
     log_dtaint_for_new_input() (src/afl-fuzz-dtaint.c). Missing/
     unparsable is routine (e.g. this seed never got taint-tracked, or
     had nothing taint-worthy), not an error. */
  const char *base = strrchr((const char *)afl->queue_cur->fname, '/');
  base = base ? base + 1 : (const char *)afl->queue_cur->fname;
  u8 *dtaint_path = alloc_printf("%s/dtaint_logs/%s.dtaint", afl->out_dir, base);

  dtaint_reader_t *reader = dtaint_reader_load((const char *)dtaint_path);
  ck_free(dtaint_path);

  if (!reader) { return 0; }

  u32 n_conds = 0;
  const struct dtaint_cond_record *conds = dtaint_reader_conds(reader, &n_conds);

  reusing_site_t *sites = NULL;
  u32 n_sites = 0, cap_sites = 0;

  for (u32 i = 0; i < n_conds; ++i) {

    const struct dtaint_cond_record *cond = &conds[i];

    u32 n1 = 0, n2 = 0;
    const struct dtaint_tag_seg_wire *segs1 =
        dtaint_reader_resolve_label(reader, cond->lb1, &n1);
    const struct dtaint_tag_seg_wire *segs2 =
        dtaint_reader_resolve_label(reader, cond->lb2, &n2);

    if (segs1) { add_site(afl, cond, segs1, n1, &sites, &n_sites, &cap_sites); }
    if (segs2) { add_site(afl, cond, segs2, n2, &sites, &n_sites, &cap_sites); }

    if (segs1 && segs2) {

      struct dtaint_tag_seg_wire *combined =
          malloc((size_t)(n1 + n2) * sizeof(struct dtaint_tag_seg_wire));
      if (!combined) { abort(); }
      memcpy(combined, segs1, (size_t)n1 * sizeof(struct dtaint_tag_seg_wire));
      memcpy(combined + n1, segs2, (size_t)n2 * sizeof(struct dtaint_tag_seg_wire));

      add_site(afl, cond, combined, n1 + n2, &sites, &n_sites, &cap_sites);

      free(combined);

    }

  }

  dtaint_reader_free(reader); /* sites[].segs are our own copies, safe past this */

  u8 ret = 0;

  if (n_sites == 0) { goto cleanup; }

  afl->stage_name = "reusing";
  afl->stage_short = "reuse";
  afl->stage_val_type = STAGE_VAL_NONE;

  {

    u32 shift = 8;
    u32 perf_score = (u32)afl->queue_cur->perf_score;
    afl->stage_max = (HAVOC_CYCLES * perf_score / afl->havoc_div) >> shift;
    if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  }

  {

    reusing_site_select_ctx_t site_ctx = {
        .afl = afl, .sites = sites, .n_sites = n_sites, .budget = afl->stage_max};
    reusing_site_select_result_t chosen = reusing_site_select()(&site_ctx);
    reusing_value_select_fn      pick_value = reusing_value_select();

    u64 orig_hit_cnt = afl->queued_items + afl->saved_crashes;

    for (afl->stage_cur = 0; afl->stage_cur < chosen.n_indices; ++afl->stage_cur) {

      const reusing_site_t *site = &sites[chosen.indices[afl->stage_cur]];

      reusing_value_select_ctx_t value_ctx = {
          .afl = afl, .bucket = site->bucket, .cond = site->cond};
      reusing_value_select_result_t val = pick_value(&value_ctx);

      if (!val.record) { continue; }

      memcpy(out_buf, in_buf, len);

      u32 off = 0;
      u8  in_range = 1;

      for (u32 s = 0; s < site->n_segs; ++s) {

        u32 begin = site->segs[s].begin, end = site->segs[s].end;

        /* Offsets came from this same queue entry's own .dtaint log, so
           they should always fit -- unless the file was trimmed/edited
           since being taint-tracked. Skip rather than trust it. */
        if (end > len || begin > end) { in_range = 0; break; }

        memcpy(out_buf + begin, val.record->value + off, end - begin);
        off += end - begin;

      }

      if (!in_range) { continue; }

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation), "%s REUSING_cmpid_%u",
               afl->queue_cur->fname, site->cond->cmpid);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) {

        ret = 1;
        free(chosen.indices);
        goto cleanup;

      }

    }

    u64 new_hit_cnt = afl->queued_items + afl->saved_crashes;
    afl->stage_finds[STAGE_REUSING] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_REUSING] += chosen.n_indices;

    free(chosen.indices);

  }

cleanup:

  for (u32 i = 0; i < n_sites; ++i) free((void *)sites[i].segs);
  free(sites);

  return ret;

}
