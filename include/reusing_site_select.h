/*
   american fuzzy lop++ - reusing mutation: site selection interface
   -----------------------------------------------------------------

   Pluggable "which of this input's pool-matched candidate sites to
   actually try, and how many" strategy. Selected once at startup via
   AFL_REUSING_SITE_SELECT, same shape as include/reusing_filter.h.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_SITE_SELECT_H
#define _AFL_REUSING_SITE_SELECT_H

#include "reusing_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

struct afl_state;

/* One pool-matched candidate site in the input currently being mutated
   -- a byte range plus the pool bucket whose pattern matches it (always
   >=1 record; sites with no matching bucket never get built). */
typedef struct {

  const struct dtaint_cond_record  *cond;
  const struct dtaint_tag_seg_wire *segs;
  u32                                n_segs;
  reusing_bucket_t                 *bucket;

} reusing_site_t;

typedef struct {

  struct afl_state      *afl; /* for rand_below() */
  const reusing_site_t *sites;
  u32                    n_sites;
  u32                    budget; /* how many attempts the caller can afford */

} reusing_site_select_ctx_t;

typedef struct {

  u32 *indices; /* heap-allocated, indices into ctx->sites; caller frees */
  u32  n_indices;

} reusing_site_select_result_t;

typedef reusing_site_select_result_t (*reusing_site_select_fn)(
    const reusing_site_select_ctx_t *ctx);

typedef struct {

  const char             *name;
  reusing_site_select_fn  fn;
  const char              *description;

} reusing_site_select_entry_t;

reusing_site_select_fn reusing_site_select(void);
void                   reusing_site_select_list(void);

#ifdef __cplusplus
}
#endif

#endif
