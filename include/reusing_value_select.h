/*
   american fuzzy lop++ - reusing mutation: value selection interface
   -----------------------------------------------------------------

   Pluggable "which record from a matched bucket to actually splice in"
   strategy. Selected once at startup via AFL_REUSING_VALUE_SELECT, same
   shape as include/reusing_filter.h.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_VALUE_SELECT_H
#define _AFL_REUSING_VALUE_SELECT_H

#include "reusing_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

struct afl_state;

typedef struct {

  struct afl_state             *afl; /* for rand_below() */
  const reusing_bucket_t        *bucket;
  const struct dtaint_cond_record *cond;

} reusing_value_select_ctx_t;

typedef struct {

  const reusing_record_t *record; /* NULL: skip this site */

} reusing_value_select_result_t;

typedef reusing_value_select_result_t (*reusing_value_select_fn)(
    const reusing_value_select_ctx_t *ctx);

typedef struct {

  const char              *name;
  reusing_value_select_fn  fn;
  const char               *description;

} reusing_value_select_entry_t;

reusing_value_select_fn reusing_value_select(void);
void                    reusing_value_select_list(void);

#ifdef __cplusplus
}
#endif

#endif
