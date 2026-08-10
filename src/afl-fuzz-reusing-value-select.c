/*
   american fuzzy lop++ - reuse-mutation value selection strategies
   -----------------------------------------------------------------

   Concrete strategies + registry/selection glue for include/
   reusing_value_select.h. Add a new strategy: one function + one line in
   kValueSelects, nowhere else.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl-fuzz.h"
#include "reusing_value_select.h"

/* Oldest (first-inserted) record in the bucket -- deterministic baseline. */
static reusing_value_select_result_t value_select_first(
    const reusing_value_select_ctx_t *ctx) {

  if (ctx->bucket->n_records == 0) { return (reusing_value_select_result_t){.record = NULL}; }
  return (reusing_value_select_result_t){.record = &ctx->bucket->records[0]};

}

/* Uniformly random record in the bucket. Default: a bucket accumulates
   many distinct values over a campaign (see the reusing_pool.txt dumps
   this was designed against); always picking the first one would ignore
   nearly all of them. */
static reusing_value_select_result_t value_select_random(
    const reusing_value_select_ctx_t *ctx) {

  if (ctx->bucket->n_records == 0) { return (reusing_value_select_result_t){.record = NULL}; }
  u32 idx = rand_below(ctx->afl, ctx->bucket->n_records);
  return (reusing_value_select_result_t){.record = &ctx->bucket->records[idx]};

}

static const reusing_value_select_entry_t kValueSelects[] = {

    {"first", value_select_first, "oldest record in the matched bucket"},
    {"random", value_select_random,
     "uniformly random record in the matched bucket (default)"},

};

#define N_VALUE_SELECTS (sizeof(kValueSelects) / sizeof(kValueSelects[0]))

void reusing_value_select_list(void) {

  printf("Available AFL_REUSING_VALUE_SELECT values:\n");
  for (u32 i = 0; i < N_VALUE_SELECTS; ++i) {

    printf("  %-10s %s\n", kValueSelects[i].name, kValueSelects[i].description);

  }

}

reusing_value_select_fn reusing_value_select(void) {

  const char *want = getenv("AFL_REUSING_VALUE_SELECT");

  if (want && !strcmp(want, "list")) {

    reusing_value_select_list();
    exit(0);

  }

  if (want) {

    for (u32 i = 0; i < N_VALUE_SELECTS; ++i) {

      if (!strcmp(want, kValueSelects[i].name)) { return kValueSelects[i].fn; }

    }

    fprintf(stderr,
            "[-] Unknown AFL_REUSING_VALUE_SELECT '%s'. Run with "
            "AFL_REUSING_VALUE_SELECT=list to see available values.\n",
            want);
    exit(1);

  }

  for (u32 i = 0; i < N_VALUE_SELECTS; ++i) {

    if (!strcmp("random", kValueSelects[i].name)) { return kValueSelects[i].fn; }

  }

  return value_select_first; /* unreachable unless kValueSelects loses "random" */

}
