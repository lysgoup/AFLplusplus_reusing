/*
   american fuzzy lop++ - reuse-mutation site selection strategies
   -----------------------------------------------------------------

   Concrete strategies + registry/selection glue for include/
   reusing_site_select.h. Add a new strategy: one function + one line in
   kSiteSelects, nowhere else.

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
#include "reusing_site_select.h"

/* Cycles through all sites in order, repeating (0,1,...,n_sites-1,0,1,...)
   until `budget` picks are made -- always spends the full budget rather
   than capping at n_sites, since revisiting a site still costs a fresh
   value_select() draw (a different candidate value from its bucket). */
static reusing_site_select_result_t site_select_first(
    const reusing_site_select_ctx_t *ctx) {

  reusing_site_select_result_t result = {.indices = NULL, .n_indices = 0};
  if (ctx->budget == 0 || ctx->n_sites == 0) { return result; }

  result.indices = malloc((size_t)ctx->budget * sizeof(u32));
  if (!result.indices) { abort(); }
  for (u32 i = 0; i < ctx->budget; ++i) result.indices[i] = i % ctx->n_sites;
  result.n_indices = ctx->budget;

  return result;

}

/* `budget` random draws with replacement -- same "always spend the full
   budget" reasoning as site_select_first above. Default: spreads which
   site gets hit each draw instead of always cycling in the same order. */
static reusing_site_select_result_t site_select_random(
    const reusing_site_select_ctx_t *ctx) {

  reusing_site_select_result_t result = {.indices = NULL, .n_indices = 0};
  if (ctx->budget == 0 || ctx->n_sites == 0) { return result; }

  result.indices = malloc((size_t)ctx->budget * sizeof(u32));
  if (!result.indices) { abort(); }
  for (u32 i = 0; i < ctx->budget; ++i) {

    result.indices[i] = rand_below(ctx->afl, ctx->n_sites);

  }

  result.n_indices = ctx->budget;

  return result;

}

static const reusing_site_select_entry_t kSiteSelects[] = {

    {"first", site_select_first, "cycle through sites in order, `budget` picks"},
    {"random", site_select_random,
     "`budget` random picks with replacement (default)"},

};

#define N_SITE_SELECTS (sizeof(kSiteSelects) / sizeof(kSiteSelects[0]))

void reusing_site_select_list(void) {

  printf("Available AFL_REUSING_SITE_SELECT values:\n");
  for (u32 i = 0; i < N_SITE_SELECTS; ++i) {

    printf("  %-10s %s\n", kSiteSelects[i].name, kSiteSelects[i].description);

  }

}

reusing_site_select_fn reusing_site_select(void) {

  const char *want = getenv("AFL_REUSING_SITE_SELECT");

  if (want && !strcmp(want, "list")) {

    reusing_site_select_list();
    exit(0);

  }

  if (want) {

    for (u32 i = 0; i < N_SITE_SELECTS; ++i) {

      if (!strcmp(want, kSiteSelects[i].name)) { return kSiteSelects[i].fn; }

    }

    fprintf(stderr,
            "[-] Unknown AFL_REUSING_SITE_SELECT '%s'. Run with "
            "AFL_REUSING_SITE_SELECT=list to see available values.\n",
            want);
    exit(1);

  }

  for (u32 i = 0; i < N_SITE_SELECTS; ++i) {

    if (!strcmp("random", kSiteSelects[i].name)) { return kSiteSelects[i].fn; }

  }

  return site_select_first; /* unreachable unless kSiteSelects loses "random" */

}
