/*
   american fuzzy lop++ - reusing pool: seen (cmpid, condition) set
   -----------------------------------------------------------------

   Campaign-wide record of which (cmpid, condition) outcomes have ever
   been observed, independent of context (see reusing_filter_ctx_t's own
   comment on why context is left out). Backs the "novel" filter level
   (afl-fuzz-reusing-filter.c) -- a much stronger signal than filter_diff's
   "byte differs from parent", since it's checked against every taint-
   tracked input so far, not just one ancestor.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_SEEN_H
#define _AFL_REUSING_SEEN_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reusing_seen reusing_seen_t;

reusing_seen_t *reusing_seen_create(void);
void            reusing_seen_free(reusing_seen_t *seen);

/* Checks whether (cmpid, condition) is already in the set; if not, inserts
   it. Returns 1 if this call just inserted it (i.e. it's novel this
   campaign), 0 if it was already there. Combined check+insert, same
   reasoning as reusing_pool_insert's own dedup-then-insert shape -- avoids
   a second hash probe on the common path.

   Identity is by hash alone, not by re-deriving (cmpid, condition) from a
   stored key -- a collision could make a genuinely novel tuple look
   already-seen (a missed candidate, not a correctness problem), same
   "good enough, not collision-free" tradeoff already accepted elsewhere
   in this codebase's own hash tables (dtaint_runtime/dtaint_logger.c's
   order_map, afl-fuzz-reusing-pool.c's slots). */
u8 reusing_seen_check_and_mark(reusing_seen_t *seen, u32 cmpid, u32 condition);

#ifdef __cplusplus
}
#endif

#endif
