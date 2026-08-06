/*
   american fuzzy lop++ - reusing pool
   -----------------------------------------------------------------

   The stateful store reuse candidates accumulate into over a campaign --
   keyed by reusing_pattern_t (see include/reusing_pattern.h), one bucket
   per distinct pattern, one record per distinct (accepted-by-filter)
   candidate value seen for that pattern.

   This header is the pool's own self-contained API (create/insert/
   lookup/free) only. Nothing here reads a .dtaint file or hooks into the
   fuzzing loop yet -- that glue (walk a newly-written .dtaint log's
   cond_list, resolve lb1/lb2 through its tags table, call
   reusing_filter_select()'s chosen filter per candidate, insert survivors
   here) is the next slice, built on top of this.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_POOL_H
#define _AFL_REUSING_POOL_H

#include "reusing_pattern.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Where a record's value came from -- not part of any lookup key, kept as
   metadata so a future filter/consumer can prefer or restrict by kind
   without needing a second pool. */
typedef enum {

  REUSING_SRC_TAINTED, /* observed real input bytes at these offsets */
  REUSING_SRC_MAGIC,   /* untransformed constant-comparison operand */
  REUSING_SRC_CMPFN,   /* strcmp/memcmp-family raw snapshot */

} reusing_value_source_t;

/* One candidate value. `value` is a single contiguous buffer (see
   include/reusing_pattern.h's own reasoning on why records are serialized
   rather than split per-segment) -- its per-segment boundaries are
   whatever the owning bucket's `pattern.lens` says, not stored again
   here. `value_len` is redundant with that (always equals the sum of the
   owning bucket's pattern.lens), kept inline anyway so a record is
   self-describing without needing its bucket at hand. */
typedef struct reusing_record {

  u32                    cmpid;
  u32                    context;
  reusing_value_source_t source;

  u8    *value;      /* heap-allocated, value_len bytes, pool-owned */
  u32    value_len;
  u32    value_hash;  /* over `value`, computed once at insert; dedup key */

} reusing_record_t;

/* All records sharing one pattern. Growable array, no cap -- insertion
   order is preserved for free by array order (see include/reusing_pool.h
   -- er, this file's own header comment -- on why that means no separate
   insertion-order side list is needed the way Angora's own pools used
   one). `pattern` is this bucket's own copy (see reusing_pool_insert's
   ownership note) -- doubles as the value records[i].value should be
   interpreted against, and as the exact-match check when the top-level
   table's hash lookup lands here (hash collisions between two genuinely
   different patterns are possible; a stored copy of the real pattern is
   what tells them apart). */
typedef struct {

  reusing_pattern_t pattern;

  reusing_record_t *records;
  u32               n_records;
  u32               cap_records;

} reusing_bucket_t;

/* Top-level pool: open-addressing hash table keyed by hash(pattern),
   mirroring dtaint_runtime/dtaint_logger.c's order_map_get/grow (same
   codebase, same proven shape) except each slot holds a bucket pointer
   instead of a plain counter. No cap on the number of distinct patterns
   or on records per bucket (both by design -- see the reusing-pool
   design discussion this header came out of).

   Tagged (`struct reusing_pool`, not an anonymous struct) specifically so
   include/afl-fuzz.h can hold a `struct reusing_pool *` field via a bare
   forward declaration (`struct reusing_pool;`) instead of including this
   whole header -- afl_state_t is included practically everywhere, so
   keeping its own header's dependency footprint small matters more than
   it would for a leaf header. Only .c files that actually call
   reusing_pool_*() need this file. */
typedef struct reusing_pool {

  reusing_bucket_t **slots; /* NULL = empty slot */
  u32                cap;
  u32                len;   /* occupied slots, for grow's load-factor check */

} reusing_pool_t;

reusing_pool_t *reusing_pool_create(void);
void            reusing_pool_free(reusing_pool_t *pool);

/* Finds or creates the bucket for `pattern` (matched by real equality,
   not just hash -- see reusing_bucket_t's own comment on why). The
   returned bucket is pool-owned; callers don't free it directly. */
reusing_bucket_t *reusing_pool_get_bucket(reusing_pool_t           *pool,
                                          const reusing_pattern_t *pattern);

/* Inserts one candidate under `pattern`'s bucket (creating the bucket if
   this is its first record). Copies `value` (value_len bytes) rather than
   taking ownership of the caller's buffer -- callers keep managing
   whatever they passed in regardless of whether this call actually
   stores it (deduped-away inserts never touch the caller's buffer at
   all). A no-op (returns NULL, nothing inserted) if a record with the
   same value already exists in that bucket.

   Returns the inserted (or pre-existing, on a dedup no-op -- see below)
   record; pool-owned, do not free directly.

   pattern itself is also copied into a new bucket's own storage on first
   use, not referenced -- the caller's reusing_pattern_t can be freed via
   reusing_pattern_free() right after this call returns regardless of
   which path was taken. */
reusing_record_t *reusing_pool_insert(reusing_pool_t          *pool,
                                      const reusing_pattern_t *pattern,
                                      u32 cmpid, u32 context,
                                      reusing_value_source_t source,
                                      const u8 *value, u32 value_len);

#ifdef __cplusplus
}
#endif

#endif
