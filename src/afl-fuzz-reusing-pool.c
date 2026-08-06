/*
   american fuzzy lop++ - reusing pool
   -----------------------------------------------------------------

   Implementation. See include/reusing_pool.h for the contract.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reusing_pool.h"

#define REUSING_POOL_EMPTY_SLOT 0xFFFFFFFFU /* sentinel hash: no such slot */
#define REUSING_POOL_INITIAL_CAP 256U

/* FNV-1a -- same "good enough, not collision-free" rigor already accepted
   elsewhere in this codebase's own hash tables (dtaint_runtime/
   dtaint_logger.c's order_map_key). Exact-match verification against the
   stored pattern/value (see reusing_pool_get_bucket and the dedup check
   in reusing_pool_insert) is what actually guards correctness here, not
   the hash quality. */
static u32 fnv1a(const void *data, size_t len) {

  const u8 *p = data;
  u32       h = 2166136261U;

  for (size_t i = 0; i < len; ++i) {

    h ^= p[i];
    h *= 16777619U;

  }

  return h;

}

static u32 hash_pattern(const reusing_pattern_t *pattern) {

  if (pattern->n_lens == 0) { return 0; }
  return fnv1a(pattern->lens, (size_t)pattern->n_lens * sizeof(u32));

}

static int pattern_equal(const reusing_pattern_t *a, const reusing_pattern_t *b) {

  if (a->n_lens != b->n_lens) { return 0; }
  if (a->n_lens == 0) { return 1; }
  return memcmp(a->lens, b->lens, (size_t)a->n_lens * sizeof(u32)) == 0;

}

static reusing_pattern_t pattern_copy(const reusing_pattern_t *src) {

  reusing_pattern_t out = {.lens = NULL, .n_lens = src->n_lens};

  if (src->n_lens) {

    out.lens = malloc((size_t)src->n_lens * sizeof(u32));
    if (!out.lens) { abort(); }
    memcpy(out.lens, src->lens, (size_t)src->n_lens * sizeof(u32));

  }

  return out;

}

reusing_pool_t *reusing_pool_create(void) {

  reusing_pool_t *pool = malloc(sizeof(reusing_pool_t));
  if (!pool) { abort(); }

  pool->cap = REUSING_POOL_INITIAL_CAP;
  pool->len = 0;
  pool->slots = malloc((size_t)pool->cap * sizeof(reusing_bucket_t *));
  if (!pool->slots) { abort(); }
  memset(pool->slots, 0, (size_t)pool->cap * sizeof(reusing_bucket_t *));

  return pool;

}

static void bucket_free(reusing_bucket_t *bucket) {

  for (u32 i = 0; i < bucket->n_records; ++i) {

    free(bucket->records[i].value);

  }

  free(bucket->records);
  reusing_pattern_free(&bucket->pattern);
  free(bucket);

}

void reusing_pool_free(reusing_pool_t *pool) {

  if (!pool) { return; }

  for (u32 i = 0; i < pool->cap; ++i) {

    if (pool->slots[i]) { bucket_free(pool->slots[i]); }

  }

  free(pool->slots);
  free(pool);

}

/* Open-addressing insert into a slots array -- used both by the real
   table (via reusing_pool_get_bucket) and by grow's rehash pass, exactly
   mirroring dtaint_logger.c's order_map_insert/order_map_grow split for
   the same reason: grow needs to redistribute existing entries through
   the *same* probe logic a fresh insert uses, so the two can't drift
   apart into two different collision-resolution behaviors. */
static void slots_insert(reusing_bucket_t **slots, u32 cap,
                         reusing_bucket_t *bucket) {

  u32 h = hash_pattern(&bucket->pattern);
  u32 idx = h % cap;

  while (slots[idx]) { idx = (idx + 1) % cap; }

  slots[idx] = bucket;

}

static void pool_grow(reusing_pool_t *pool) {

  u32                new_cap = pool->cap * 2;
  reusing_bucket_t **new_slots = malloc((size_t)new_cap * sizeof(reusing_bucket_t *));
  if (!new_slots) { abort(); }
  memset(new_slots, 0, (size_t)new_cap * sizeof(reusing_bucket_t *));

  for (u32 i = 0; i < pool->cap; ++i) {

    if (pool->slots[i]) { slots_insert(new_slots, new_cap, pool->slots[i]); }

  }

  free(pool->slots);
  pool->slots = new_slots;
  pool->cap = new_cap;

}

reusing_bucket_t *reusing_pool_get_bucket(reusing_pool_t           *pool,
                                          const reusing_pattern_t *pattern) {

  u32 h = hash_pattern(pattern);
  u32 idx = h % pool->cap;
  u32 probed = 0;

  while (pool->slots[idx]) {

    if (pattern_equal(&pool->slots[idx]->pattern, pattern)) {

      return pool->slots[idx];

    }

    idx = (idx + 1) % pool->cap;
    /* Every slot occupied and none matched -- only reachable if grow's
       load-factor check below is broken (table is full). Guard instead
       of looping forever. */
    if (++probed >= pool->cap) { pool_grow(pool); idx = h % pool->cap; probed = 0; }

  }

  /* Not found -- create. Grow first if we're more than half full, same
     threshold dtaint_logger.c's order_map uses. */
  if (pool->len * 2 >= pool->cap) {

    pool_grow(pool);
    idx = hash_pattern(pattern) % pool->cap;
    while (pool->slots[idx]) { idx = (idx + 1) % pool->cap; }

  }

  reusing_bucket_t *bucket = malloc(sizeof(reusing_bucket_t));
  if (!bucket) { abort(); }
  bucket->pattern = pattern_copy(pattern);
  bucket->records = NULL;
  bucket->n_records = 0;
  bucket->cap_records = 0;

  pool->slots[idx] = bucket;
  pool->len++;

  return bucket;

}

reusing_record_t *reusing_pool_insert(reusing_pool_t          *pool,
                                      const reusing_pattern_t *pattern,
                                      u32 cmpid, u32 context,
                                      reusing_value_source_t source,
                                      const u8 *value, u32 value_len) {

  reusing_bucket_t *bucket = reusing_pool_get_bucket(pool, pattern);
  u32 vhash = value_len ? fnv1a(value, value_len) : 0;

  /* Dedup: value_hash first (cheap integer compare across potentially
     many existing records), full memcmp only on a hash match -- same
     "hash narrows it down, exact comparison confirms" split as
     reusing_pool_get_bucket's own pattern check, and for the same reason
     (a hash match alone isn't proof of equality). */
  for (u32 i = 0; i < bucket->n_records; ++i) {

    reusing_record_t *r = &bucket->records[i];
    if (r->value_hash == vhash && r->value_len == value_len &&
        (value_len == 0 || memcmp(r->value, value, value_len) == 0)) {

      return NULL; /* already have this exact value -- no-op */

    }

  }

  if (bucket->n_records >= bucket->cap_records) {

    u32 new_cap = bucket->cap_records ? bucket->cap_records * 2 : 16;
    reusing_record_t *grown =
        realloc(bucket->records, (size_t)new_cap * sizeof(reusing_record_t));
    if (!grown) { abort(); }
    bucket->records = grown;
    bucket->cap_records = new_cap;

  }

  reusing_record_t *rec = &bucket->records[bucket->n_records++];
  rec->cmpid = cmpid;
  rec->context = context;
  rec->source = source;
  rec->value_len = value_len;
  rec->value_hash = vhash;
  rec->value = NULL;
  if (value_len) {

    rec->value = malloc(value_len);
    if (!rec->value) { abort(); }
    memcpy(rec->value, value, value_len);

  }

  return rec;

}

static const char *source_name(reusing_value_source_t source) {

  switch (source) {

    case REUSING_SRC_TAINTED: return "TAINTED";
    case REUSING_SRC_MAGIC: return "MAGIC";
    case REUSING_SRC_CMPFN: return "CMPFN";

  }

  return "?";

}

void reusing_pool_dump(const reusing_pool_t *pool, const char *path) {

  if (!pool) { return; }

  FILE *fp = fopen(path, "w");
  if (!fp) { return; }

  fprintf(fp, "# reusing pool dump: %u distinct pattern(s)\n", pool->len);

  for (u32 i = 0; i < pool->cap; i++) {

    reusing_bucket_t *bucket = pool->slots[i];
    if (!bucket) { continue; }

    fprintf(fp, "pattern [");
    for (u32 j = 0; j < bucket->pattern.n_lens; j++) {

      fprintf(fp, "%s%u", j ? "," : "", bucket->pattern.lens[j]);

    }

    fprintf(fp, "] (%u record(s)):\n", bucket->n_records);

    for (u32 j = 0; j < bucket->n_records; j++) {

      reusing_record_t *r = &bucket->records[j];
      fprintf(fp, "  cmpid=%u context=%u source=%s value=", r->cmpid, r->context,
             source_name(r->source));

      for (u32 k = 0; k < r->value_len; k++) fprintf(fp, "%02x", r->value[k]);

      fprintf(fp, " (len=%u)\n", r->value_len);

    }

  }

  fclose(fp);

}
