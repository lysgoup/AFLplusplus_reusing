/*
   american fuzzy lop++ - reusing pool: seen (cmpid, condition) set
   -----------------------------------------------------------------

   Implementation. See include/reusing_seen.h for the contract. Same
   open-addressing shape as afl-fuzz-reusing-pool.c's slots table and
   dtaint_runtime/dtaint_logger.c's order_map -- grow-at-half-full, linear
   probing -- just a set of hashes instead of a bucket/counter map.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdlib.h>
#include <string.h>

#include "reusing_seen.h"

#define REUSING_SEEN_EMPTY 0xFFFFFFFFU
#define REUSING_SEEN_INITIAL_CAP 1024U

struct reusing_seen {

  u32 *keys; /* REUSING_SEEN_EMPTY = unused slot */
  u32  cap;
  u32  len;

};

/* Knuth multiplicative combine -- same rigor already accepted for cmpid/
   pattern hashing elsewhere in this codebase (see order_map_key). */
static u32 seen_key(u32 cmpid, u32 condition) {

  return cmpid ^ (condition * 2654435761U);

}

reusing_seen_t *reusing_seen_create(void) {

  reusing_seen_t *seen = malloc(sizeof(reusing_seen_t));
  if (!seen) { abort(); }

  seen->cap = REUSING_SEEN_INITIAL_CAP;
  seen->len = 0;
  seen->keys = malloc((size_t)seen->cap * sizeof(u32));
  if (!seen->keys) { abort(); }
  memset(seen->keys, 0xFF, (size_t)seen->cap * sizeof(u32));

  return seen;

}

void reusing_seen_free(reusing_seen_t *seen) {

  if (!seen) { return; }
  free(seen->keys);
  free(seen);

}

static void seen_insert(u32 *keys, u32 cap, u32 key) {

  u32 idx = key % cap;
  while (keys[idx] != REUSING_SEEN_EMPTY) idx = (idx + 1) % cap;
  keys[idx] = key;

}

static void seen_grow(reusing_seen_t *seen) {

  u32  new_cap = seen->cap * 2;
  u32 *new_keys = malloc((size_t)new_cap * sizeof(u32));
  if (!new_keys) { abort(); }
  memset(new_keys, 0xFF, (size_t)new_cap * sizeof(u32));

  for (u32 i = 0; i < seen->cap; ++i) {

    if (seen->keys[i] != REUSING_SEEN_EMPTY) { seen_insert(new_keys, new_cap, seen->keys[i]); }

  }

  free(seen->keys);
  seen->keys = new_keys;
  seen->cap = new_cap;

}

u8 reusing_seen_check_and_mark(reusing_seen_t *seen, u32 cmpid, u32 condition) {

  u32 key = seen_key(cmpid, condition);
  u32 idx = key % seen->cap;
  u32 probed = 0;

  while (seen->keys[idx] != REUSING_SEEN_EMPTY) {

    if (seen->keys[idx] == key) { return 0; } /* already seen */

    idx = (idx + 1) % seen->cap;
    if (++probed >= seen->cap) { seen_grow(seen); idx = key % seen->cap; probed = 0; }

  }

  /* Not found -- grow first if more than half full, then insert. */
  if (seen->len * 2 >= seen->cap) {

    seen_grow(seen);
    idx = key % seen->cap;
    while (seen->keys[idx] != REUSING_SEEN_EMPTY) { idx = (idx + 1) % seen->cap; }

  }

  seen->keys[idx] = key;
  seen->len++;

  return 1; /* novel */

}
