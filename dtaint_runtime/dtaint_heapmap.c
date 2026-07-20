/*
   american fuzzy lop++ - dynamic taint tracking: heap allocation size map
   --------------------------------------------------------------------

   See dtaint_heapmap.h. Open-addressing hash table keyed by pointer value,
   growth/probing scheme in the spirit of dtaint_logger.c's order_map (see
   that file for why a plain array-indexed table isn't an option -- here
   the key is a heap address rather than a sparse cmpid, so the same
   reasoning applies even more directly). Unlike order_map, entries here
   are actually removed (on free()/on a moved realloc()'s old pointer), so
   this uses real tombstones rather than order_map's insert-only scheme:
   linear probing needs a marker that keeps later entries in the same
   collision chain reachable after an earlier one is deleted. Guarded by a
   mutex since malloc/free/realloc may be called from multiple threads in
   the target program, mirroring heapmap.rs's Mutex<HashMap<..>>.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include "dtaint_heapmap.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uintptr_t heap_key_t;

/* NULL is never a live allocation, so slot value 0 is a safe "never used"
   sentinel. Slot value 1 is a safe tombstone sentinel too: every real
   allocator hands out pointers with at least 8-byte alignment, so no live
   heap block can ever have base address 1. */
#define HEAP_MAP_EMPTY    ((heap_key_t)0)
#define HEAP_MAP_TOMBSTONE ((heap_key_t)1)

static heap_key_t *heap_keys = NULL;
static size_t     *heap_vals = NULL;
static size_t       heap_cap = 0;
static size_t       heap_len = 0;   /* live entries */
static size_t       heap_tomb = 0;  /* tombstoned (deleted) slots */

static pthread_mutex_t heap_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t heap_hash(heap_key_t key, size_t cap) {

  /* Pointers are typically 16-byte aligned; shift away the low bits so
     nearby allocations don't all collide in the same bucket. */
  return (size_t)((key >> 4) % cap);

}

/* Insert into a fresh table during grow/rehash -- the table being built
   has no tombstones yet, so this only ever needs to skip EMPTY slots. */
static void heap_map_insert_fresh(heap_key_t *keys, size_t *vals, size_t cap,
                                  heap_key_t key, size_t val) {

  size_t idx = heap_hash(key, cap);

  while (keys[idx] != HEAP_MAP_EMPTY) idx = (idx + 1) % cap;

  keys[idx] = key;
  vals[idx] = val;

}

static void heap_map_grow(void) {

  size_t new_cap = heap_cap ? heap_cap * 2 : 1024;
  heap_key_t *new_keys = malloc(new_cap * sizeof(heap_key_t));
  size_t     *new_vals = malloc(new_cap * sizeof(size_t));
  if (!new_keys || !new_vals) abort();
  memset(new_keys, 0, new_cap * sizeof(heap_key_t));

  for (size_t i = 0; i < heap_cap; i++)
    if (heap_keys[i] != HEAP_MAP_EMPTY && heap_keys[i] != HEAP_MAP_TOMBSTONE)
      heap_map_insert_fresh(new_keys, new_vals, new_cap, heap_keys[i],
                            heap_vals[i]);

  free(heap_keys);
  free(heap_vals);
  heap_keys = new_keys;
  heap_vals = new_vals;
  heap_cap = new_cap;
  heap_tomb = 0;

}

/* Returns the index of `key`'s slot (creating it, zeroed, if absent),
   growing/rehashing first if the table is more than half full (counting
   live entries *and* tombstones, since both occupy a probe slot). Must be
   called with heap_lock held. */
static size_t heap_map_find_or_insert(heap_key_t key) {

  if (heap_cap == 0 || (heap_len + heap_tomb) * 2 >= heap_cap) heap_map_grow();

  size_t idx = heap_hash(key, heap_cap);
  size_t first_tomb = (size_t)-1;

  while (heap_keys[idx] != HEAP_MAP_EMPTY) {

    if (heap_keys[idx] == key) return idx;
    if (heap_keys[idx] == HEAP_MAP_TOMBSTONE && first_tomb == (size_t)-1)
      first_tomb = idx;
    idx = (idx + 1) % heap_cap;

  }

  /* Not found: reuse the first tombstone seen along the probe chain if
     there was one, otherwise take this fresh EMPTY slot. */
  size_t use_idx = (first_tomb != (size_t)-1) ? first_tomb : idx;
  if (heap_keys[use_idx] == HEAP_MAP_TOMBSTONE) heap_tomb--;
  heap_keys[use_idx] = key;
  heap_vals[use_idx] = 0;
  heap_len++;

  return use_idx;

}

void dtaint_heapmap_set(void *base, size_t bound) {

  if (!base) return;

  pthread_mutex_lock(&heap_lock);
  size_t idx = heap_map_find_or_insert((heap_key_t)base);
  heap_vals[idx] = bound;
  pthread_mutex_unlock(&heap_lock);

}

void dtaint_heapmap_invalidate(void *base) {

  if (!base || heap_cap == 0) return;

  pthread_mutex_lock(&heap_lock);

  heap_key_t key = (heap_key_t)base;
  size_t idx = heap_hash(key, heap_cap);

  while (heap_keys[idx] != HEAP_MAP_EMPTY) {

    if (heap_keys[idx] == key) {

      heap_keys[idx] = HEAP_MAP_TOMBSTONE;
      heap_vals[idx] = 0;
      heap_len--;
      heap_tomb++;
      break;

    }

    idx = (idx + 1) % heap_cap;

  }

  pthread_mutex_unlock(&heap_lock);

}

size_t dtaint_heapmap_get(void *base) {

  if (!base || heap_cap == 0) return 0;

  pthread_mutex_lock(&heap_lock);

  heap_key_t key = (heap_key_t)base;
  size_t idx = heap_hash(key, heap_cap);
  size_t ret = 0;

  while (heap_keys[idx] != HEAP_MAP_EMPTY) {

    if (heap_keys[idx] == key) {

      ret = heap_vals[idx];
      break;

    }

    idx = (idx + 1) % heap_cap;

  }

  pthread_mutex_unlock(&heap_lock);

  return ret;

}
