/*
   american fuzzy lop++ - dynamic taint tracking: heap allocation size map
   --------------------------------------------------------------------

   C port of Angora's runtime/src/heapmap.rs. Tracks the allocated size of
   each live heap block so dtaint_stdalloc.c's __dfsw_realloc can know how
   many bytes of shadow labels to carry over when realloc() moves the
   block to a new address (dfsan's own shadow memory is indexed by address,
   not by allocation, so a moved block's old labels would otherwise be
   silently lost).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _DTAINT_HEAPMAP_H
#define _DTAINT_HEAPMAP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Records that the live block at `base` is `bound` bytes long. Overwrites
   any previous entry for the same `base`. Mirrors heapmap_set. */
void dtaint_heapmap_set(void *base, size_t bound);

/* Forgets `base` (call on free()/on the old pointer after a realloc() that
   moved the block). A no-op if `base` isn't tracked. Mirrors
   heapmap_invalidate. */
void dtaint_heapmap_invalidate(void *base);

/* Returns the previously-recorded size for `base`, or 0 if untracked.
   Mirrors heapmap_get. */
size_t dtaint_heapmap_get(void *base);

#ifdef __cplusplus
}
#endif

#endif
