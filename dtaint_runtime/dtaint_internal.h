/*
   american fuzzy lop++ - dynamic taint tracking: internal runtime glue
   -----------------------------------------------------------------------

   Declarations shared only between this directory's .c files (dtaint-rt.c's
   shadow-table primitives, used by dtaint_abi.c's ABI-list wrappers) -- not
   part of the target-facing API in include/dtaint.h.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _DTAINT_INTERNAL_H
#define _DTAINT_INTERNAL_H

#include "dtaint.h"

/* Seeds `len` fresh per-byte labels at file offset [offset, offset+len),
   tagging the shadow table at `ptr`. Like dtaint_source_buf, but lets ABI-
   list source wrappers (dtaint_abi.c) record the real file position they
   recovered via ftell()/lseek(), instead of always starting from 0. */
void dtaint_source_at_offset(const void *ptr, u64 len, u32 offset);

/* Copies shadow labels byte-for-byte from `src` to `dst` (overlap-safe, like
   memmove). Used by the memcpy/memmove/strcpy/strncpy/strcat wrappers. */
void __dtaint_propagate_mem(const void *dst, const void *src, u64 len);

#endif
