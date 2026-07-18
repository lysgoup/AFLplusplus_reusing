/*
   american fuzzy lop++ - dynamic taint tracking: ABI-list library wrappers
   ---------------------------------------------------------------------------

   Ported from Angora's llvm_mode/external_lib/io_func.c (source functions:
   read/fread/fgets/pread) and llvm_mode/dfsan_rt/dfsan/dfsan_custom.cc-style
   propagate/compare wrapping (memcpy/memmove/strcpy/strncpy/strcat as
   propagators; strcmp/strncmp/memcmp/strcasecmp/strncasecmp as the
   "cmpfn" category from llvm_mode/rules/exploitation_list.txt).

   Mechanism difference from Angora, both deliberate and documented in
   instrumentation/README.dtaint.md:

     - Angora's DFSan build makes the *linker* redirect e.g. every `read`
       symbol reference to `__dfsw_read` (DFSan's custom-function ABI,
       which also passes hidden label arguments). This pass instead has the
       LLVM pass redirect matching CallInsts directly to these
       identically-signatured wrapper functions (see the pass file's
       instrumentCallSite) -- no hidden ABI, no linker tricks, just plain
       call-target substitution.
     - No "is this fd the fuzzing input file" allowlist (Angora's
       add_fuzzing_fd/is_fuzzing_fd, populated by also intercepting
       open/fopen and checking the path). Every call through these wrappers
       taints its output unconditionally. This is simpler and, for AFL++'s
       usual single-input-stream harnesses, not meaningfully less accurate;
       it would over-taint incidental file reads (config files, etc.) in a
       more complex target -- a known, documented limitation, not an
       oversight.
     - Angora's assign_taint_labels_exf also speculatively taints up to
       `count - ret` extra bytes past what was actually read/returned (a
       defensive over-taint for partially-filled caller buffers). This port
       only taints the `ret` bytes actually produced -- less taint, not
       more; documented as a real behavioral difference, not a bug.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dtaint.h"
#include "dtaint_internal.h"

/* Fallback source-offset cursor for non-seekable streams (pipes, stdin
   redirected from a pipe, sockets) where lseek()/ftell() fail. A single
   process-wide counter is enough for AFL++'s usual model of one linear
   input stream per execution; see the file header for why this, unlike
   Angora's per-fd bookkeeping, is an acceptable simplification here. */
static uint64_t fallback_cursor = 0;

static uint32_t clamp_offset(int64_t off) {

  return (off < 0) ? 0 : (uint32_t)off;

}

/* ---------------------------------------------------------------------- */
/* Sources                                                                 */
/* ---------------------------------------------------------------------- */

ssize_t __dtaint_read(int fd, void *buf, size_t count) {

  int64_t pos = lseek(fd, 0, SEEK_CUR);
  uint32_t offset = (pos >= 0) ? clamp_offset(pos) : clamp_offset((int64_t)fallback_cursor);

  ssize_t ret = read(fd, buf, count);

  if (ret > 0) {

    dtaint_source_at_offset(buf, (uint64_t)ret, offset);
    if (pos < 0) fallback_cursor += (uint64_t)ret;

  }

  return ret;

}

size_t __dtaint_fread(void *buf, size_t size, size_t count, FILE *stream) {

  long pos = ftell(stream);
  uint32_t offset = (pos >= 0) ? clamp_offset(pos) : clamp_offset((int64_t)fallback_cursor);

  size_t ret = fread(buf, size, count, stream);
  uint64_t retbytes = (uint64_t)ret * (uint64_t)size;

  if (retbytes > 0) {

    dtaint_source_at_offset(buf, retbytes, offset);
    if (pos < 0) fallback_cursor += retbytes;

  }

  return ret;

}

char *__dtaint_fgets(char *str, int count, FILE *stream) {

  long pos = ftell(stream);
  uint32_t offset = (pos >= 0) ? clamp_offset(pos) : clamp_offset((int64_t)fallback_cursor);

  char *ret = fgets(str, count, stream);

  if (ret) {

    uint64_t len = (uint64_t)strlen(ret);
    dtaint_source_at_offset(str, len, offset);
    if (pos < 0) fallback_cursor += len;

  }

  return ret;

}

ssize_t __dtaint_pread(int fd, void *buf, size_t count, off_t offset) {

  ssize_t ret = pread(fd, buf, count, offset);

  if (ret > 0) dtaint_source_at_offset(buf, (uint64_t)ret, clamp_offset((int64_t)offset));

  return ret;

}

/* ---------------------------------------------------------------------- */
/* Propagators                                                            */
/* ---------------------------------------------------------------------- */

void *__dtaint_memcpy(void *dst, const void *src, size_t n) {

  void *ret = memcpy(dst, src, n);
  __dtaint_propagate_mem(dst, src, (uint64_t)n);
  return ret;

}

void *__dtaint_memmove(void *dst, const void *src, size_t n) {

  void *ret = memmove(dst, src, n);
  __dtaint_propagate_mem(dst, src, (uint64_t)n);
  return ret;

}

char *__dtaint_strcpy(char *dst, const char *src) {

  size_t len = strlen(src);
  char  *ret = strcpy(dst, src); /* NOLINT */
  __dtaint_propagate_mem(dst, src, (uint64_t)len);
  return ret;

}

char *__dtaint_strncpy(char *dst, const char *src, size_t n) {

  size_t srclen = strlen(src);
  size_t copy_len = (srclen < n) ? srclen : n;
  char  *ret = strncpy(dst, src, n);
  __dtaint_propagate_mem(dst, src, (uint64_t)copy_len);
  return ret;

}

char *__dtaint_strcat(char *dst, const char *src) {

  size_t dst_len = strlen(dst);
  size_t src_len = strlen(src);
  char  *ret = strcat(dst, src); /* NOLINT */
  __dtaint_propagate_mem(dst + dst_len, src, (uint64_t)src_len);
  return ret;

}

/* ---------------------------------------------------------------------- */
/* Compare functions ("cmpfn") -- logs a COND_FN_OP record as a side       */
/* effect, mirrors llvm_mode/rules/exploitation_list.txt's cmpfn category. */
/* `cmpid` is a fixed per-call-site id assigned by the pass at compile     */
/* time (one per instrumented call site, sharing the same counter space   */
/* as icmp/switch sites); context is always 0 -- see include/dtaint.h.     */
/* ---------------------------------------------------------------------- */

int __dtaint_strcmp(uint32_t cmpid, const char *a, const char *b) {

  int ret = strcmp(a, b);
  __dtaint_trace_fn(cmpid, 0, 0, a, b);
  return ret;

}

int __dtaint_strncmp(uint32_t cmpid, const char *a, const char *b, size_t n) {

  int ret = strncmp(a, b, n);
  __dtaint_trace_fn(cmpid, 0, (uint32_t)n, a, b);
  return ret;

}

int __dtaint_memcmp(uint32_t cmpid, const void *a, const void *b, size_t n) {

  int ret = memcmp(a, b, n);
  __dtaint_trace_fn(cmpid, 0, (uint32_t)n, a, b);
  return ret;

}

int __dtaint_strcasecmp(uint32_t cmpid, const char *a, const char *b) {

  int ret = strcasecmp(a, b);
  __dtaint_trace_fn(cmpid, 0, 0, a, b);
  return ret;

}

int __dtaint_strncasecmp(uint32_t cmpid, const char *a, const char *b, size_t n) {

  int ret = strncasecmp(a, b, n);
  __dtaint_trace_fn(cmpid, 0, (uint32_t)n, a, b);
  return ret;

}
