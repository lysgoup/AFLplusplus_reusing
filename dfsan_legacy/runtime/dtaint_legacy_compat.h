/*
   american fuzzy lop++ - dynamic taint tracking (real DFSan): io_func.c glue
   -----------------------------------------------------------------------------

   Stands in for Angora's runtime/include/ffds.h (fd-tracking allowlist) and
   len_label.h (length-label FFI) so io_func.c (vendored verbatim from
   Angora_original/llvm_mode/external_lib/io_func.c) can be used without
   the Rust runtime crate.

   Deliberate simplification, matching this port's earlier (custom-pass)
   phase: no "is this fd the fuzzing input file" allowlist -- every read
   through io_func.c's wrapped functions taints its output unconditionally.
   See instrumentation/README.dtaint.md's "ABI list mechanism" section for
   why (simpler, and not meaningfully less accurate for AFL++'s usual
   single-input-stream harnesses).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef DTAINT_LEGACY_COMPAT_H
#define DTAINT_LEGACY_COMPAT_H

#include <stdint.h>
#include <stdio.h>

#include "dtaint_len_label.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ffds.h stand-in: every fd/FILE* is always "the fuzzing input" -- see file
   header. */
static inline uint32_t __angora_io_find_fd(int fd) { (void)fd; return 1; }
static inline uint32_t __angora_io_find_pfile(FILE *f) { (void)f; return 1; }
static inline void __angora_io_add_fd(int fd) { (void)fd; }
static inline void __angora_io_add_pfile(FILE *f) { (void)f; }
static inline void __angora_io_remove_fd(int fd) { (void)fd; }
static inline void __angora_io_remove_pfile(FILE *f) { (void)f; }

/* len_label.h stand-in: forwards to our C port (dtaint_runtime/
   dtaint_len_label.c, already built/tested) instead of Angora's Rust FFI. */
static inline uint32_t __angora_get_len_label(uint32_t offset, uint32_t size) {

  return dtaint_len_label_new(offset, size);

}

#ifdef __cplusplus
}
#endif

#endif
