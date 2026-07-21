/*
   american fuzzy lop++ - dynamic taint tracking (real DFSan): io_func.c glue
   -----------------------------------------------------------------------------

   Stands in for Angora's runtime/include/ffds.h (fd-tracking allowlist) and
   len_label.h (length-label FFI) so io_func.c (vendored verbatim from
   Angora_original/llvm_mode/external_lib/io_func.c) can be used without
   the Rust runtime crate.

   Earlier phase used a deliberate simplification here: no "is this fd the
   fuzzing input file" allowlist at all, every read through io_func.c's
   wrapped functions tainted its output unconditionally. That turned out to
   be a real bug, not just an accuracy tradeoff: found when SQLite's bundled
   `lemon` parser-generator (itself taint-compiled, and *run as part of the
   build* to generate parse.c from parse.y) aborted with "more than 4194303
   label nodes" -- lemon isn't a fuzzing target at all, it's a one-shot
   build-time code generator, but with every file read unconditionally
   taint-tracked, parsing its own (legitimately large) grammar file blew
   through dtaint_tagset's fixed label-node capacity. Angora's own real
   runtime never hits this because it gates tainting on the opened
   filename containing the literal substring "cur_input"
   (FUZZING_INPUT_FILE, defs.h) -- io_func.c already has that exact check
   wired into __dfsw_open/__dfsw_fopen (IS_FUZZING_FILE, vendored verbatim
   from Angora), it was only the fd/FILE*-membership query functions below
   that ignored it. Restored to real (if simple) tracking sets so the
   gating Angora relies on actually takes effect.

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

/* ffds.h stand-in: real (if simple) membership tracking for "is this fd/
   FILE* the fuzzing input file" -- see file header for why the previous
   always-true stub was a real bug, not just a simplification. fds are
   small non-negative ints bounded by the process' fd-table size in
   practice, so a flat array indexed directly by fd is both correct and
   O(1); FILE* handles get a small linear-scan table since a program
   rarely has more than a handful of "fuzzing" streams open at once. */
#define DTAINT_MAX_FUZZING_FD 4096
#define DTAINT_MAX_FUZZING_PFILE 64

static uint8_t __dtaint_fuzzing_fd_set[DTAINT_MAX_FUZZING_FD];
static FILE *__dtaint_fuzzing_pfile_set[DTAINT_MAX_FUZZING_PFILE];

static inline uint32_t __angora_io_find_fd(int fd) {
  if (fd < 0 || fd >= DTAINT_MAX_FUZZING_FD) return 0;
  return __dtaint_fuzzing_fd_set[fd];
}
static inline uint32_t __angora_io_find_pfile(FILE *f) {
  for (int i = 0; i < DTAINT_MAX_FUZZING_PFILE; i++)
    if (__dtaint_fuzzing_pfile_set[i] == f) return 1;
  return 0;
}
static inline void __angora_io_add_fd(int fd) {
  if (fd >= 0 && fd < DTAINT_MAX_FUZZING_FD) __dtaint_fuzzing_fd_set[fd] = 1;
}
static inline void __angora_io_add_pfile(FILE *f) {
  for (int i = 0; i < DTAINT_MAX_FUZZING_PFILE; i++) {
    if (__dtaint_fuzzing_pfile_set[i] == NULL) {
      __dtaint_fuzzing_pfile_set[i] = f;
      return;
    }
  }
}
static inline void __angora_io_remove_fd(int fd) {
  if (fd >= 0 && fd < DTAINT_MAX_FUZZING_FD) __dtaint_fuzzing_fd_set[fd] = 0;
}
static inline void __angora_io_remove_pfile(FILE *f) {
  for (int i = 0; i < DTAINT_MAX_FUZZING_PFILE; i++)
    if (__dtaint_fuzzing_pfile_set[i] == f) { __dtaint_fuzzing_pfile_set[i] = NULL; return; }
}

/* len_label.h stand-in: forwards to our C port (dtaint_runtime/
   dtaint_len_label.c, already built/tested) instead of Angora's Rust FFI. */
static inline uint32_t __angora_get_len_label(uint32_t offset, uint32_t size) {

  return dtaint_len_label_new(offset, size);

}

#ifdef __cplusplus
}
#endif

#endif
