/*
   american fuzzy lop++ - dynamic taint tracking header
   -----------------------------------------------------

   Minimal DFSan-style dynamic taint tracking, ported from the Angora fuzzer
   (https://github.com/AngoraFuzzer/Angora, see also the reusing-fuzzer fork
   this was scoped against). This is a validation slice only: it proves that
   input-byte offsets can be tracked through load/store/arithmetic and
   recorded at comparison sites, in AFL++'s build/runtime model. It does not
   yet include ABI-list library-call modeling, real shadow memory, heap
   tracking, length-derived comparisons, or a fuzzer-side consumer -- see
   the plan this was built from for the full scope notes.

   Naming note: AFL++ already has an unrelated `struct tainted` /
   `queue_entry.taint` (CmpLog's redqueen colorization result -- a coarser
   "these byte regions seem to matter" heuristic, not real dataflow
   provenance). Everything here uses a `dtaint_`/`DTAINT_` prefix instead of
   bare `taint_`/`TAINT_` to avoid confusion with that existing, different
   concept.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_DTAINT_H
#define _AFL_DTAINT_H

#include "config.h"
#include "types.h"

/* Env var pointing at the output track-file path. Set by the fuzzer (or,
   for standalone testing, by hand) before running a dtaint-instrumented
   binary. */
#define DTAINT_TRACK_ENV_VAR "AFL_DTAINT_TRACK_FILE"

/* Label 0 is reserved to mean "untainted". */
#define DTAINT_NO_LABEL 0

/* One record per __dtaint_trace_cmp call where at least one operand carried
   a non-zero label. Followed inline in the file by `n_offsets` raw u32
   byte offsets (lb1's offsets first, then lb2's) -- no TagSeg-style range
   compression in this slice, just a flat list of individual byte indices. */
struct dtaint_record {

  u32 cmpid;
  u32 op;    /* LLVM CmpInst predicate, stored raw */
  u32 size;  /* operand width in bits */
  u32 cond;  /* actual runtime outcome of the comparison: 0 or 1 */
  u64 arg1;
  u64 arg2;  /* concrete operand values, zero-extended to u64 */
  u32 lb1;
  u32 lb2;       /* labels, DTAINT_NO_LABEL (0) if that operand is untainted */
  u32 n_offsets; /* count of u32 byte offsets following this record in the file */

};

/* Written once, at the very start of the track file. */
struct dtaint_file_header {

  u32 magic; /* 'DTNT' i.e. 0x444e5454 */
  u32 version;
  u32 n_records;

};

#define DTAINT_FILE_MAGIC 0x444e5454U
#define DTAINT_FILE_VERSION 1U

/* Runtime API the LLVM pass's inserted calls target (defined in
   dtaint_runtime/dtaint-rt.c, declared here so both the instrumented target
   and any standalone test/driver code can share one prototype set). These
   four use a double-underscore prefix, matching the convention DFSan/CmpLog/
   Angora all use for compiler-inserted runtime hooks (reserved-identifier
   namespace, claimed deliberately here since this file plays that role). */

/* Returns the (possibly combined) label currently covering the `size` bytes
   at `ptr`. */
u32 __dtaint_load(void *ptr, u64 size);

/* Tags the `size` bytes at `ptr` with `label` going forward. */
void __dtaint_store(void *ptr, u64 size, u32 label);

/* Combines two labels into one representing the union of what they each
   cover; DTAINT_NO_LABEL is the identity element. */
u32 __dtaint_combine(u32 l1, u32 l2);

/* The actual record-writing hook: no-ops if both l1 and l2 are
   DTAINT_NO_LABEL. */
void __dtaint_trace_cmp(u32 cmpid, u32 op, u32 size, u64 arg1, u64 arg2, u32 cond,
                         u32 l1, u32 l2);

/* Taint source: seed one fresh label per byte starting at `ptr`. Called
   explicitly by a test harness right after it loads input into memory --
   there is no ABI-list-driven automatic interception of read()/fread() in
   this slice, so this is a normal (non-double-underscore) library call the
   harness makes itself, not something the pass inserts. */
void dtaint_source_buf(const void *ptr, u64 len);

/* Execs the dtaint-instrumented child -- mirrors cmplog_exec_child
   (include/cmplog.h). */
struct afl_forkserver;
void dtaint_exec_child(struct afl_forkserver *fsrv, char **argv);

#endif
