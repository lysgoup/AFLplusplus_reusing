/*
   american fuzzy lop++ - dynamic taint tracking header
   -----------------------------------------------------

   DFSan-style dynamic taint tracking, ported from the Angora fuzzer
   (https://github.com/AngoraFuzzer/Angora). Goal of this phase: capture the
   *same* taint information Angora's own `.taint` runtime captures (per-byte
   provenance via a range-compressed label tree, comparison/switch/library-
   call-comparison sites, length-derived comparisons) so that -- while
   nothing in AFL++ consumes it yet -- the data is there to build a real
   consumer against later. See instrumentation/README.dtaint.md for exactly
   what's implemented vs. still deferred (real shadow memory, function-call
   context-sensitivity, C++ std::string comparisons, a fuzzer-side reuse/
   mutation consumer).

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

#ifdef __cplusplus
extern "C" {
#endif

/* Env var pointing at the output track-file path. Set by the fuzzer (or,
   for standalone testing, by hand) before running a dtaint-instrumented
   binary.

   Fuzzer-side note (src/afl-fuzz.c / src/afl-fuzz-dtaint.c): this can only
   be set *once*, before the dtaint forkserver's one-time execve() -- the
   forkserver protocol forks already-running children for every later
   execution and never re-execs or re-reads the environment, so a per-call
   setenv() from afl-fuzz's own (separate) process can never reach them.
   afl-fuzz therefore points this at one fixed per-session scratch path
   (<out_dir>/dtaint_logs/DTAINT_SCRATCH_NAME) and renames that file to each
   input's real destination itself after every run -- see
   log_dtaint_for_new_input(). */
#define DTAINT_TRACK_ENV_VAR "AFL_DTAINT_TRACK_FILE"
#define DTAINT_SCRATCH_NAME ".scratch.dtaint"

/* Label 0 is reserved to mean "untainted". */
#define DTAINT_NO_LABEL 0

/* ---------------------------------------------------------------------- */
/* Comparison-site "op" encoding -- mirrors common/src/defs.rs exactly.    */
/* The icmp predicate values themselves are *not* redefined here: LLVM's   */
/* own CmpInst::Predicate enum already numbers ICMP_EQ..ICMP_SLE as        */
/* 32..41, identical to Angora's COND_ICMP_*_OP constants, so the pass     */
/* just forwards CmpInst::getPredicate() as-is. Only the non-predicate     */
/* op values need restating here.                                         */
/* ---------------------------------------------------------------------- */

#define DTAINT_COND_SW_OP  0x00FFU

#define DTAINT_COND_SIGN_MASK 0x100U
#define DTAINT_COND_BOOL_MASK 0x200U

#define DTAINT_COND_MAX_EXPLORE_OP (0x4000U - 1U)
#define DTAINT_COND_MAX_EXPLOIT_OP (0x5000U - 1U)

#define DTAINT_COND_AFL_OP 0x8001U
#define DTAINT_COND_FN_OP  0x8002U
#define DTAINT_COND_LEN_OP 0x8003U

#define DTAINT_COND_FALSE_ST 0U
#define DTAINT_COND_TRUE_ST  1U
#define DTAINT_COND_DONE_ST  2U

/* Repeated-hit-of-the-same-site cutoff per execution (loops) -- mirrors
   common/src/config.rs's MAX_COND_ORDER, but context is hardcoded to 0 in
   this port (see dtaint_cond_record's comment below), so unlike Angora --
   where the order_map key is (cmpid, context) and a call-site-varying
   context naturally buckets a hot site into several independent 16-deep
   counters -- every hit of a given cmpid here shares ONE counter no matter
   how many different call contexts it's actually reached from.

   Tried raising this to 1024 as a blunt workaround (no context bucketing
   added) and it backfired: on inputs where Angora's context genuinely does
   vary across a hot site (e.g. jq's \\uXXXX-unescape loop touching several
   call contexts), the higher cap did let this port catch up to Angora's
   effectively-larger multi-context budget. But most hot loops run under a
   *single* context throughout (tight scanning loops, havoc-mutated
   repeated-byte inputs), where Angora's own order<=16 gate caps it at 16
   too -- there raising the cap made this port sweep hundreds to thousands
   of extra bytes Angora never tainted, e.g. infotocap inputs going from
   ~20 tainted bytes to ~1950 (nearly the whole file). Measured net effect
   across the 5-target comparison harness (dtaint_convert/src/bin/
   compare_taint.rs in Reusing_mut's compare_with_aflpp branch): mean
   Jaccard agreement with Angora's taint sets dropped from 0.92 to 0.49.
   Since then: context is no longer hardcoded to 0 -- the LLVM pass
   (instrumentation/afl-llvm-dtaint-pass.so.cc) now computes a real per-call
   context mirroring Angora's own AngoraPass.cc (XOR of per-call-site ids
   across the call stack, pushed at function entry / popped at return), and
   dtaint_runtime/dtaint_logger.c's order_map keys on (cmpid, context)
   instead of cmpid alone. 16 is kept as the per-(cmpid,context) cap rather
   than raised again -- the whole point of adding context was to get the
   *bucketing* right so the existing cap behaves the way Angora's does, not
   to justify a different cap value. Still pending: this is a lower bound on
   accuracy (matches Angora's own approximation, doesn't exceed it) --
   deliberately taking the cap higher than 16 *within* a context bucket,
   now that buckets are meaningful, is the next step for going past parity
   with Angora rather than just reaching it. */
#define DTAINT_MAX_COND_ORDER 16U

/* One entry of the "cond_list" -- mirrors angora_common::cond_stmt_base::
   CondStmtBase field-for-field. context is a real per-call-stack value now
   (see DTAINT_MAX_COND_ORDER's comment above and the LLVM pass), computed
   the same way Angora's own AngoraPass.cc does it -- not the location-hash
   `cmpid` is (see below), a genuinely different value that changes with
   which call path reached this site, not just where the site is. lb1/lb2
   are TagSet label ids, resolved to byte-offset ranges separately in the
   "tags" table below (not inlined per record), exactly mirroring how
   Angora's own LogData separates `cond_list: Vec<CondStmtBase>` from
   `tags: HashMap<u32, Vec<TagSeg>>`. */
struct dtaint_cond_record {

  u32 cmpid;
  u32 context;
  u32 order;
  u32 belong;

  u32 condition;
  u32 level;
  u32 op;
  u32 size;

  u32 lb1;
  u32 lb2;

  u64 arg1;
  u64 arg2;

};

/* Wire form of dtaint_tagset.h's dtaint_tag_seg_t (bool widened to u32 for
   simple fixed-width (de)serialization). */
struct dtaint_tag_seg_wire {

  u32 sign;
  u32 begin;
  u32 end;

};

/* One entry of the "tags" dedup table: written once per unique label id the
   first time any cond_record references it (mirrors LogData.tags /
   Logger::save_tag), followed inline in the file by `n_segs`
   dtaint_tag_seg_wire entries. */
struct dtaint_tag_record {

  u32 label;
  u32 n_segs;

};

/* One entry of the "magic_bytes" table -- the raw byte snapshots captured
   at a COND_FN_OP (strcmp/memcmp-family) comparison site, mirrors
   LogData.magic_bytes: HashMap<usize, (Vec<u8>, Vec<u8>)>. `cond_index` is
   the index into the file's cond_list this belongs to. Followed inline by
   `len1` bytes (arg1's snapshot) then `len2` bytes (arg2's snapshot). */
struct dtaint_magic_bytes_record {

  u32 cond_index;
  u32 len1;
  u32 len2;

};

/* Written once, at the very start of the track file. */
struct dtaint_file_header {

  u32 magic; /* 'DTNT' i.e. 0x444e5454 */
  u32 version;
  u32 n_conds;
  u32 n_tags;
  u32 n_magic_bytes;

};

#define DTAINT_FILE_MAGIC 0x444e5454U
#define DTAINT_FILE_VERSION 2U

/* ---------------------------------------------------------------------- */
/* Runtime API the LLVM pass's inserted calls target (defined across the   */
/* dtaint_runtime directory's .c files, declared here so both the          */
/* instrumented target and any standalone test/driver code can share one   */
/* prototype set). The double-underscore hooks match the convention       */
/* DFSan/CmpLog/Angora all use for compiler-inserted runtime calls; the     */
/* plain-named ones are explicitly-called (by a test harness, or by this   */
/* pass's own call-site instrumentation, which is a normal CallInst, not   */
/* a magic hook).                                                          */
/* ---------------------------------------------------------------------- */

/* Returns the (possibly combined) label currently covering the `size` bytes
   at `ptr`. For size >= 2, uses TagSet's shape-inference combine (mirrors
   Angora's DFSanPass load handling: combine_n(.., infer=true)). */
u32 __dtaint_load(void *ptr, u64 size);

/* Tags the `size` bytes at `ptr` with `label` going forward. */
void __dtaint_store(void *ptr, u64 size, u32 label);

/* Combines two labels (TagSet::combine). DTAINT_NO_LABEL is the identity
   element. */
u32 __dtaint_combine(u32 l1, u32 l2);

/* Marks `lb`'s value as coming from a signed arithmetic/comparison context
   (TagSet::set_sign / DFSanMarkSignedFn semantics). */
void __dtaint_mark_signed(u32 lb1, u32 lb2);

/* Marks `lb` as having been masked with a compile-time constant via `&`
   (TagSet::combine_and / DFSanCombineAndFn semantics). */
void __dtaint_combine_and(u32 lb);

/* The icmp record-writing hook: no-op if both l1 and l2 are DTAINT_NO_LABEL.
   `cmpid` identifies the comparison site (a per-build monotonic counter in
   this port, not Angora's location-hash -- see README); `context` is always
   0 (see above). Internally applies TagSet::infer_shape2 to both operand
   labels (mirrors track.rs's __dfsw___angora_trace_cmp_tt calling
   infer_shape), the runtime eq-sign inference (COND_ICMP_EQ_OP + either
   operand's TagSeg.sign set => OR in DTAINT_COND_SIGN_MASK), order
   computation, and len_label extraction, all exactly mirroring
   track.rs::__dfsw___angora_trace_cmp_tt + logger.rs::save. */
void __dtaint_trace_cmp(u32 cmpid, u32 context, u32 op, u32 size, u64 arg1,
                        u64 arg2, u32 cond, u32 l1, u32 l2);

/* The switch record-writing hook: emits one record per case value, mirrors
   track.rs's __dfsw___angora_trace_switch_tt. `cases` points at `num`
   u64 case values; `matched_case` is the actual runtime switch value
   (compared against each case to set DTAINT_COND_DONE_ST). */
void __dtaint_trace_switch(u32 cmpid, u32 context, u32 size, u64 matched_value,
                           u32 num, const u64 *cases, u32 lb);

/* strcmp/memcmp-family comparison hook (Angora's "cmpfn" ExploitList
   category / __dfsw___angora_trace_fn_tt): `size` is the caller-supplied
   length for memcmp/strncmp-style calls, or 0 to mean "use strlen() on both
   pointers" (matching track.rs's exact fallback). Reads current shadow
   labels for both buffers itself (this port has no DFSan-style automatic
   per-call shadow propagation, so unlike Angora it takes raw pointers, not
   pre-resolved labels). */
void __dtaint_trace_fn(u32 cmpid, u32 context, u32 size, const void *arg1,
                       const void *arg2);

/* Taint source: seed one fresh label per byte starting at `ptr`, at file
   offset 0..len (not tied to any real stream position). Called explicitly
   by a test harness that wants to seed taint without going through one of
   the ABI-list-modeled library calls below. */
void dtaint_source_buf(const void *ptr, u64 len);

/* ---------------------------------------------------------------------- */
/* ABI-list-modeled library call wrappers.                                 */
/*                                                                          */
/* Unlike Angora's real DFSan custom-function ABI (which relies on the     */
/* target's *own* call to e.g. `read` being transparently redirected to a  */
/* same-signature `__dfsw_read` by DFSan's label-passing calling           */
/* convention), this pass has the LLVM pass directly redirect matching     */
/* CallInsts to these distinctly-named wrapper functions instead (see      */
/* instrumentation/afl-llvm-dtaint-pass.so.cc's call-site handling). Each  */
/* wrapper below has the exact same signature and behavior as the libc     */
/* function it stands in for, plus taint bookkeeping -- callers get        */
/* identical program behavior.                                             */
/*                                                                          */
/* Source functions use ftell()/lseek() to recover the real file position  */
/* (falling back to a process-wide monotonic counter if the fd/FILE isn't  */
/* seekable, e.g. a pipe or stdin-as-pipe), exactly like Angora's own       */
/* io_func.c -- but (deliberate simplification, unlike Angora) there is no  */
/* "is this fd the fuzzing input" allowlist: every call through these       */
/* wrappers taints its output unconditionally. See README.dtaint.md.        */
/* ---------------------------------------------------------------------- */

#include <stdio.h>
#include <sys/types.h>

ssize_t __dtaint_read(int fd, void *buf, size_t count);
size_t  __dtaint_fread(void *buf, size_t size, size_t count, FILE *stream);
char   *__dtaint_fgets(char *str, int count, FILE *stream);
ssize_t __dtaint_pread(int fd, void *buf, size_t count, off_t offset);

/* Copies shadow labels byte-for-byte from `src` to `dst` (overlap-safe).
   Inserted directly by the pass right after an `llvm.memcpy.*`/
   `llvm.memmove.*` intrinsic -- clang lowers even a plain source-level
   `memcpy()`/`memmove()` call to one of these intrinsics rather than a
   real CallInst in the overwhelming majority of cases (confirmed by
   testing: the __dtaint_memcpy wrapper below only ever fires for the rare
   case where the call survives as a real CallInst, e.g. taking memcpy's
   address as a function pointer), so this is the primary propagation
   path, not a fallback. */
void __dtaint_propagate_mem(const void *dst, const void *src, u64 len);

void *__dtaint_memcpy(void *dst, const void *src, size_t n);
void *__dtaint_memmove(void *dst, const void *src, size_t n);
char *__dtaint_strcpy(char *dst, const char *src);
char *__dtaint_strncpy(char *dst, const char *src, size_t n);
char *__dtaint_strcat(char *dst, const char *src);

/* These take a leading `cmpid` (a compile-time constant the pass assigns
   per call site, from the same counter space as icmp/switch sites) since,
   unlike the propagators above, they need to identify themselves to
   __dtaint_trace_fn -- so the pass builds a *new* call (extra leading arg),
   not a same-signature callee swap, when redirecting these sites. */
int __dtaint_strcmp(u32 cmpid, const char *a, const char *b);
int __dtaint_strncmp(u32 cmpid, const char *a, const char *b, size_t n);
int __dtaint_memcmp(u32 cmpid, const void *a, const void *b, size_t n);
int __dtaint_strcasecmp(u32 cmpid, const char *a, const char *b);
int __dtaint_strncasecmp(u32 cmpid, const char *a, const char *b, size_t n);

/* Execs the dtaint-instrumented child -- mirrors cmplog_exec_child
   (include/cmplog.h). */
struct afl_forkserver;
void dtaint_exec_child(struct afl_forkserver *fsrv, char **argv);

#ifdef __cplusplus
}
#endif

#endif
