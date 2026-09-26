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

/* Repeated-hit-of-the-same-site cutoff per execution (loops) -- the writer
   keys its order_map on (cmpid, context), so a hot site reached from
   several call contexts gets an independent counter per context, and this
   is the depth of each one. Mirrors common/src/config.rs's
   MAX_COND_ORDER in Angora, which taint_scan runs unmodified. */
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
/* Version 3 -- the only version anything still writes or reads.          */
/*                                                                        */
/* Produced by taint_scan (Reusing_mut's fuzzer/src/bin/taint_scan.rs),    */
/* which drives Angora's own pipeline over an Angora track binary and      */
/* serialises the result: one <seed>.dtaint per seed, next to              */
/* value_pool.dict and unsolved_condition in the directory afl-fuzz -r     */
/* is pointed at. src/afl-fuzz-reusing.c is the only reader.               */
/*                                                                        */
/* Difference from version 2 (which nothing produces any more -- it was    */
/* the raw per-run format of a DFSan-instrumented target, back when        */
/* afl-fuzz did its own taint tracking): runs of adjacent single-byte      */
/* magic-byte comparisons are glued into one combined offset span per      */
/* group, ported from Angora's fparser.rs. See the struct below.           */
/* ---------------------------------------------------------------------- */
#define DTAINT_FILE_VERSION_GROUPED 3U

/* Same fields as dtaint_cond_record, plus the combined offset span of the
   magic-byte group this record was merged into (see above). Both are 0 for
   a record that isn't part of any group (either not a magic-byte
   comparison at all, or a magic-byte comparison with no contiguous
   same-context neighbor) -- check magic_group_end > magic_group_begin to
   tell "grouped" from "ungrouped", not just nonzero, since offset 0 is a
   valid group start. Every member of the same group carries an identical
   [magic_group_begin, magic_group_end) span, exactly mirroring how
   fparser.rs assigns the same cloned `group` Vec to every member index in
   its run. */
struct dtaint_cond_record_grouped {

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

  u32 magic_group_begin;
  u32 magic_group_end;

};

#ifdef __cplusplus
}
#endif

#endif
