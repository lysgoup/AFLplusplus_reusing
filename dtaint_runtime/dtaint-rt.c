/*
   american fuzzy lop++ - dynamic taint tracking runtime
   -------------------------------------------------------

   Core compiler-inserted hooks, ported from Angora's runtime/src/track.rs
   (comparison/switch/fn-site glue) sitting on top of dtaint_tagset.c
   (runtime/src/tag_set.rs's label tree) and dtaint_logger.c
   (runtime/src/logger.rs's track-file writer). See include/dtaint.h and
   instrumentation/README.dtaint.md for the full scope notes and deliberate
   simplifications this slice makes -- most notably:

     - shadow_table below is a fixed-size, direct-mapped, address-hashed
       array, NOT real shadow memory (no page-remapped address translation).
       Collisions across unrelated live allocations are possible in a long
       session; acceptable only for validation-scale runs.
     - Label propagation through SSA values within one function is tracked
       by the pass itself (Value* -> Value* label map), not by shadowing
       real memory continuously -- see the pass file's own header comment.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dtaint.h"
#include "dtaint_internal.h"
#include "dtaint_logger.h"
#include "dtaint_tagset.h"

/* ---------------------------------------------------------------------- */
/* Address-keyed shadow store (NOT real shadow memory -- see file header). */
/* ---------------------------------------------------------------------- */

#define DTAINT_SHADOW_BITS 24
#define DTAINT_SHADOW_SIZE (1U << DTAINT_SHADOW_BITS)
#define DTAINT_SHADOW_MASK (DTAINT_SHADOW_SIZE - 1U)

static dtaint_label_t shadow_table[DTAINT_SHADOW_SIZE];

static inline u32 shadow_slot(const void *ptr) {

  /* Byte-granularity addressing -- an earlier version shifted by 2 (a
     word-alignment hash), which silently collided every 4 consecutive byte
     addresses onto the same slot. Confirmed by direct testing. */
  return (u32)((uintptr_t)ptr & DTAINT_SHADOW_MASK);

}

static int inited = 0;

static void ensure_init(void) {

  if (!inited) { dtaint_tagset_init(); inited = 1; }

}

/* ---------------------------------------------------------------------- */
/* Load/store/combine -- the SSA-level hooks the pass inserts directly.   */
/* ---------------------------------------------------------------------- */

#define MAX_SCALAR_BYTES 32 /* generous for any real int/float scalar */

u32 __dtaint_load(void *ptr, u64 size) {

  ensure_init();

  if (size == 0) return DTAINT_NO_LABEL;
  if (size == 1) return shadow_table[shadow_slot(ptr)];

  u64 n = (size > MAX_SCALAR_BYTES) ? MAX_SCALAR_BYTES : size;
  dtaint_label_t labels[MAX_SCALAR_BYTES];

  for (u64 i = 0; i < n; i++)
    labels[i] = shadow_table[shadow_slot((char *)ptr + i)];

  /* Load instructions get shape inference (a multi-byte load of otherwise
     unrelated adjacent single-offset labels is recognized as one grouped
     variable) -- mirrors tag_set.rs's own comment: "load inst will only
     call combine_n if size >= 2". */
  return dtaint_tagset_combine_n(labels, (u32)n, /*infer=*/1);

}

void __dtaint_store(void *ptr, u64 size, u32 label) {

  ensure_init();

  for (u64 i = 0; i < size; i++)
    shadow_table[shadow_slot((char *)ptr + i)] = label;

}

u32 __dtaint_combine(u32 l1, u32 l2) {

  ensure_init();
  return dtaint_tagset_combine(l1, l2);

}

void __dtaint_mark_signed(u32 lb1, u32 lb2) {

  /* Mirrors dfsan_mark_signed: marks both operands' *own* labels, not a
     combined result. */
  if (lb1 > 0) dtaint_tagset_set_sign(lb1);
  if (lb2 > 0) dtaint_tagset_set_sign(lb2);

}

void __dtaint_combine_and(u32 lb) {

  if (lb > 0) dtaint_tagset_combine_and(lb);

}

/* ---------------------------------------------------------------------- */
/* Comparison-site hooks -- mirrors track.rs.                              */
/* ---------------------------------------------------------------------- */

/* Mirrors track.rs's infer_eq_sign: an == comparison where either operand's
   underlying label was itself marked signed (e.g. it flowed through a
   signed comparison/division elsewhere) gets flagged so the fuzzer knows to
   treat the compared constant as signed. `op`'s low byte carries the icmp
   predicate (see include/dtaint.h -- these are LLVM's own enum values,
   ICMP_EQ == 32). */
#define DTAINT_COND_ICMP_EQ_OP 32U

static u32 infer_eq_sign(u32 op, u32 lb1, u32 lb2) {

  if (op == DTAINT_COND_ICMP_EQ_OP &&
      ((lb1 > 0 && dtaint_tagset_get_sign(lb1)) ||
       (lb2 > 0 && dtaint_tagset_get_sign(lb2))))
    return op | DTAINT_COND_SIGN_MASK;

  return op;

}

void __dtaint_trace_cmp(u32 cmpid, u32 context, u32 op, u32 size, u64 arg1,
                        u64 arg2, u32 cond, u32 l1, u32 l2) {

  if (l1 == DTAINT_NO_LABEL && l2 == DTAINT_NO_LABEL) return;

  op = infer_eq_sign(op, l1, l2);
  if (l1 > 0) dtaint_tagset_infer_shape2(l1, size);
  if (l2 > 0) dtaint_tagset_infer_shape2(l2, size);

  struct dtaint_cond_record rec = {

      .cmpid = cmpid,
      .context = context,
      .order = 0,
      .belong = 0,
      .condition = cond,
      .level = 0,
      .op = op,
      .size = size,
      .lb1 = l1,
      .lb2 = l2,
      .arg1 = arg1,
      .arg2 = arg2,

  };

  dtaint_logger_save(&rec);

}

void __dtaint_trace_switch(u32 cmpid, u32 context, u32 size, u64 matched_value,
                           u32 num, const u64 *cases, u32 lb) {

  if (lb == DTAINT_NO_LABEL) return;

  dtaint_tagset_infer_shape2(lb, size);

  u32 op = DTAINT_COND_SW_OP;
  if (dtaint_tagset_get_sign(lb)) op |= DTAINT_COND_SIGN_MASK;

  for (u32 i = 0; i < num; i++) {

    struct dtaint_cond_record rec = {

        .cmpid = cmpid,
        .context = context,
        .order = (i << 16), /* case index in the high bits, see
                                dtaint_logger.c's get_order for how the low
                                bits get folded in */
        .belong = 0,
        .condition = (cases[i] == matched_value) ? DTAINT_COND_DONE_ST
                                                  : DTAINT_COND_FALSE_ST,
        .level = 0,
        .op = op,
        .size = size,
        .lb1 = lb,
        .lb2 = 0,
        .arg1 = matched_value,
        .arg2 = cases[i],

    };

    dtaint_logger_save(&rec);

  }

}

void __dtaint_trace_fn(u32 cmpid, u32 context, u32 size, const void *arg1,
                       const void *arg2) {

  ensure_init();

  size_t len1, len2;

  if (size == 0) {

    len1 = strlen((const char *)arg1);
    len2 = strlen((const char *)arg2);

  } else {

    len1 = len2 = size;

  }

  dtaint_label_t l1 = (len1 > 0) ? __dtaint_load((void *)arg1, len1) : DTAINT_NO_LABEL;
  dtaint_label_t l2 = (len2 > 0) ? __dtaint_load((void *)arg2, len2) : DTAINT_NO_LABEL;

  if (l1 == DTAINT_NO_LABEL && l2 == DTAINT_NO_LABEL) return;

  struct dtaint_cond_record rec = {

      .cmpid = cmpid,
      .context = context,
      .order = 0,
      .belong = 0,
      .condition = DTAINT_COND_FALSE_ST,
      .level = 0,
      .op = DTAINT_COND_FN_OP,
      .size = 0,
      .lb1 = 0,
      .lb2 = 0,
      .arg1 = 0,
      .arg2 = 0,

  };

  /* Mirrors track.rs's __dfsw___angora_trace_fn_tt: only the tainted side's
     label + the *other* side's length is kept (asymmetric on purpose --
     the "size" field records how many bytes of the untainted side a
     mutation should try to match against). */
  if (l1 > 0) {

    rec.lb1 = l1;
    rec.size = (u32)len2;

  } else if (l2 > 0) {

    rec.lb2 = l2;
    rec.size = (u32)len1;

  }

  int idx = dtaint_logger_save(&rec);
  if (idx >= 0)
    dtaint_logger_save_magic_bytes(idx, arg1, (u32)len1, arg2, (u32)len2);

}

/* ---------------------------------------------------------------------- */
/* Explicit taint source (test harnesses / non-ABI-list-modeled input).   */
/* ---------------------------------------------------------------------- */

void dtaint_source_buf(const void *ptr, u64 len) {

  ensure_init();

  for (u64 i = 0; i < len; i++) {

    dtaint_label_t lb = dtaint_tagset_insert((u32)i);
    shadow_table[shadow_slot((const char *)ptr + i)] = lb;

  }

}

/* Used by dtaint_runtime/dtaint_abi.c's source wrappers -- not part of the
   public header (internal linkage between the two runtime files only). */
void dtaint_source_at_offset(const void *ptr, u64 len, u32 offset) {

  ensure_init();

  for (u64 i = 0; i < len; i++) {

    dtaint_label_t lb = dtaint_tagset_insert(offset + (u32)i);
    shadow_table[shadow_slot((const char *)ptr + i)] = lb;

  }

}

void __dtaint_propagate_mem(const void *dst, const void *src, u64 len) {

  ensure_init();

  /* Snapshot src labels first: dst and src shadow regions may alias (e.g.
     memmove with overlapping ranges), so this must not read-after-write its
     own output, mirroring memmove's own overlap-safety. */
  u64 n = len;
  while (n > 0) {

    u64 chunk = (n > MAX_SCALAR_BYTES) ? MAX_SCALAR_BYTES : n;
    dtaint_label_t tmp[MAX_SCALAR_BYTES];
    u64 base = len - n;

    for (u64 i = 0; i < chunk; i++)
      tmp[i] = shadow_table[shadow_slot((const char *)src + base + i)];
    for (u64 i = 0; i < chunk; i++)
      shadow_table[shadow_slot((const char *)dst + base + i)] = tmp[i];

    n -= chunk;

  }

}

/* Note: dtaint_exec_child (the forkserver child-exec hook) is fuzzer-side
   code that runs inside afl-fuzz's forked child, not inside the
   instrumented target -- it lives in src/afl-fuzz-dtaint.c (Piece 3), not
   here. This file only contains code that gets linked into the target
   binary itself. */
