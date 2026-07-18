/*
   american fuzzy lop++ - dynamic taint tracking (real DFSan): comparison hooks
   --------------------------------------------------------------------------------

   These are the DFSan custom-function ABI implementations
   (`__dfsw_<name>`) that AngoraPass.cc's inserted calls to `__angora_trace_
   cmp_tt`/`__angora_trace_switch_tt`/`__angora_trace_fn_tt`/
   `__angora_trace_exploit_val_tt` resolve to, because those names are
   marked `custom` in the abilist DFSanPass.cc parses (rules/angora_abilist.txt,
   rules/dfsan_abilist.txt). DFSan's own pass appends one hidden dfsan_label
   argument per real argument, in order, after all the real arguments --
   this is why each function below has twice(ish) as many parameters as its
   "real" signature suggests. This mirrors runtime/src/track.rs exactly (the
   Rust side of Angora's own DFSan fork), translated to C and forwarding
   into our own dtaint_logger.c (dtaint_runtime/, already built/tested in
   this session's earlier phase) instead of Angora's Rust Logger.

   Unlike the earlier (custom-pass) phase's dtaint-rt.c, there is no
   __dtaint_load/__dtaint_store/__dtaint_combine here -- real DFSan already
   propagates labels automatically through every instruction, so those
   hooks aren't needed at all in this path.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <string.h>

#include "dtaint.h"
#include "dtaint_len_label.h"
#include "dtaint_logger.h"
#include "dtaint_tagset.h"
#include "dfsan_interface.h"

/* UnfoldBranchPass.cc inserts a call to this (void(i32)) at every split
   compound-conditional site purely as a marker for AngoraPass.cc's own
   cleanup pass (visitCallInst erases the call once it's served its
   purpose -- see AngoraPass.cc). In practice a live (non-dead-code-
   eliminated) reference to the *unwrapped* symbol can still reach the
   linker via DFSan's auto-generated `dfsw$__unfold_branch_fn` wrapper, so
   a real (trivial, no-op) definition is needed -- Angora's own build
   apparently relies on -ffunction-sections/--gc-sections eliminating this
   before it ever needs to link; we don't control that here, so just
   define it. */
void __unfold_branch_fn(int cid) { (void)cid; }

/* Mirrors track.rs's infer_eq_sign: an == comparison where either operand's
   underlying label was itself marked signed gets flagged so the fuzzer
   knows to treat the compared constant as signed. */
#define DTAINT_COND_ICMP_EQ_OP 32U

static u32 infer_eq_sign(u32 op, dfsan_label lb1, dfsan_label lb2) {

  /* Strip any length label before indexing the tag tree -- see dfsan.cc's
     dfsan_mark_signed/_infer_shape_in_math_op for the same fix and why it's
     needed (a raw fat label caused a real SIGSEGV here). The *record*
     passed to dtaint_logger_save keeps the original, unstripped lb1/lb2 --
     only these direct dtaint_tagset_* calls need the plain id. */
  dfsan_label n1 = dtaint_len_label_get_normal(lb1);
  dfsan_label n2 = dtaint_len_label_get_normal(lb2);

  if (op == DTAINT_COND_ICMP_EQ_OP &&
      ((n1 > 0 && dtaint_tagset_get_sign(n1)) ||
       (n2 > 0 && dtaint_tagset_get_sign(n2))))
    return op | DTAINT_COND_SIGN_MASK;

  return op;

}

/* Real params: (cmpid, context, size, op, arg1, arg2, condition). Hidden
   labels l0..l6 correspond 1:1; only l4 (arg1) and l5 (arg2) are used,
   mirroring track.rs's __dfsw___angora_trace_cmp_tt exactly. */
void __dfsw___angora_trace_cmp_tt(u32 cmpid, u32 context, u32 size, u32 op,
                                  u64 arg1, u64 arg2, u32 condition,
                                  dfsan_label l0, dfsan_label l1,
                                  dfsan_label l2, dfsan_label l3,
                                  dfsan_label l4, dfsan_label l5,
                                  dfsan_label l6) {

  (void)l0; (void)l1; (void)l2; (void)l3; (void)l6;

  dfsan_label lb1 = l4, lb2 = l5;
  if (lb1 == 0 && lb2 == 0) return;

  op = infer_eq_sign(op, lb1, lb2);
  {

    dfsan_label n1 = dtaint_len_label_get_normal(lb1);
    dfsan_label n2 = dtaint_len_label_get_normal(lb2);
    if (n1 > 0) dtaint_tagset_infer_shape2(n1, size);
    if (n2 > 0) dtaint_tagset_infer_shape2(n2, size);

  }

  struct dtaint_cond_record rec = {

      .cmpid = cmpid, .context = context, .order = 0, .belong = 0,
      .condition = condition, .level = 0, .op = op, .size = size,
      .lb1 = lb1, .lb2 = lb2, .arg1 = arg1, .arg2 = arg2,

  };

  dtaint_logger_save(&rec);

}

/* Real params: (cmpid, context, size, condition, num, args). Hidden labels
   l0..l5; only l3 (condition's own label) is used, mirrors track.rs's
   __dfsw___angora_trace_switch_tt. */
void __dfsw___angora_trace_switch_tt(u32 cmpid, u32 context, u32 size,
                                     u64 condition, u32 num, u64 *args,
                                     dfsan_label l0, dfsan_label l1,
                                     dfsan_label l2, dfsan_label l3,
                                     dfsan_label l4, dfsan_label l5) {

  (void)l0; (void)l1; (void)l2; (void)l4; (void)l5;

  dfsan_label lb = l3;
  if (lb == 0) return;

  /* Same strip-before-indexing fix as __dfsw___angora_trace_cmp_tt -- `lb`
     (and the record's own lb1 below) may be a length label. */
  dfsan_label lb_normal = dtaint_len_label_get_normal(lb);
  if (lb_normal > 0) dtaint_tagset_infer_shape2(lb_normal, size);

  u32 op = DTAINT_COND_SW_OP;
  if (lb_normal > 0 && dtaint_tagset_get_sign(lb_normal)) op |= DTAINT_COND_SIGN_MASK;

  for (u32 i = 0; i < num; i++) {

    struct dtaint_cond_record rec = {

        .cmpid = cmpid, .context = context, .order = (i << 16), .belong = 0,
        .condition = (args[i] == condition) ? DTAINT_COND_DONE_ST
                                            : DTAINT_COND_FALSE_ST,
        .level = 0, .op = op, .size = size,
        .lb1 = lb, .lb2 = 0, .arg1 = condition, .arg2 = args[i],

    };

    dtaint_logger_save(&rec);

  }

}

/* Real params: (cmpid, context, size, parg1, parg2). The hidden labels for
   the two pointer arguments (l3, l4) are each pointer's OWN label, not
   what's pointed to -- so, exactly like track.rs, this reads the labels of
   the pointed-to bytes explicitly via dfsan_read_label() instead of using
   the hidden args. `size == 0` means "use strlen() on both sides" (memcmp
   vs strcmp-family), matching Angora's convention exactly. */
void __dfsw___angora_trace_fn_tt(u32 cmpid, u32 context, u32 size,
                                 char *parg1, char *parg2, dfsan_label l0,
                                 dfsan_label l1, dfsan_label l2,
                                 dfsan_label l3, dfsan_label l4) {

  (void)l0; (void)l1; (void)l2; (void)l3; (void)l4;

  size_t arglen1, arglen2;

  if (size == 0) {

    arglen1 = strlen(parg1);
    arglen2 = strlen(parg2);

  } else {

    arglen1 = arglen2 = size;

  }

  dfsan_label lb1 = dfsan_read_label(parg1, arglen1);
  dfsan_label lb2 = dfsan_read_label(parg2, arglen2);

  if (lb1 == 0 && lb2 == 0) return;

  struct dtaint_cond_record rec = {

      .cmpid = cmpid, .context = context, .order = 0, .belong = 0,
      .condition = DTAINT_COND_FALSE_ST, .level = 0, .op = DTAINT_COND_FN_OP,
      .size = 0, .lb1 = 0, .lb2 = 0, .arg1 = 0, .arg2 = 0,

  };

  if (lb1 > 0) {

    rec.lb1 = lb1;
    rec.size = (u32)arglen2;

  } else if (lb2 > 0) {

    rec.lb2 = lb2;
    rec.size = (u32)arglen1;

  }

  int idx = dtaint_logger_save(&rec);
  if (idx >= 0)
    dtaint_logger_save_magic_bytes(idx, parg1, (u32)arglen1, parg2, (u32)arglen2);

}

/* Real params: (cmpid, context, size, op, val). Hidden labels l0..l4; only
   l4 (val's label) is used, mirrors track.rs's
   __dfsw___angora_trace_exploit_val_tt. Skips length-labels entirely (this
   is Angora's separate "exploitation" feature, not core taint capture). */
void __dfsw___angora_trace_exploit_val_tt(u32 cmpid, u32 context, u32 size,
                                          u32 op, u64 val, dfsan_label l0,
                                          dfsan_label l1, dfsan_label l2,
                                          dfsan_label l3, dfsan_label l4) {

  (void)l0; (void)l1; (void)l2; (void)l3;

  dfsan_label lb = l4;
  if (lb == 0 || dtaint_len_label_is_len(lb)) return;

  struct dtaint_cond_record rec = {

      .cmpid = cmpid, .context = context, .order = 0, .belong = 0,
      .condition = DTAINT_COND_FALSE_ST, .level = 0, .op = op, .size = size,
      .lb1 = lb, .lb2 = 0, .arg1 = val, .arg2 = 0,

  };

  dtaint_logger_save(&rec);

}
