//===-- dfsan.cc ----------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//

#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_flag_parser.h"
#include "../sanitizer_common/sanitizer_flags.h"
#include "../sanitizer_common/sanitizer_libc.h"

#include "defs.h"
#include "dfsan.h"

using namespace __dfsan;

/* Redirected to our own C port of Angora's tag_set.rs (dtaint_runtime/, this
   session's earlier phase, already built and Docker-verified) instead of
   Angora's original Rust FFI (runtime/include/tag_set.h) -- same algorithm,
   no Rust/cargo dependency needed. dfsan_label here is uint32_t (see
   include/defs.h's typedef, pulled in above), matching dtaint_label_t
   exactly, so no conversion is needed at any call site below. */
#include "dtaint_tagset.h"
#include "dtaint_len_label.h"

Flags __dfsan::flags_data;

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_retval_tls;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_arg_tls[64];

SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;

#ifdef DFSAN_RUNTIME_VMA
// Runtime detected VMA size.
int __dfsan::vmaSize;
#endif

static uptr UnusedAddr() {
  // return MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() +
  // sizeof(dfsan_union_table_t);
  return MappingArchImpl<MAPPING_UNION_TABLE_ADDR>();
}

// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
//
// Mirrors tag_set_wrap.rs's __angora_tag_set_combine exactly: a length label
// (see dtaint_len_label.h) must be stripped down to its plain TagSet id
// before it ever reaches the tag tree, then re-attached to the combined
// result -- confirmed necessary by a real SIGSEGV (dtaint_tagset_infer_
// shape2() indexing its node array with a raw, unstripped fat-label value
// coming from a length-tainted read() return value flowing into a
// comparison; see dfsan_infer_shape_in_math_op below for the matching fix).
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsan_union(dfsan_label l1, dfsan_label l2) {
  if (l1 == 0) return l2;
  if (l2 == 0) return l1;

  dfsan_label len_lb = 0;
  if (dtaint_len_label_is_len(l1)) {
    len_lb = dtaint_len_label_get_sublabel(l1);
    l1 = dtaint_len_label_get_normal(l1);
  }
  if (dtaint_len_label_is_len(l2)) {
    len_lb = dtaint_len_label_get_sublabel(l2);
    l2 = dtaint_len_label_get_normal(l2);
  }

  dfsan_label l3 = dtaint_tagset_combine(l1, l2);
  return dtaint_len_label_attach(l3, len_lb);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsan_union_load(const dfsan_label *ls, uptr n) {
  if (!ls) return 0;

  /* Mirrors tag_set_wrap.rs's __angora_tag_set_combine_n: strip any length
     label from each element (keeping the last one seen, exactly matching
     the Rust fold's overwrite-on-each-match behavior) before combining. */
  dfsan_label len_lb = 0;
  dfsan_label stripped[64];
  uptr count = (n > 64) ? 64 : n;

  for (uptr i = 0; i < count; i++) {
    dfsan_label l = ls[i];
    if (dtaint_len_label_is_len(l)) {
      len_lb = dtaint_len_label_get_sublabel(l);
      l = dtaint_len_label_get_normal(l);
    }
    stripped[i] = l;
  }

  dfsan_label combined = dtaint_tagset_combine_n(stripped, (uint32_t)count, /*infer=*/1);
  return dtaint_len_label_attach(combined, len_lb);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_unimplemented(
    char *fname) {
  if (flags().warn_unimplemented)
    Report("WARNING: DataFlowSanitizer: call to uninstrumented function %s\n",
           fname);
}

// Use '-mllvm -dfsan-debug-nonzero-labels' and break on this function
// to try to figure out where labels are being introduced in a nominally
// label-free program.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_nonzero_label() {
  if (flags().warn_nonzero_labels)
    Report("WARNING: DataFlowSanitizer: saw nonzero label\n");
}

// Indirect call to an uninstrumented vararg function. We don't have a way of
// handling these at the moment.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_vararg_wrapper(
    const char *fname) {
  Report(
      "FATAL: DataFlowSanitizer: unsupported indirect call to vararg "
      "function %s\n",
      fname);
  Die();
}

/* Both of these mirror tag_set_wrap.rs's __angora_tag_set_mark_sign /
   _infer_shape_in_math_op: strip to the plain TagSet id
   (get_normal_label_usize in Rust) before indexing the tag tree -- a
   length-labeled value (e.g. a tainted read() return count) must never
   reach dtaint_tagset_* directly. This is the exact fix for the SIGSEGV
   noted at __dfsan_union above. */
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_mark_signed(dfsan_label l1, dfsan_label l2) {
  l1 = dtaint_len_label_get_normal(l1);
  l2 = dtaint_len_label_get_normal(l2);
  if (l1 > 0) dtaint_tagset_set_sign(l1);
  if (l2 > 0) dtaint_tagset_set_sign(l2);
  return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_infer_shape_in_math_op(
    dfsan_label l1, dfsan_label l2, u32 len) {
  l1 = dtaint_len_label_get_normal(l1);
  l2 = dtaint_len_label_get_normal(l2);
  if (l1 > 0) dtaint_tagset_infer_shape2(l1, len);
  if (l2 > 0) dtaint_tagset_infer_shape2(l2, len);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_combine_and_ins(
    dfsan_label lb) {
  lb = dtaint_len_label_get_normal(lb);
  if (lb > 0) dtaint_tagset_combine_and(lb);
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
SANITIZER_INTERFACE_ATTRIBUTE dfsan_label dfsan_union(dfsan_label l1,
                                                      dfsan_label l2) {
  if (l1 == l2) return l1;
  return __dfsan_union(l1, l2);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_create_label(int pos) {
  return dtaint_tagset_insert((uint32_t)pos);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_set_label(
    dfsan_label label, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp) {
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp) continue;

    *labelp = label;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_add_label(dfsan_label label, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    if (*labelp != label) *labelp = __dfsan_union(*labelp, label);
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label __dfsw_dfsan_get_label(
    long data, dfsan_label data_label, dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label dfsan_read_label(const void *addr,
                                                           uptr size) {
  if (size == 0) return 0;
  const dfsan_label *ls = shadow_for(addr);
  if (!ls) return 0;

  /* Same len-label strip/reattach as __dfsan_union_load above. */
  dfsan_label len_lb = 0;
  dfsan_label stripped[64];
  uptr count = (size > 64) ? 64 : size;

  for (uptr i = 0; i < count; i++) {
    dfsan_label l = ls[i];
    if (dtaint_len_label_is_len(l)) {
      len_lb = dtaint_len_label_get_sublabel(l);
      l = dtaint_len_label_get_normal(l);
    }
    stripped[i] = l;
  }

  dfsan_label combined = dtaint_tagset_combine_n(stripped, (uint32_t)count, /*infer=*/0);
  return dtaint_len_label_attach(combined, len_lb);
}

SANITIZER_INTERFACE_ATTRIBUTE const dfsan_label *dfsan_shadow_for(
    const void *addr) {
  return shadow_for(addr);
}

// const std::vector<struct tag_seg> dfsan_get_label_offsets(dfsan_label l) {
//   return  __dfsan_tag_set->find(l);
// }

void Flags::SetDefaults() {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void RegisterDfsanFlags(FlagParser *parser, Flags *f) {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  flags().SetDefaults();

  FlagParser parser;
  RegisterCommonFlags(&parser);
  RegisterDfsanFlags(&parser, &flags());
  parser.ParseString(GetEnv("DFSAN_OPTIONS"));
  InitializeCommonFlags();
  if (Verbosity()) ReportUnrecognizedFlags();
  if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void InitializePlatformEarly() {
  AvoidCVE_2016_2143();
#ifdef DFSAN_RUNTIME_VMA
  __dfsan::vmaSize = (MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
  if (__dfsan::vmaSize == 39 || __dfsan::vmaSize == 42 ||
      __dfsan::vmaSize == 48) {
    __dfsan_shadow_ptr_mask = ShadowMask();
  } else {
    Printf("FATAL: DataFlowSanitizer: unsupported VMA range\n");
    Printf("FATAL: Found %d - Supported 39, 42, and 48\n", __dfsan::vmaSize);
    Die();
  }
#endif
}

static void dfsan_fini() {}

static void dfsan_init(int argc, char **argv, char **envp) {
  InitializeFlags();

  /* NOT dtaint_tagset_init() here: dfsan_init() runs via .preinit_array,
     before glibc's malloc is guaranteed to be safely usable in a
     dynamically-linked PIE binary -- confirmed by testing: calling it here
     led to a corrupted/uninitialized `nodes` array and a real SIGSEGV
     inside dtaint_tagset_infer_shape2() on the very first comparison.
     Every dtaint_tagset_* entry point now lazily self-initializes on first
     real use instead (well after main() starts), exactly like the
     equivalent ensure_init() pattern in the custom-pass phase's
     dtaint-rt.c. */

  InitializePlatformEarly();

  if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr())) Die();

  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uptr init_addr = (uptr)&dfsan_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());

  InitializeInterceptors();

  // Register the fini callback to run when the program terminates successfully
  // or it is killed by the runtime.
  Atexit(dfsan_fini);
  AddDieCallback(dfsan_fini);
}

#if SANITIZER_CAN_USE_PREINIT_ARRAY
__attribute__((section(".preinit_array"),
               used)) static void (*dfsan_init_ptr)(int, char **,
                                                    char **) = dfsan_init;
#endif
