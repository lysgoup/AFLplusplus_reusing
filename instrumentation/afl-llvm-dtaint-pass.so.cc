/*
   american fuzzy lop++ - dynamic taint tracking LLVM pass
   -----------------------------------------------------------------

   Ported from the Angora fuzzer (llvm_mode/pass/DFSanPass.cc +
   llvm_mode/pass/AngoraPass.cc's processCmp/visitSwitchInst/
   visitCompareFunc) -- see include/dtaint.h and
   instrumentation/README.dtaint.md for full scope notes. Goal of this
   phase: capture the *same* taint information Angora's `.taint` runtime
   captures (per-byte provenance, comparison/switch/library-call-comparison
   sites, length-derived comparisons), not just prove the propagation
   mechanism works -- nothing here feeds a mutation strategy yet.

   Deliberate simplifications versus real Angora (all documented in
   README.dtaint.md, not oversights):

     - No real shadow *memory* (page-remapped address translation). Every
       Load/Store is instead instrumented to call into a runtime hook
       backed by a simple address-keyed lookup table.
     - No function-call context-sensitivity (Angora's opt-in, off-by-
       default `-c` feature) -- context is always the constant 0, which is
       exactly what real Angora does with context disabled, not an
       approximation of it.
     - `cmpid` is a per-build monotonic counter, not Angora's location-hash
       -- deterministic per build, not stable across recompiles.
     - ABI-list call-site interception covers a documented subset of libc
       (read/fread/fgets/pread as sources; memcpy/memmove/strcpy/strncpy/
       strcat as propagators; strcmp/strncmp/memcmp/strcasecmp/
       strncasecmp as cmpfn) via direct call-site redirection to
       identically-signatured wrapper functions, not DFSan's real custom-
       function label-passing ABI. No open/fopen fd-allowlisting (every
       call through these wrappers taints unconditionally).
     - Only integer Load/Store/BinaryOperator/ICmpInst/SwitchInst are
       instrumented; floats, vectors, pointers, and aggregates are skipped
       entirely.
     - Label propagation through SSA values within one function is tracked
       by the pass itself (a Value* -> Value* map), not by shadowing real
       memory continuously -- this only works correctly for straight-
       line/structured control flow where definitions are visited before
       uses in IR layout order, a known limitation for arbitrary control
       flow.

   Registers at PB.registerPipelineStartEPCallback (not OptimizerLast/
   Early, where CmpLog and AFL++'s own coverage pass register) specifically
   so it runs *before* LLVM's function-simplification pipeline (SROA +
   mem2reg), which at -O1+ can eliminate the original alloca+Load+Store for
   a stack buffer before a later-registered pass ever sees it. Build with
   AFL_DONT_OPTIMIZE=1 for this slice as a second safety margin. Verified
   against real LLVM 18 -- see README.dtaint.md's "Known risks" section.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

*/

#include <cstdint>
#include <vector>

#include "llvm/Config/llvm-config.h"
#ifndef LLVM_MAJOR
  #define LLVM_MAJOR LLVM_VERSION_MAJOR
#endif
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/IR/Verifier.h"

/* Not used for allow/deny-list filtering here (this slice instruments the
   whole module unconditionally) -- included because afl-llvm-common.h's
   IS_EXTERN trick means whichever .cc includes it *without* pre-defining
   IS_EXTERN (i.e. this file, not afl-llvm-common.cc itself) is the one that
   supplies real storage for its `be_quiet`/`debug` globals. Confirmed by
   testing: omitting this include left those symbols undefined at
   plugin-load time. */
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

/* op-code / mask constants mirroring common/src/defs.rs -- kept in sync by
   hand with include/dtaint.h's DTAINT_COND_* since this file is C++ and
   can't directly include that C header's extern "C" function decls without
   pulling in AFL++'s config.h/types.h (harmless, but unnecessary here). */
constexpr uint32_t kCondSignMask = 0x100U;

/* ABI-list call-site redirection table -- mirrors llvm_mode's
   dfsan_custom.cc (sources) + exploitation_list.txt's cmpfn category. See
   this pass's file header and dtaint_runtime/dtaint_abi.c for the exact
   function list and why call-site redirection (not DFSan's real custom-
   function ABI) is used here. */
enum class DtaintCallKind { Source, Propagate, CmpFn };

struct DtaintCallRule {

  const char    *name;
  const char    *wrapper;
  DtaintCallKind kind;

};

constexpr DtaintCallRule kCallRules[] = {

    {"read", "__dtaint_read", DtaintCallKind::Source},
    {"fread", "__dtaint_fread", DtaintCallKind::Source},
    {"fgets", "__dtaint_fgets", DtaintCallKind::Source},
    {"pread", "__dtaint_pread", DtaintCallKind::Source},

    {"memcpy", "__dtaint_memcpy", DtaintCallKind::Propagate},
    {"memmove", "__dtaint_memmove", DtaintCallKind::Propagate},
    {"strcpy", "__dtaint_strcpy", DtaintCallKind::Propagate},
    {"strncpy", "__dtaint_strncpy", DtaintCallKind::Propagate},
    {"strcat", "__dtaint_strcat", DtaintCallKind::Propagate},

    {"strcmp", "__dtaint_strcmp", DtaintCallKind::CmpFn},
    {"strncmp", "__dtaint_strncmp", DtaintCallKind::CmpFn},
    {"memcmp", "__dtaint_memcmp", DtaintCallKind::CmpFn},
    {"strcasecmp", "__dtaint_strcasecmp", DtaintCallKind::CmpFn},
    {"strncasecmp", "__dtaint_strncasecmp", DtaintCallKind::CmpFn},

};

static const DtaintCallRule *findCallRule(StringRef Name) {

  for (const auto &Rule : kCallRules)
    if (Name == Rule.name) return &Rule;

  return nullptr;

}

class AFLDTaint : public PassInfoMixin<AFLDTaint> {

 public:
  AFLDTaint() {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  struct Hooks {

    FunctionCallee Load;
    FunctionCallee Store;
    FunctionCallee Combine;
    FunctionCallee MarkSigned;
    FunctionCallee CombineAnd;
    FunctionCallee TraceCmp;
    FunctionCallee TraceSwitch;
    FunctionCallee PropagateMem;

  };

  bool instrumentFunction(Module &M, Function &F, const DataLayout &DL,
                          LLVMContext &C, const Hooks &H, uint32_t &cmpid);

  void instrumentCallSites(Module &M, LLVMContext &C,
                           const std::vector<CallInst *> &Calls,
                           uint32_t &cmpid);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "afldtaint", "v0.2",
          [](PassBuilder &PB) {

            /* PipelineStart, not OptimizerLast/Early -- see file header. */
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(AFLDTaint());

                });

          }};

}

/* Returns the label Value (i32) currently associated with `V` if this pass
   has instrumented something that produced one, otherwise nullptr (meaning
   "untainted" -- callers should use a literal 0 constant in that case). */
static Value *lookupLabel(DenseMap<Value *, Value *> &Labels, Value *V) {

  auto It = Labels.find(V);
  return It == Labels.end() ? nullptr : It->second;

}

/* Mirrors DFSanPass::combineShadows's is_signed detection for binary
   operators: SDiv/SRem/AShr are always signed; other overflowing ops are
   signed only if the frontend marked them nsw but not nuw (clang's own
   convention for "this came from a signed source type"). */
static bool binopIsSigned(BinaryOperator *BO) {

  switch (BO->getOpcode()) {

    case Instruction::SDiv:
    case Instruction::SRem:
    case Instruction::AShr:
      return true;
    default:
      if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(BO))
        return OBO->hasNoSignedWrap() && !OBO->hasNoUnsignedWrap();
      return false;

  }

}

bool AFLDTaint::instrumentFunction(Module &M, Function &F,
                                   const DataLayout &DL, LLVMContext &C,
                                   const Hooks &H, uint32_t &cmpid) {

  if (F.isDeclaration()) return false;

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  Constant    *ZeroLabel = ConstantInt::get(Int32Ty, 0);
  Constant    *ZeroCtx = ConstantInt::get(Int32Ty, 0); /* context: always 0 */

#if LLVM_MAJOR >= 20
  PointerType *PtrTy = PointerType::getUnqual(C);
#else
  PointerType *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  /* Per-function Value -> label map. Only ever grows via instructions
     collected below, in a single forward walk over the function's
     instructions in layout order -- see the "known limitation" note in the
     file header regarding non-straight-line control flow. */
  DenseMap<Value *, Value *> Labels;

  /* Collect targets first, instrument second: avoids iterator invalidation
     from inserting new instructions while walking. Call sites are
     collected separately and processed (with erasure) after everything
     else, via instrumentCallSites. */
  std::vector<LoadInst *>       loads;
  std::vector<StoreInst *>      stores;
  std::vector<BinaryOperator *> binops;
  std::vector<CastInst *>       casts;
  std::vector<ICmpInst *>       icmps;
  std::vector<SwitchInst *>     switches;
  std::vector<CallInst *>       calls;
  std::vector<MemTransferInst *> memxfers;

  for (Instruction &I : instructions(F)) {

    if (auto *LI = dyn_cast<LoadInst>(&I)) {

      if (LI->getType()->isIntegerTy()) loads.push_back(LI);

    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {

      if (SI->getValueOperand()->getType()->isIntegerTy())
        stores.push_back(SI);

    } else if (auto *BO = dyn_cast<BinaryOperator>(&I)) {

      if (BO->getType()->isIntegerTy()) binops.push_back(BO);

    } else if (auto *CI = dyn_cast<CastInst>(&I)) {

      /* C's integer promotion rules insert a ZExt/SExt (occasionally Trunc)
         between practically every narrow-integer load and its use in a
         comparison or arithmetic. Without forwarding labels through these
         casts, almost no real comparison would ever see a non-zero label
         -- confirmed by testing. Pure forwarding, no new runtime call. */
      if (CI->getType()->isIntegerTy() &&
          CI->getOperand(0)->getType()->isIntegerTy())
        casts.push_back(CI);

    } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {

      Type *OpTy = IC->getOperand(0)->getType();
      if (OpTy->isIntegerTy()) icmps.push_back(IC);

    } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {

      if (SW->getCondition()->getType()->isIntegerTy() && SW->getNumCases() > 0)
        switches.push_back(SW);

    } else if (auto *MX = dyn_cast<MemTransferInst>(&I)) {

      /* Clang lowers source-level memcpy()/memmove() calls to these
         intrinsics in the overwhelming majority of cases, not to a real
         CallInst against a "memcpy"/"memmove" symbol -- confirmed by
         testing: without this, the __dtaint_memcpy/__dtaint_memmove
         wrappers below (matched via the CallInst branch) silently never
         fired. Instrumented in-place (a call inserted right after), not
         via call-site redirection, since MemTransferInst's fixed 4-arg
         intrinsic signature (dst, src, len, isvolatile) doesn't match
         either wrapper's signature. */
      memxfers.push_back(MX);

    } else if (auto *CB = dyn_cast<CallInst>(&I)) {

      if (Function *Callee = CB->getCalledFunction())
        if (findCallRule(Callee->getName())) calls.push_back(CB);

    }

  }

  if (loads.empty() && stores.empty() && binops.empty() && casts.empty() &&
      icmps.empty() && switches.empty() && calls.empty() && memxfers.empty())
    return false;

  DenseSet<Instruction *> wanted;
  for (auto *I : loads) wanted.insert(I);
  for (auto *I : stores) wanted.insert(I);
  for (auto *I : binops) wanted.insert(I);
  for (auto *I : casts) wanted.insert(I);
  for (auto *I : icmps) wanted.insert(I);
  for (auto *I : switches) wanted.insert(I);
  for (auto *I : memxfers) wanted.insert(I);

  for (Instruction &I : instructions(F)) {

    if (!wanted.count(&I)) continue;

    if (auto *LI = dyn_cast<LoadInst>(&I)) {

      IRBuilder<> Builder(LI->getNextNode());
      Value      *PtrCast = Builder.CreateBitOrPointerCast(
          LI->getPointerOperand(), PtrTy);
      uint64_t Size = DL.getTypeStoreSize(LI->getType()).getFixedValue();
      Value   *Label = Builder.CreateCall(
          H.Load, {PtrCast, ConstantInt::get(Int64Ty, Size)});
      Labels[LI] = Label;

    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {

      Value *ValueLabel = lookupLabel(Labels, SI->getValueOperand());
      if (!ValueLabel) continue; /* nothing tracked flows into this store */

      IRBuilder<> Builder(SI);
      Value      *PtrCast =
          Builder.CreateBitOrPointerCast(SI->getPointerOperand(), PtrTy);
      uint64_t Size =
          DL.getTypeStoreSize(SI->getValueOperand()->getType()).getFixedValue();
      Builder.CreateCall(
          H.Store, {PtrCast, ConstantInt::get(Int64Ty, Size), ValueLabel});

    } else if (auto *BO = dyn_cast<BinaryOperator>(&I)) {

      Value *L1 = lookupLabel(Labels, BO->getOperand(0));
      Value *L2 = lookupLabel(Labels, BO->getOperand(1));
      if (!L1 && !L2) continue; /* neither operand tracked -- skip */

      IRBuilder<> Builder(BO->getNextNode());

      if (binopIsSigned(BO))
        Builder.CreateCall(H.MarkSigned, {L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});

      /* `x & <constant>` masking -- mirrors DFSanPass::combineShadows's
         Instruction::And special case: mark the *non-constant* operand's
         own label (not the combine result) as and-masked, so find() can
         later split its segment shape to reflect only the masked bits
         really being "one variable". */
      if (BO->getOpcode() == Instruction::And && BO->getNumOperands() == 2) {

        Value *Arg1 = BO->getOperand(0);
        Value *Arg2 = BO->getOperand(1);

        if (isa<ConstantInt>(Arg1) && L2)
          Builder.CreateCall(H.CombineAnd, {L2});
        else if (isa<ConstantInt>(Arg2) && L1)
          Builder.CreateCall(H.CombineAnd, {L1});

      }

      Value *Label = Builder.CreateCall(
          H.Combine, {L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});
      Labels[BO] = Label;

    } else if (auto *CI = dyn_cast<CastInst>(&I)) {

      Value *SrcLabel = lookupLabel(Labels, CI->getOperand(0));
      if (SrcLabel) Labels[CI] = SrcLabel;

    } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {

      Value *L1 = lookupLabel(Labels, IC->getOperand(0));
      Value *L2 = lookupLabel(Labels, IC->getOperand(1));
      if (!L1 && !L2) continue; /* neither operand tracked -- skip */

      IRBuilder<> Builder(IC->getNextNode());
      Type       *OpTy = IC->getOperand(0)->getType();
      uint32_t    bits = OpTy->getIntegerBitWidth();

      if (IC->isSigned())
        Builder.CreateCall(H.MarkSigned, {L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});

      /* Compile-time sign inference: a negative constant on the RHS marks
         the predicate signed even if the icmp predicate itself is
         unsigned (mirrors AngoraPass.cc's processCmp checking
         OpArg[1]). */
      uint32_t predicate = static_cast<uint32_t>(IC->getPredicate());
      if (auto *CInt = dyn_cast<ConstantInt>(IC->getOperand(1)))
        if (CInt->isNegative()) predicate |= kCondSignMask;

      Value *Arg1 = Builder.CreateZExtOrTrunc(IC->getOperand(0), Int64Ty);
      Value *Arg2 = Builder.CreateZExtOrTrunc(IC->getOperand(1), Int64Ty);
      Value *Cond = Builder.CreateZExt(IC, Int32Ty);

      Builder.CreateCall(
          H.TraceCmp,
          {ConstantInt::get(Int32Ty, cmpid++), ZeroCtx,
           ConstantInt::get(Int32Ty, predicate),
           ConstantInt::get(Int32Ty, bits), Arg1, Arg2, Cond,
           L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});

    } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {

      Value *CondLabel = lookupLabel(Labels, SW->getCondition());
      if (!CondLabel) continue;

      IRBuilder<> Builder(SW);
      Type       *CondTy = SW->getCondition()->getType();
      uint32_t    bits = CondTy->getIntegerBitWidth();
      Value      *MatchedVal = Builder.CreateZExtOrTrunc(SW->getCondition(), Int64Ty);

      std::vector<Constant *> CaseVals;
      for (auto CaseIt : SW->cases())
        CaseVals.push_back(ConstantInt::get(
            Int64Ty, CaseIt.getCaseValue()->getZExtValue()));

      ArrayType *ArrTy = ArrayType::get(Int64Ty, CaseVals.size());
      Constant  *ArrConst = ConstantArray::get(ArrTy, CaseVals);
      auto      *GV = new GlobalVariable(M, ArrTy, /*isConstant=*/true,
                                         GlobalValue::PrivateLinkage, ArrConst,
                                         "dtaint.switch.cases");
      Value *ArrPtr = Builder.CreateBitOrPointerCast(GV, PtrTy);

      Builder.CreateCall(
          H.TraceSwitch,
          {ConstantInt::get(Int32Ty, cmpid++), ZeroCtx,
           ConstantInt::get(Int32Ty, bits), MatchedVal,
           ConstantInt::get(Int32Ty, (uint32_t)CaseVals.size()), ArrPtr,
           CondLabel});

    } else if (auto *MX = dyn_cast<MemTransferInst>(&I)) {

      IRBuilder<> Builder(MX->getNextNode());
      Value      *DstCast = Builder.CreateBitOrPointerCast(MX->getRawDest(), PtrTy);
      Value      *SrcCast = Builder.CreateBitOrPointerCast(MX->getRawSource(), PtrTy);
      Value      *Len = Builder.CreateZExtOrTrunc(MX->getLength(), Int64Ty);

      Builder.CreateCall(H.PropagateMem, {DstCast, SrcCast, Len});

    }

  }

  if (!calls.empty()) instrumentCallSites(M, C, calls, cmpid);

  return true;

}

void AFLDTaint::instrumentCallSites(Module &M, LLVMContext &C,
                                    const std::vector<CallInst *> &Calls,
                                    uint32_t &cmpid) {

  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  for (CallInst *Caller : Calls) {

    Function *Callee = Caller->getCalledFunction();
    if (!Callee) continue;

    const DtaintCallRule *Rule = findCallRule(Callee->getName());
    if (!Rule) continue;

    if (Rule->kind != DtaintCallKind::CmpFn) {

      /* Source/propagate wrappers keep the exact same signature as the
         function they replace -- a plain callee swap, no argument list
         changes, so all existing uses/attributes of the call stay valid
         untouched. */
      FunctionCallee Wrapper =
          M.getOrInsertFunction(Rule->wrapper, Callee->getFunctionType());
      Caller->setCalledOperand(Wrapper.getCallee());

    } else {

      /* cmpfn wrappers need an extra leading cmpid argument (they must
         identify themselves to __dtaint_trace_fn), so this builds a new
         call rather than swapping the callee in place. */
      FunctionType         *OrigFT = Callee->getFunctionType();
      std::vector<Type *>   NewParams;
      NewParams.push_back(Int32Ty);
      for (Type *T : OrigFT->params()) NewParams.push_back(T);

      FunctionType  *NewFT =
          FunctionType::get(OrigFT->getReturnType(), NewParams, false);
      FunctionCallee Wrapper = M.getOrInsertFunction(Rule->wrapper, NewFT);

      std::vector<Value *> NewArgs;
      NewArgs.push_back(ConstantInt::get(Int32Ty, cmpid++));
      for (Value *A : Caller->args()) NewArgs.push_back(A);

      IRBuilder<> Builder(Caller);
      CallInst   *NewCall = Builder.CreateCall(Wrapper, NewArgs);
      Caller->replaceAllUsesWith(NewCall);
      Caller->eraseFromParent();

    }

  }

}

PreservedAnalyses AFLDTaint::run(Module &M, ModuleAnalysisManager &MAM) {

  LLVMContext      &C = M.getContext();
  const DataLayout &DL = M.getDataLayout();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
#if LLVM_MAJOR >= 20
  PointerType *PtrTy = PointerType::getUnqual(C);
#else
  PointerType *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  Hooks H;

  /* u32 __dtaint_load(void *ptr, u64 size) */
  H.Load = M.getOrInsertFunction("__dtaint_load", Int32Ty, PtrTy, Int64Ty);

  /* void __dtaint_store(void *ptr, u64 size, u32 label) */
  H.Store = M.getOrInsertFunction("__dtaint_store", VoidTy, PtrTy, Int64Ty, Int32Ty);

  /* u32 __dtaint_combine(u32 l1, u32 l2) */
  H.Combine = M.getOrInsertFunction("__dtaint_combine", Int32Ty, Int32Ty, Int32Ty);

  /* void __dtaint_mark_signed(u32 lb1, u32 lb2) */
  H.MarkSigned = M.getOrInsertFunction("__dtaint_mark_signed", VoidTy, Int32Ty, Int32Ty);

  /* void __dtaint_combine_and(u32 lb) */
  H.CombineAnd = M.getOrInsertFunction("__dtaint_combine_and", VoidTy, Int32Ty);

  /* void __dtaint_trace_cmp(u32 cmpid, u32 context, u32 op, u32 size,
                              u64 arg1, u64 arg2, u32 cond, u32 l1, u32 l2) */
  H.TraceCmp = M.getOrInsertFunction(
      "__dtaint_trace_cmp", VoidTy, Int32Ty, Int32Ty, Int32Ty, Int32Ty,
      Int64Ty, Int64Ty, Int32Ty, Int32Ty, Int32Ty);

  /* void __dtaint_trace_switch(u32 cmpid, u32 context, u32 size,
                                 u64 matched_value, u32 num,
                                 const u64 *cases, u32 lb) */
  H.TraceSwitch = M.getOrInsertFunction(
      "__dtaint_trace_switch", VoidTy, Int32Ty, Int32Ty, Int32Ty, Int64Ty,
      Int32Ty, PtrTy, Int32Ty);

  /* void __dtaint_propagate_mem(const void *dst, const void *src, u64 len) */
  H.PropagateMem = M.getOrInsertFunction(
      "__dtaint_propagate_mem", VoidTy, PtrTy, PtrTy, Int64Ty);

  if (getenv("AFL_QUIET") == NULL)
    printf("Running afl-llvm-dtaint-pass (Angora-parity taint tracking)\n");

  uint32_t cmpid = 1;
  bool     changed = false;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    changed |= instrumentFunction(M, F, DL, C, H, cmpid);

  }

  if (changed) verifyModule(M);

  return changed ? PreservedAnalyses() : PreservedAnalyses::all();

}
