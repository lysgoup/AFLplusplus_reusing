/*
   american fuzzy lop++ - minimal dynamic taint tracking LLVM pass
   -----------------------------------------------------------------

   Ported from the Angora fuzzer (llvm_mode/pass/DFSanPass.cc) as a
   validation slice -- see include/dtaint.h and the scoping plan this was
   built from for full context.

   Deliberate simplifications versus a real DFSan-style pass (all
   documented in the plan, not oversights):

     - No real shadow *memory* (page-remapped address translation). Every
       Load/Store is instead instrumented to call into a runtime hook
       (__dtaint_load/__dtaint_store) backed by a simple address-keyed
       lookup table -- correctness-first, not performance-first.
     - No ABI list / library-call modeling: taint sources are seeded by the
       target program itself calling dtaint_source_buf() once, explicitly,
       right after loading its input -- there is no automatic interception
       of read()/fread()/etc. in this slice.
     - Only integer Load/Store/BinaryOperator/ICmpInst are instrumented;
       floats, vectors, pointers, and aggregates are skipped entirely.
     - Label propagation through SSA values is tracked by the pass itself
       (a Value* -> Value* map from each instrumented instruction to its
       runtime-hook-computed label), not by the target's real memory being
       shadowed -- this only works correctly for straight-line/structured
       control flow where definitions are visited before uses in IR layout
       order, which is true for the validation test program this was built
       against, but is a known limitation for arbitrary control flow.

   IMPORTANT, unresolved without a machine that has LLVM 14-21 installed to
   test against (this development environment has neither clang nor
   llvm-config): this pass registers at PB.registerPipelineStartEPCallback
   (not OptimizerLast/Early, where CmpLog and AFL++'s own coverage pass
   register) specifically so it runs *before* LLVM's function-simplification
   pipeline (SROA + mem2reg), which at -O1+ can eliminate the original
   alloca+Load+Store for a stack buffer before a later-registered pass ever
   sees it. Build with AFL_DONT_OPTIMIZE=1 for this validation slice as a
   second safety margin. See the plan's "Known risks" section.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

*/

#include <cstdint>

#include "llvm/Config/llvm-config.h"
#ifndef LLVM_MAJOR
  #define LLVM_MAJOR LLVM_VERSION_MAJOR
#endif
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
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
   supplies real storage for its `be_quiet`/`debug` globals. Since this
   pass's build rule links instrumentation/afl-llvm-common.o (which only
   ever sees `extern int be_quiet;`), omitting this include left those
   symbols undefined at plugin-load time -- confirmed by testing. */
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class AFLDTaint : public PassInfoMixin<AFLDTaint> {

 public:
  AFLDTaint() {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  bool instrumentFunction(Function &F, const DataLayout &DL, LLVMContext &C,
                           FunctionCallee LoadHook, FunctionCallee StoreHook,
                           FunctionCallee CombineHook, FunctionCallee TraceCmpHook,
                           uint32_t &cmpid);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "afldtaint", "v0.1",
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

bool AFLDTaint::instrumentFunction(Function &F, const DataLayout &DL,
                                   LLVMContext &C, FunctionCallee LoadHook,
                                   FunctionCallee StoreHook,
                                   FunctionCallee CombineHook,
                                   FunctionCallee TraceCmpHook,
                                   uint32_t &cmpid) {

  if (F.isDeclaration()) return false;

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  Constant    *ZeroLabel = ConstantInt::get(Int32Ty, 0);

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
     from inserting new instructions while walking, and (as a side effect)
     means our own inserted CallInsts are never in these worklists, so
     there's no risk of re-instrumenting them. */
  std::vector<LoadInst *>       loads;
  std::vector<StoreInst *>      stores;
  std::vector<BinaryOperator *> binops;
  std::vector<CastInst *>       casts;
  std::vector<ICmpInst *>       icmps;

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
         comparison or arithmetic -- e.g. `unsigned char buf[i] == 'A'`
         actually compares a zext-to-i32'd value, not the raw i8 load.
         Without forwarding labels through these casts, almost no real
         comparison would ever see a non-zero label. Confirmed by testing:
         omitting this caused every comparison in the validation test
         program to silently go uninstrumented. This only *forwards* an
         existing label (no new runtime call -- a cast doesn't combine
         anything), so it's cheap and doesn't need a worklist-independent
         hook the way loads/stores/binops/icmps do. */
      if (CI->getType()->isIntegerTy() &&
          CI->getOperand(0)->getType()->isIntegerTy())
        casts.push_back(CI);

    } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {

      Type *OpTy = IC->getOperand(0)->getType();
      if (OpTy->isIntegerTy()) icmps.push_back(IC);

    }

  }

  if (loads.empty() && stores.empty() && binops.empty() && casts.empty() &&
      icmps.empty())
    return false;

  /* Loads, stores, binops, casts, and icmps can all reference each other (a
     load feeds a cast feeds a binop feeds an icmp), so instrument in a
     single walk over the function's original instruction *order* rather
     than per-worklist -- rebuild that order from the worklists' union,
     sorted by position via a second scan. Simplest correct approach for
     this slice: just re-walk `instructions(F)` once more and dispatch by
     dyn_cast, using the worklists above only as the "should I touch this"
     filter (a std::set-backed membership check would be cleaner; a
     DenseSet is used here to keep it to one extra pass with O(1)
     lookups). */
  DenseSet<Instruction *> wanted;
  for (auto *I : loads) wanted.insert(I);
  for (auto *I : stores) wanted.insert(I);
  for (auto *I : binops) wanted.insert(I);
  for (auto *I : casts) wanted.insert(I);
  for (auto *I : icmps) wanted.insert(I);

  for (Instruction &I : instructions(F)) {

    if (!wanted.count(&I)) continue;

    if (auto *LI = dyn_cast<LoadInst>(&I)) {

      IRBuilder<> Builder(LI->getNextNode());
      Value      *PtrCast = Builder.CreateBitOrPointerCast(
          LI->getPointerOperand(), PtrTy);
      uint64_t Size = DL.getTypeStoreSize(LI->getType()).getFixedValue();
      Value   *Label = Builder.CreateCall(
          LoadHook, {PtrCast, ConstantInt::get(Int64Ty, Size)});
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
          StoreHook, {PtrCast, ConstantInt::get(Int64Ty, Size), ValueLabel});

    } else if (auto *BO = dyn_cast<BinaryOperator>(&I)) {

      Value *L1 = lookupLabel(Labels, BO->getOperand(0));
      Value *L2 = lookupLabel(Labels, BO->getOperand(1));
      if (!L1 && !L2) continue; /* neither operand tracked -- skip */

      IRBuilder<> Builder(BO->getNextNode());
      Value      *Label = Builder.CreateCall(
          CombineHook, {L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});
      Labels[BO] = Label;

    } else if (auto *CI = dyn_cast<CastInst>(&I)) {

      /* Pure forwarding, no runtime call: see the worklist-collection
         comment above for why this is needed at all. */
      Value *SrcLabel = lookupLabel(Labels, CI->getOperand(0));
      if (SrcLabel) Labels[CI] = SrcLabel;

    } else if (auto *IC = dyn_cast<ICmpInst>(&I)) {

      Value *L1 = lookupLabel(Labels, IC->getOperand(0));
      Value *L2 = lookupLabel(Labels, IC->getOperand(1));
      if (!L1 && !L2) continue; /* neither operand tracked -- skip */

      IRBuilder<> Builder(IC->getNextNode());
      Type       *OpTy = IC->getOperand(0)->getType();
      uint32_t    bits = OpTy->getIntegerBitWidth();

      Value *Arg1 = Builder.CreateZExtOrTrunc(IC->getOperand(0), Int64Ty);
      Value *Arg2 = Builder.CreateZExtOrTrunc(IC->getOperand(1), Int64Ty);
      Value *Cond = Builder.CreateZExt(IC, Int32Ty);

      Builder.CreateCall(
          TraceCmpHook,
          {ConstantInt::get(Int32Ty, cmpid++),
           ConstantInt::get(Int32Ty, static_cast<uint32_t>(IC->getPredicate())),
           ConstantInt::get(Int32Ty, bits), Arg1, Arg2, Cond,
           L1 ? L1 : ZeroLabel, L2 ? L2 : ZeroLabel});

    }

  }

  return true;

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

  /* u32 __dtaint_load(void *ptr, u64 size) */
  FunctionCallee LoadHook =
      M.getOrInsertFunction("__dtaint_load", Int32Ty, PtrTy, Int64Ty);

  /* void __dtaint_store(void *ptr, u64 size, u32 label) */
  FunctionCallee StoreHook = M.getOrInsertFunction(
      "__dtaint_store", VoidTy, PtrTy, Int64Ty, Int32Ty);

  /* u32 __dtaint_combine(u32 l1, u32 l2) */
  FunctionCallee CombineHook =
      M.getOrInsertFunction("__dtaint_combine", Int32Ty, Int32Ty, Int32Ty);

  /* void __dtaint_trace_cmp(u32 cmpid, u32 op, u32 size, u64 arg1, u64 arg2,
                              u32 cond, u32 l1, u32 l2) */
  FunctionCallee TraceCmpHook = M.getOrInsertFunction(
      "__dtaint_trace_cmp", VoidTy, Int32Ty, Int32Ty, Int32Ty, Int64Ty,
      Int64Ty, Int32Ty, Int32Ty, Int32Ty);

  if (getenv("AFL_QUIET") == NULL)
    printf("Running afl-llvm-dtaint-pass (minimal Angora-style taint slice)\n");

  uint32_t cmpid = 1;
  bool     changed = false;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    changed |= instrumentFunction(F, DL, C, LoadHook, StoreHook, CombineHook,
                                  TraceCmpHook, cmpid);

  }

  if (changed) verifyModule(M);

  return changed ? PreservedAnalyses() : PreservedAnalyses::all();

}
