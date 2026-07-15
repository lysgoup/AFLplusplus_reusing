# Dynamic taint tracking (dtaint) -- minimal validation slice

This is a minimal, DFSan-style dynamic taint tracking pass ported from the
[Angora fuzzer](https://github.com/AngoraFuzzer/Angora), scoped down to
validate the core mechanism only: proving that input byte offsets can be
tracked through load/store/arithmetic and recorded at comparison sites, in
AFL++'s build/runtime model.

**This is not (yet) a usable fuzzing feature.** Nothing here reads the
resulting data back into a mutation strategy -- see "Out of scope" below. It
exists so a later phase can build the actual reuse-pool/mutation-guidance
logic (Angora's `label_pattern_tracker`-equivalent) on top of a validated
foundation, without also having to debug the propagation mechanism itself at
the same time.

## Why not just use CmpLog?

CmpLog already records comparison operand *values*, but it does not track
byte-level *provenance*: redqueen finds which input offsets "probably"
correspond to a compared value by searching the input buffer for a matching
byte pattern after the fact. That's a good heuristic for direct
input-to-state relationships, but it's not verified dataflow, and it doesn't
generalize to values derived through arithmetic/transformation the way real
taint propagation does. This pass tracks the actual dataflow instead, at the
cost of being considerably more invasive to instrument.

## Scope of this slice

In scope:
- `instrumentation/afl-llvm-dtaint-pass.so.cc`: instruments integer
  `Load`/`Store`/`BinaryOperator`/`ICmpInst` only (no floats, vectors,
  pointers, or aggregates).
- `dtaint_runtime/`: a runtime linked into the target binary implementing a
  minimal label combine-tree and a flat track-file writer (see
  `include/dtaint.h` for the wire format).
- `include/afl-fuzz.h` / `src/afl-fuzz.c` / `src/afl-fuzz-dtaint.c`: a
  second forkserver (`afl->dtaint_fsrv`), mirroring CmpLog's
  `afl->cmplog_fsrv` plumbing exactly, so a taint run can be triggered
  (`run_one_dtaint()`) and its output file inspected.

Explicitly out of scope (future work, not attempted here):
- ABI-list / library-call modeling (`read`/`memcpy`/`strcmp`/`malloc` as
  taint sources or propagation rules). Taint sources in this slice are seeded
  by the target program itself calling `dtaint_source_buf(ptr, len)`
  explicitly, right after loading its input -- there is no automatic
  interception of I/O calls yet.
- Real shadow *memory* (page-remapped address translation). Loads/stores are
  instead routed through runtime hook calls backed by a simple fixed-size,
  direct-mapped, address-hashed lookup table -- correctness-first, not
  performance-first, and known to have collision risk across unrelated live
  allocations in a long-running session.
- Heap tracking (realloc size bookkeeping), length-derived comparisons, and
  the interval-tree/shape-inference sophistication of Angora's real label
  representation (`tag_set.rs`).
- Any consumer that reads the track file back into a mutation strategy
  (Angora's reuse pool, or anything else).

## Build

Requires LLVM 14-21 (this pass is new-PM only, like CmpLog).

**Verified working** against a real toolchain (Ubuntu 24.04 container, LLVM/Clang
18.1.3, `afl-clang-fast`/new-PM plugin pass) -- a full clean build (`make` +
`make -C dtaint_runtime`) succeeds, and `test/test-dtaint.sh` passes its
automated assertion end-to-end. See "Known risks" below for the three real
bugs this verification pass caught and fixed.

```
make               # builds afl-fuzz, afl-cc, etc.
make -C dtaint_runtime
AFL_LLVM_DTAINT=1 AFL_DONT_OPTIMIZE=1 \
    ./afl-clang-fast -o test-dtaint test/test-dtaint.c dtaint_runtime/libdtaint-rt.a
```

`AFL_DONT_OPTIMIZE=1` matters here: the pass registers at LLVM's
`PipelineStart` extension point (before `mem2reg`/SROA) specifically so the
original `alloca`+`Load`+`Store` for a stack input buffer still exist when it
runs. Building at `-O1` and above has not been tested and should be treated
as unsupported until someone checks it.

## Test

`test/test-dtaint.c` + `test/test-dtaint.sh` exercise all four instrumented
instruction categories (plain comparisons, a multi-byte load combined via
`Or`/`Shl`, an `Add` feeding a comparison) against a 6-byte input, and assert
that the track file's last four records' reconstructed byte offsets exactly
match `{0}`, `{1}`, `{2,3}`, `{4,5}` (cmpid values themselves aren't part of
the contract -- they number every instrumented comparison in the harness,
including a few unrelated `argc`/`fd`/`n` checks that run before
`dtaint_source_buf`, so the script asserts on offsets/order, not literal
cmpid). This has been run and passes.

The forkserver wiring (Piece 3) was additionally verified with a real
`afl-fuzz` run: built a persistent instrumented binary with
`AFL_LLVM_DTAINT=1`, set `AFL_DTAINT_BINARY`, and confirmed a clean startup
("Spawning dtaint forkserver" / "Dtaint forkserver successfully started")
followed by a normal fuzzing session with corpus growth and zero
crashes/errors.

The runtime (`dtaint_runtime/dtaint-rt.c`) was also validated standalone
(calling its API directly with literal arguments, no compiler pass involved)
before the pass was even written; that exercise caught bug #1 below.

## Known risks carried into future work

1. **Pass EP placement vs. mem2reg/SROA** is the single highest-risk item in
   Piece 1 -- get it wrong and the pass silently instruments nothing for
   realistic (non `-O0`) builds. `instrumentation/afl-c11-pass.so.cc`
   registers at the same `PipelineStart` EP for the identical reason (see its
   comment) and was used as the concrete precedent for this pass's
   registration. Verified correct against LLVM 18.
2. In-memory-only track-file buffering and the fixed-size shadow table are
   deliberate, documented scale cutoffs for this slice, not general
   solutions -- revisit before pointing this at a real (non-toy) target.
3. Three real bugs were found and fixed during the LLVM-18 verification pass,
   worth knowing about if similar symptoms recur after future changes:
   - **Shadow-table address-hash collision**: `shadow_slot()` originally
     shifted the pointer by 2 bits before masking, silently colliding every 4
     consecutive byte addresses onto the same slot (symptom: adjacent bytes
     reporting identical labels). Fixed by using byte-granularity addressing
     (no shift) -- see the comment at `dtaint_runtime/dtaint-rt.c`'s
     `shadow_slot()`.
   - **Pre-LLVM20 pointer API**: `PointerType::getInt8PtrTy()` was removed
     from LLVM's API; this pass now branches on `LLVM_MAJOR` and uses
     `PointerType::get(Int8Ty, 0)` below LLVM 20, `PointerType::getUnqual(C)`
     at/above it (same pattern `afl-c11-pass.so.cc` uses).
   - **Missing label propagation through integer-promotion casts** (the most
     consequential of the three): C implicitly inserts `ZExtInst`/`SExtInst`
     before most comparisons and arithmetic on narrow integer types (e.g.
     `unsigned char buf[0] == 'A'` actually compiles to a `zext i8 to i32`
     feeding the `icmp`). The pass originally only recorded labels for the
     raw `LoadInst`/`BinaryOperator`/`ICmpInst` results, not `CastInst`
     results, so essentially no real-world comparison ever got instrumented
     -- confirmed by dumping `.ll` IR and observing zero `__dtaint_combine`
     calls for the test harness's actual target comparisons. Fixed by adding
     a `CastInst` worklist that purely forwards the source operand's label
     to the cast result (no new runtime call needed). Any future change to
     this pass's instruction-selection logic should keep this in mind --
     forgetting to forward through casts silently breaks nearly everything.
