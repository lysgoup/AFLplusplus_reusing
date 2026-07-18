# Dynamic taint tracking (dtaint) -- Angora-parity taint info

This is a DFSan-style dynamic taint tracking pass ported from the
[Angora fuzzer](https://github.com/AngoraFuzzer/Angora). It captures the
*same taint information* Angora's own `.taint` runtime captures: per-byte
provenance through load/store/arithmetic/library calls, tracked via the same
range-compressed label-tree representation Angora uses (`tag_set.rs`), and
recorded at every comparison site (icmp, switch, and strcmp/memcmp-family
"cmpfn" calls) -- not just a proof-of-concept slice anymore.

**This is not (yet) a usable fuzzing feature.** Nothing here reads the
resulting data back into a mutation strategy -- that's explicitly out of
scope (see below), by the user's own direction: get the *information*
capture to Angora parity first, without touching AFL++'s actual fuzzing
loop/mutation strategy yet.

## Why not just use CmpLog?

CmpLog already records comparison operand *values*, but it does not track
byte-level *provenance*: redqueen finds which input offsets "probably"
correspond to a compared value by searching the input buffer for a matching
byte pattern after the fact. That's a good heuristic for direct
input-to-state relationships, but it's not verified dataflow, and it doesn't
generalize to values derived through arithmetic/transformation the way real
taint propagation does. This pass tracks the actual dataflow instead, at the
cost of being considerably more invasive to instrument.

## Scope

In scope, and verified working against real LLVM 18 (see "Build"/"Test"):

- **Label representation**: `dtaint_runtime/dtaint_tagset.c` is a faithful
  port of `runtime/src/tag_set.rs` -- the same range-compressed binary-trie
  label tree Angora uses (not a naive per-byte combine-tree), including
  shape inference for multi-byte loads (`combine_n(..., infer=true)`),
  `infer_shape2` for arithmetic contexts, sign marking, and `&`-mask segment
  splitting (`combine_and`/`split_and_op`).
- **Track-file format**: `include/dtaint.h`'s `struct dtaint_cond_record`
  mirrors `common/src/cond_stmt_base::CondStmtBase` field-for-field
  (`cmpid, context, order, belong, condition, level, op, size, lb1, lb2,
  arg1, arg2`). Labels are dedup'd into a separate `tags` table (label id ->
  resolved `TagSeg` list), and `magic_bytes` captures raw buffer snapshots
  at cmpfn sites -- both mirror `common/src/log_data::LogData` exactly
  (`dtaint_runtime/dtaint_logger.c` ports `runtime/src/logger.rs`, including
  the per-(cmpid) `order` bookkeeping and the `MAX_COND_ORDER` repeated-hit
  cutoff).
- **Comparison sites**: `ICmpInst` (op = LLVM's own `CmpInst::Predicate`,
  numerically identical to Angora's `COND_ICMP_*_OP` constants; sign-mask
  inference for negative compile-time constants and signed predicates,
  mirroring `AngoraPass.cc::processCmp`), `SwitchInst` (one record per case,
  `COND_SW_OP`, mirroring `visitSwitchInst`), and `strcmp`/`strncmp`/
  `memcmp`/`strcasecmp`/`strncasecmp` (`COND_FN_OP` + magic bytes, mirroring
  the `cmpfn` category in `llvm_mode/rules/exploitation_list.txt`).
- **ABI-list library call modeling**: sources (`read`/`fread`/`fgets`/
  `pread`, ported from `llvm_mode/external_lib/io_func.c`, using
  `lseek`/`ftell` to recover real file-position offsets) and propagators
  (`memcpy`/`memmove`/`strcpy`/`strncpy`/`strcat`). See "ABI list mechanism"
  below for how this differs structurally from Angora's real DFSan custom-
  function ABI.
- **Length labels**: `dtaint_runtime/dtaint_len_label.c` ports
  `runtime/src/len_label.rs`'s fat-label bit-packing exactly (a length
  sub-label id packed into the label's upper bits, `COND_LEN_OP` sidecar
  records). **The mechanism is implemented and unit-correct, but not yet
  wired to a real call site** -- see "Known gaps" below.
- **Core wiring**: `include/afl-fuzz.h` / `src/afl-fuzz.c` /
  `src/afl-fuzz-dtaint.c`: a second forkserver (`afl->dtaint_fsrv`),
  mirroring CmpLog's `afl->cmplog_fsrv` plumbing exactly, so a taint run can
  be triggered (`run_one_dtaint()`) and its output file inspected.

Explicitly out of scope (by design, not this phase's job):

- **Any consumer that reads the track file back into a mutation strategy**
  (Angora's reuse pool, or anything else) -- this phase is information
  capture only, by explicit instruction.
- Real shadow *memory* (page-remapped address translation). Loads/stores are
  instead routed through runtime hook calls backed by a simple fixed-size,
  direct-mapped, address-hashed lookup table -- correctness-first, not
  performance-first, with collision risk across unrelated live allocations
  in a long-running session.
- Function-call context-sensitivity (Angora's opt-in `-c` feature, off by
  default). `context` is always the constant `0` in this port -- exactly
  what real Angora does with the feature disabled, not an approximation of
  a feature that exists here.
- Heap tracking (`realloc` size bookkeeping).
- The full breadth of Angora's real ABI list (`stat`/`mmap`/`strtol`-family/
  `getline`/`getutxent`/etc., and no `open`/`fopen`-based fd-allowlisting --
  see "ABI list mechanism"). C++ `std::string` comparison operators
  (`exploitation_list.txt`'s mangled-name entries) are also not modeled.
- `cmpid` is a per-build monotonic counter (assigned during the pass's IR
  walk), not Angora's location-hash -- deterministic per build, not stable
  across recompiles.

## ABI list mechanism (how this differs from Angora's real DFSan ABI)

Angora's DFSan build makes the *linker* redirect e.g. every `read` symbol
reference to `__dfsw_read` (DFSan's custom-function ABI, which also passes
hidden per-argument label values). This port has the LLVM pass redirect
matching call sites directly to identically-signatured wrapper functions
instead (`instrumentCallSites` in the pass; `dtaint_runtime/dtaint_abi.c`'s
`__dtaint_read`/`__dtaint_memcpy`/etc.) -- no hidden ABI, no linker tricks,
just call-target substitution (source/propagate wrappers keep the exact same
signature and get a plain callee swap; cmpfn wrappers need an extra leading
`cmpid` argument, so those get a whole new call built in their place).

Two real, deliberate differences from Angora's behavior, not oversights:

- **No "is this fd the fuzzing input file" allowlist.** Angora's
  `io_func.c` only taints reads from a specifically-tracked fd/`FILE*`
  (populated by also intercepting `open`/`fopen` and checking the path
  against a magic marker). This port taints **every** read through these
  wrappers unconditionally. Simpler, and for AFL++'s usual single-input-
  stream harnesses not meaningfully less accurate; would over-taint
  incidental file reads (config files, shared library loads, etc.) in a
  more complex target.
- **`memcpy`/`memmove` are usually instrumented as LLVM intrinsics, not
  call-site redirection.** Confirmed by testing: clang lowers a plain
  source-level `memcpy()`/`memmove()` call to `llvm.memcpy.*`/
  `llvm.memmove.*` in the overwhelming majority of cases, not a real
  `CallInst` against a `memcpy`/`memmove` symbol -- the call-site-redirected
  `__dtaint_memcpy`/`__dtaint_memmove` wrappers only fire for the rare case
  where the call survives as a real indirect-callable symbol. The pass
  additionally instruments `MemTransferInst` (the common base of the
  `llvm.memcpy`/`llvm.memmove` intrinsics) directly, inserting a call to
  `__dtaint_propagate_mem` right after -- this is the path that actually
  fires for ordinary source code. Found and fixed during this phase's
  verification; see "Known gaps".

## Build

Requires LLVM 14-21 (this pass is new-PM only, like CmpLog).

**Verified working** against a real toolchain (Ubuntu 24.04 container,
LLVM/Clang 18.1.3, `afl-clang-fast`/new-PM plugin pass) -- a full clean
build (`make` + `make -C dtaint_runtime`) succeeds, and `test/test-dtaint.sh`
passes its automated assertions end-to-end, including a real `afl-fuzz` run
against the dtaint-instrumented binary (clean forkserver startup, corpus
growth, zero crashes/errors).

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

`test/test-dtaint.c` reads its input via a plain `read()` call (auto-tainted
via the ABI-list source wrapper -- no explicit `dtaint_source_buf` call
needed, unlike the original slice) and exercises: two plain `ICmpInst`
comparisons, a multi-byte value built via `Or`/`Shl` (`BinaryOperator`
combine), an `Add` feeding a comparison, a `switch` statement, and a
`memcpy` (intrinsic-propagated) into a local buffer compared via `strcmp`
(cmpfn, with magic-bytes capture). `test/test-dtaint.sh` asserts the
reconstructed byte-offset ranges for all six sites, the switch's per-case
`DONE_ST`/`FALSE_ST` outcomes and `order` encoding, and the cmpfn record's
magic-bytes snapshot -- all pass.

The forkserver wiring (Piece 3) was additionally verified with a real
`afl-fuzz` run: built a persistent instrumented binary with
`AFL_LLVM_DTAINT=1`, set `AFL_DTAINT_BINARY`, and confirmed a clean startup
("Spawning dtaint forkserver" / "Dtaint forkserver successfully started")
followed by a normal fuzzing session with corpus growth and zero
crashes/errors -- unaffected by this phase's much larger runtime.

## Known gaps (honest, not yet done)

- **`len_label` is implemented but not wired to any real call site.** The
  bit-packing mechanism (`dtaint_len_label.c`) and its extraction path in
  `dtaint_logger.c` (`COND_LEN_OP` sidecar records) are ported faithfully
  and would work if something tagged a return value with a length label --
  but the ABI-list source wrappers (`__dtaint_read` etc.) don't currently do
  that (they taint the *output buffer* per-byte, matching Angora, but don't
  additionally tag the *return value* the way Angora's real
  `__dfsw_read`/`__angora_get_sp_label` does). Wiring this up requires
  treating call return values as label-producing sites in the pass's SSA
  tracking (currently only `Load`/`BinaryOperator`/`CastInst` populate the
  `Labels` map) -- a real, scoped-out piece of follow-up work, not a bug.
- Only a documented subset of Angora's real ABI list is modeled (see
  "Scope" above) -- extending it is mechanical (add a `DtaintCallRule` entry
  + a matching wrapper in `dtaint_abi.c`), not architecturally blocked.

## Known risks / bugs found during verification

1. **Pass EP placement vs. mem2reg/SROA** is the single highest-risk item --
   get it wrong and the pass silently instruments nothing for realistic
   (non `-O0`) builds. `instrumentation/afl-c11-pass.so.cc` registers at the
   same `PipelineStart` EP for the identical reason (see its comment) and
   was the concrete precedent for this pass's registration. Verified
   correct against LLVM 18.
2. In-memory-only track-file buffering and the fixed-size shadow table are
   deliberate, documented scale cutoffs, not general solutions -- revisit
   before pointing this at a real (non-toy) target.
3. Bugs found and fixed while building/verifying the original minimal slice:
   - **Shadow-table address-hash collision**: `shadow_slot()` originally
     shifted the pointer by 2 bits before masking, silently colliding every
     4 consecutive byte addresses onto the same slot. Fixed by using
     byte-granularity addressing (no shift).
   - **Pre-LLVM20 pointer API**: `PointerType::getInt8PtrTy()` was removed
     from LLVM's API; this pass branches on `LLVM_MAJOR` and uses
     `PointerType::get(Int8Ty, 0)` below LLVM 20, `PointerType::getUnqual(C)`
     at/above it (same pattern `afl-c11-pass.so.cc` uses).
   - **Missing label propagation through integer-promotion casts**: C
     implicitly inserts `ZExtInst`/`SExtInst` before most comparisons and
     arithmetic on narrow integer types. Fixed by forwarding labels through
     `CastInst` (no new runtime call needed, pure map-forwarding).
4. Bug found and fixed while building/verifying this (Piece 4) phase:
   - **`memcpy`/`memmove` calls silently never propagated taint**: as
     described in "ABI list mechanism" above, clang lowers these to LLVM
     intrinsics, not real `CallInst`s, so the call-site-redirection
     mechanism (correct for `read`/`strcmp`/etc.) never matched them. Fixed
     by adding direct `MemTransferInst` instrumentation. Confirmed via `.ll`
     IR inspection (`grep memcpy` showed only the intrinsic form) and via
     the end-to-end test (the `strcmp` cmpfn record was silently missing
     magic bytes until this was fixed, since its input depended on the
     `memcpy`'s propagation having worked).
