# Real DFSan taint tracking (Angora-parity, byte-level accurate)

This directory vendors Angora's *actual* LLVM 11.1.0 DataFlowSanitizer fork
(`pass/DFSanPass.cc`, `pass/AngoraPass.cc`, `pass/UnfoldBranchPass.cc`,
`dfsan_rt/`) from `/home/yunseo/Angora_original`, unmodified except for
redirecting `dfsan_rt/dfsan/dfsan.cc`'s label-storage FFI calls from Angora's
Rust runtime to this repo's own C port (`dtaint_runtime/dtaint_tagset.c`,
already built and validated in the `angora-taint` branch's earlier,
from-scratch-pass phase).

## Why this exists alongside `instrumentation/afl-llvm-dtaint-pass.so.cc`

That earlier phase built a custom pass + runtime that *mimics* DFSan's
concepts without using real DFSan. Modern LLVM's actual DFSan (confirmed
empirically against LLVM 18: `dfsan_label` is `uint8_t`, `dfsan_union` is a
plain bitwise OR, no `dfsan_create_label` at all) cannot give per-input-byte
provenance -- only 8 concurrently distinguishable taint sources, ever. Real
byte-level accuracy (matching Angora exactly) requires the *old* DFSan
design (a wide, combine-tree label with real provenance), which upstream
LLVM removed after the era Angora itself is still pinned to (LLVM
4.0.0-12.0.1). This directory is that old design, vendored directly rather
than re-derived, with Angora's original Rust label storage swapped for this
repo's own C port.

Both implementations coexist; nothing here replaces the other one.

## What's here

- `pass/` -- Angora's actual `DFSanPass.cc`/`UnfoldBranchPass.cc`,
  byte-for-byte unmodified, confirmed to compile and run correctly
  against the real LLVM 11.1.0 release with **zero source changes** (see
  verification below). `AngoraPass.cc` carries one deliberate deviation:
  a cmpid -> source-location text log (`cmpid_log_file`, opened/closed in
  `runOnModule()`), ported from `/home/yunseo/Reusing_mut/llvm_mode/
  pass/AngoraPass.cc`'s own copy of this same pass, which already had it.
  See that file's own comments (search `cmpid_log_file`) for the exact
  diff; output path and `cmpid_track.txt`/`cmpid_fast.txt` naming match
  that copy's `ANGORA_PASS_LOG_DIR` convention.
- `dfsan_rt/` -- Angora's actual compiler-rt DFSan runtime fork, vendored
  unmodified except `dfsan/dfsan.cc`'s FFI redirection (see that file's own
  comments) and the length-label strip/reattach fixes described below.
- `runtime/io_func.c` -- Angora's actual ABI-list custom source functions
  (`__dfsw_read`/`_fread`/`_fgets`/etc.), unmodified except swapping
  `ffds.h`/`len_label.h` (Rust FFI headers) for `dtaint_legacy_compat.h`
  (a thin local stand-in -- see that file's own comment for the one
  deliberate behavior difference, matching the earlier phase's own
  documented simplification: no `is_fuzzing_fd` allowlist).
- `runtime/dtaint_legacy_hooks.c` -- new (not vendored): the
  `__dfsw___angora_trace_{cmp,switch,fn,exploit_val}_tt` implementations
  AngoraPass.cc's inserted calls resolve to via DFSan's real custom-function
  ABI, translated from `runtime/src/track.rs` (Angora's Rust side) into C,
  forwarding into the existing `dtaint_runtime/dtaint_logger.c` (same wire
  format as the other phase -- `include/dtaint.h` is unchanged).
- `rules/` -- Angora's actual abilist files (`angora_abilist.txt`,
  `dfsan_abilist.txt` (`= done_abilist.txt` + `libc_ubuntu1404_abilist.txt`,
  concatenated the same way Angora's own CMake does), `exploitation_list.txt`).
- `angora_dfsan_clang.sh` -- standalone wrapper mirroring
  `Angora_original/llvm_mode/compiler/angora_clang.c`'s `USE_TRACK` path
  (same `-Xclang -load` pass sequence, same runtime link recipe). Produces
  the executable to point `AFL_DTAINT_BINARY` at. Not integrated into
  `afl-cc.c` -- a separate build step, same relationship
  `test/test-dtaint.sh` has to the other phase's dtaint binary.
- `CMakeLists.txt` -- builds only `dfsan_rt/` (the compiler-rt tree
  genuinely benefits from its own proven CMake logic); `pass/` builds via
  plain `clang++` invocations (see `angora_dfsan_clang.sh`, simpler and
  already validated).

## Setup

Requires the actual LLVM 11.1.0 release (Angora's own pinned version),
fetched separately from the LLVM 14-21 toolchain the rest of AFL++ needs:

```
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
tar -xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz -C /opt
mv /opt/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04 /opt/clang+llvm-11
```

Build:

```
# 1. The three passes (plain clang++, no CMake needed):
cd dfsan_legacy
LLVM11=/opt/clang+llvm-11
for p in UnfoldBranchPass AngoraPass DFSanPass; do
  $LLVM11/bin/clang++ $($LLVM11/bin/llvm-config --cxxflags) -fno-rtti -fpic -shared \
    -I include -DLLVM_VERSION_MAJOR=11 -DLLVM_VERSION_MINOR=1 -DMAP_SIZE_POW2=23 \
    -Wl,-znodelete pass/$p.cc -o build_pass/lib$p.so $($LLVM11/bin/llvm-config --ldflags)
done

# 2. dfsan_rt (CMake, builds against LLVM11 as a plain C/C++ toolchain --
#    no LLVM_DIR needed, this compiler-rt tree is standalone):
mkdir -p build && cd build
cmake -DCMAKE_C_COMPILER=$LLVM11/bin/clang -DCMAKE_CXX_COMPILER=$LLVM11/bin/clang++ ..
make -j4
cd ..

# 3. Our own C runtime pieces + Angora's io_func.c:
for f in dtaint_tagset dtaint_logger dtaint_len_label; do
  $LLVM11/bin/clang -c -O2 -fPIC -I ../include -I ../dtaint_runtime \
    ../dtaint_runtime/$f.c -o build_rt/$f.o
done
$LLVM11/bin/clang -c -O2 -fPIC -I include -I ../include -I ../dtaint_runtime \
  -I dfsan_rt -I dfsan_rt/dfsan runtime/io_func.c -o build_rt/io_func.o
$LLVM11/bin/clang -c -O2 -fPIC -I include -I ../include -I ../dtaint_runtime \
  -I dfsan_rt -I dfsan_rt/dfsan runtime/dtaint_legacy_hooks.c -o build_rt/dtaint_legacy_hooks.o
llvm-ar rcs build_rt/libdtaint-legacy-rt.a build_rt/*.o

# 4. AFL's own forkserver stub, ALSO compiled with LLVM11 (needed so the
#    dtaint binary can participate in AFL_DTAINT_BINARY's forkserver
#    protocol -- see "Known risks" below):
$LLVM11/bin/clang -c -O0 -fPIC -Wno-unused-result -I ../include -I ../instrumentation \
  ../instrumentation/afl-compiler-rt.o.c -o build_rt/afl-compiler-rt-llvm11.o
```

Then build the taint binary itself:

```
DFSAN_LEGACY_LLVM_DIR=/opt/clang+llvm-11 ./angora_dfsan_clang.sh \
    -o mytarget.dtaint mytarget.c build_rt/afl-compiler-rt-llvm11.o
```

## Verified working (Docker, LLVM 11.1.0, this session)

1. All three vendored passes compile and run against the real, unmodified
   LLVM 11.1.0 release with **zero source changes** -- confirmed by
   dumping `.ll` IR and seeing genuine `dfs$`-wrapped functions and
   `angora_trace_cmp` calls.
2. Direct execution (no forkserver): reconstructed byte offsets for icmp,
   switch, and a `memcpy`-propagated `strcmp` (with magic-bytes capture)
   all matched expected values exactly, including a case with more than 8
   distinct tainted byte regions in one execution -- something LLVM 18's
   real (`fast8labels`) DFSan categorically cannot do.
3. Full `afl-fuzz` integration: `AFL_DTAINT_BINARY` pointed at this
   toolchain's output, main target built normally via `afl-clang-fast`
   (LLVM 18) -- confirmed real per-input `.dtaint` track files produced via
   the existing, unmodified `save_if_interesting()` trigger
   (`src/afl-fuzz-bitmap.c`).

## Known risks / real bugs found and fixed here

1. **`dtaint_tagset_init()` must not run from DFSan's `.preinit_array`
   constructor** -- confirmed by testing: `calloc()` isn't guaranteed safe
   that early in a dynamically-linked PIE binary's startup, and doing so
   led to a real SIGSEGV. Every `dtaint_tagset_*` entry point now lazily
   self-initializes instead.
2. **Length labels must be stripped before touching the tag tree, and
   reattached after combining** -- confirmed missing by a real SIGSEGV
   (`dtaint_tagset_infer_shape2` indexing its node array with a raw,
   unstripped fat-label value from a tainted `read()` return count).
   Angora's own `tag_set_wrap.rs` does this in every FFI function
   (`get_normal_label_usize`); this port had skipped it. Fixed in
   `dfsan_rt/dfsan/dfsan.cc` (`__dfsan_union`, `__dfsan_union_load`,
   `dfsan_read_label`, `dfsan_mark_signed`, `dfsan_infer_shape_in_math_op`,
   `dfsan_combine_and_ins`) and `dtaint_legacy_hooks.c`.
3. **`cmpid` is a real hash (Angora's `getInstructionId()`), not a small
   dense counter** -- `dtaint_runtime/dtaint_logger.c`'s `get_order()`
   originally indexed a plain array by `cmpid` directly (fine for the
   other phase's own small monotonic counter), which tried to allocate a
   multi-gigabyte array the first time a real (sparse, ~2^31-range) cmpid
   was seen. Replaced with a real open-addressing hash table. This fix
   benefits both phases since `dtaint_logger.c` is shared.
4. **The dtaint binary needs AFL's own forkserver stub linked in** (step 4
   above) to participate in `AFL_DTAINT_BINARY`'s forkserver protocol at
   all -- it isn't compiled via `afl-cc.c`, so nothing else provides it.
5. **Map-size mismatch between the two forkservers**: `afl->dtaint_fsrv`
   clones `map_size` from the main fsrv at `afl_fsrv_init_dup()` time,
   which may already be *shrunk* to the main binary's real (small) edge
   count. A dtaint binary with no coverage instrumentation at all (this
   one) reports the uninstrumented default (65536), gets rejected as
   "larger than the one this AFL++ is set with". Fixed in `src/afl-fuzz.c`
   by declaring `afl->dtaint_fsrv.map_size = MAX(..., DEFAULT_SHMEM_SIZE)`
   before starting it -- safe specifically because this dtaint binary has
   no coverage instrumentation to ever actually write into that space
   (mirrors, but is simpler than, `cmplog_fsrv`'s own resize-and-restart
   handling of the same underlying issue).

6. **`gen_library_abilist.sh`-generated rules silently no-op on libraries
   with ELF symbol versioning** -- `nm -D` emits versioned names (e.g.
   `jpeg_read_scanlines@@LIBJPEG_8.0`), but DFSan's abilist matches the bare
   function name as it appears in the IR (the `@@VERSION` suffix is a
   dynamic-linker construct, invisible to the compiler), so a generated
   `fun:jpeg_read_scanlines@@LIBJPEG_8.0=discard` rule never matches --
   found because it broke `libtiff`'s own `checking for jpeg_read_scanlines
   in -ljpeg` configure check specifically for this wrapper (reproduced
   standalone), while the plain `afl-clang-fast` build of the same source
   linked jpeg fine. Fix (in `Reusing-unibench_build/aflplusplus-reusing-
   target/Dockerfile`, not this repo): strip `@@VERSION` with
   `sed 's/@@[^=]*=/=/'` when generating the abilist. Not every library is
   affected the same way -- `libjbig` has no versioning at all, `libz` only
   versions some newer symbols -- so this had gone unnoticed until a library
   whose *every* symbol is versioned was linked.
7. **`ANGORA_DONT_OPTIMIZE`-equivalent default was missing**: this wrapper
   never added an optimization flag at all (clang default `-O0`), unlike
   `angora_clang.c` which always forces `-g -O3 -funroll-loops` (stripping
   any `-O1/-O2/-O3` the build system passes) unless `ANGORA_DONT_OPTIMIZE`
   is set. Fixed for fidelity to Angora's actual recipe; confirmed via
   direct A/B testing on the same seed that this specific gap was *not*
   the cause of item 8 below (byte-identical dtaint output before/after).

## Cross-validation against Angora-reusing on a real benchmark

Ran both this toolchain's dtaint output and Angora-reusing's own real
`.taint` binary against the *same* target (`tiffsplit`, libtiff 3.9.7) and
the same seed corpus (a 6809-file saturated/heavily-fuzzed corpus from
`Reusing-unibench_build/_saturation/`), converting Angora's native
bincode-serialized track file to this repo's `dtaint.h` wire format via a
small new debug binary (`fuzzer/src/bin/dump_dtaint.rs`, added to
Angora-reusing, *not* this repo -- it just re-serializes data Angora's own
`get_log_data` parser already produces, no taint-logic changes), then
diffing the two `.dtaint` files' resolved byte offsets per comparison site.

Findings, after fixing items 6 and 7 above:
- 97.9% of seeds produce output at all on both sides (a small fraction of
  the corpus -- specifically inputs with malformed/non-standard TIFF
  directory structure -- trigger a severe, multi-minute slowdown in this
  build's taint tracking before the process eventually SIGSEGVs; Angora's
  own build is far less affected by the same inputs). Not yet root-caused.
- Of the 6649 seeds both sides produced output for: 100% have overlapping
  comparison sites (avg Jaccard 0.775), 80.9% of matched-site records agree
  on `condition`/`op`/`size`/`arg1`/`arg2`, and 92.5% agree on the resolved
  byte-offset ranges (after merging adjacent/touching ranges, since one
  side sometimes reports one wider segment where the other reports several
  narrower adjacent ones covering the identical bytes -- not a real
  disagreement).
8. **Open issue**: the remaining ~7.5% offset disagreement is not random --
   it's a systematic pattern where this build's resolved range starts
   exactly 2 bytes earlier than Angora's for the same comparison, and
   correlates with an extra `sign=true` `TagSeg` / `COND_SIGN_MASK` on this
   build's side that Angora's doesn't have. Ruled out so far: `-O0` vs
   `-O3` codegen (item 7, disproven by direct A/B test), and `tif_config.h`
   macro differences between the two toolchains' separate `./configure`
   runs (a real diff exists -- e.g. `HAVE_STRCASECMP` -- but `tiffsplit`'s
   own source never references it). Next step if pursued: instrument
   `dtaint_tagset_infer_shape2`/`dfsan.cc`'s union/combine call sites with
   temporary tracing and diff the actual sequence of taint-insert calls
   against Angora's real Rust runtime for one execution, since the shape-
   inference heuristics (`infer_shape`/`infer_shape2`) depend on the global
   chronological *order* labels get inserted in, not just their final
   values -- a difference there, not in the combine logic itself (verified
   line-for-line identical to `tag_set.rs`), is the leading remaining
   hypothesis.

## Known gaps (same boundary as the other phase)

No consumer reads this data back into a mutation strategy -- this is still
information capture only.
