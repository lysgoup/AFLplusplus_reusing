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

- `pass/` -- Angora's actual `DFSanPass.cc`/`AngoraPass.cc`/
  `UnfoldBranchPass.cc`, byte-for-byte unmodified. Confirmed to compile and
  run correctly against the real LLVM 11.1.0 release with **zero source
  changes** (see verification below).
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

## Known gaps (same boundary as the other phase)

No consumer reads this data back into a mutation strategy -- this is still
information capture only.
