#!/bin/bash
# american fuzzy lop++ - real-DFSan dtaint compiler wrapper
# -----------------------------------------------------------------------------
#
# Standalone tool (not integrated into afl-cc.c -- see instrumentation/
# README.dtaint.md and this directory's own notes) that produces the
# AFL_DTAINT_BINARY executable using Angora's *actual* vendored LLVM 11.1.0
# DataFlowSanitizer fork (dfsan_legacy/pass/, dfsan_rt/) instead of the
# custom from-scratch pass in instrumentation/afl-llvm-dtaint-pass.so.cc.
#
# Mirrors llvm_mode/compiler/angora_clang.c's USE_TRACK path from
# /home/yunseo/Angora_original (same -Xclang -load sequence, same -mllvm
# flags, same runtime link recipe), including its two key edge-case checks
# -- needed once this is used as a drop-in CC/CXX for arbitrary real-world
# autotools/cmake build systems (a `./configure` compiler probe, or a
# per-.c-file `-c` compile step, must not trip over flags meant for the
# final link step):
#   - maybe_assembler: a .s/.S file on the command line skips pass-loading
#     entirely (there's no C-level IR for a pass to instrument).
#   - maybe_linking: -c/-S/-E on the command line means this invocation
#     produces an object file, not a binary -- the runtime-archive link
#     flags are only appended when actually linking.
#
# Invoke as (or symlink to) *_clang++ for C++ mode; anything else uses C.
#
# Usage:
#   DFSAN_LEGACY_LLVM_DIR=/opt/clang+llvm-11 \
#     ./angora_dfsan_clang.sh -o target.dtaint target.c [afl_flags...]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0

set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLVM_DIR="${DFSAN_LEGACY_LLVM_DIR:-/opt/clang+llvm-11}"

case "$(basename "$0")" in
    *clang++*) CLANG="${LLVM_DIR}/bin/clang++" ;;
    *)         CLANG="${LLVM_DIR}/bin/clang" ;;
esac

if [ ! -x "$CLANG" ]; then
    echo "angora_dfsan_clang.sh: no compiler at $CLANG (set DFSAN_LEGACY_LLVM_DIR)" >&2
    exit 1
fi

PASS_DIR="${HERE}/build_pass"
RT_DIR="${HERE}/build_rt"
DFSAN_RT_A="${HERE}/build/dfsan_rt/libdfsan_rt-x86_64.a"
RULES_DIR="${HERE}/rules"

maybe_assembler=0
maybe_linking=1

for arg in "$@"; do
    case "$arg" in
        *.s|*.S) maybe_assembler=1 ;;
    esac
    case "$arg" in
        -c|-S|-E|-shared) maybe_linking=0 ;;
    esac
done

pass_flags=()
if [ "$maybe_assembler" -eq 0 ]; then
    pass_flags=(
        -Xclang -load -Xclang "${PASS_DIR}/libUnfoldBranchPass.so"
        -Xclang -load -Xclang "${PASS_DIR}/libAngoraPass.so"
        -mllvm -TrackMode
        -mllvm "-angora-dfsan-abilist=${RULES_DIR}/angora_abilist.txt"
        -mllvm "-angora-dfsan-abilist=${RULES_DIR}/dfsan_abilist.txt"
        -mllvm "-angora-exploitation-list=${RULES_DIR}/exploitation_list.txt"
    )
    # Optional extra "discard taint through this library" abilist -- mirrors
    # angora_clang.c's TAINT_RULE_LIST_VAR (ANGORA_TAINT_RULE_LIST) exactly,
    # including applying it to *both* AngoraPass and DFSanPass. Angora-
    # reusing's own benchmark build always sets this (see angora-reusing-
    # target/Dockerfile: an auto-generated discard-list covering every
    # shared library the target links against, built via
    # tools/gen_library_abilist.sh / this repo's own copy of it) -- without
    # it, taint is traced straight through third-party library internals
    # (libjpeg, libz, libjbig, ...) that Angora deliberately treats as
    # opaque/untainted, producing a much larger and non-comparable set of
    # cond records for the same target and seed.
    if [ -n "$ANGORA_TAINT_RULE_LIST" ]; then
        pass_flags+=( -mllvm "-angora-dfsan-abilist=${ANGORA_TAINT_RULE_LIST}" )
    fi
    pass_flags+=(
        -Xclang -load -Xclang "${PASS_DIR}/libDFSanPass.so"
        -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/angora_abilist.txt"
        -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/dfsan_abilist.txt"
    )
    if [ -n "$ANGORA_TAINT_RULE_LIST" ]; then
        pass_flags+=( -mllvm "-angora-dfsan-abilist2=${ANGORA_TAINT_RULE_LIST}" )
    fi
fi

link_flags=()
if [ "$maybe_linking" -eq 1 ]; then
    link_flags=(
        # AFL's own forkserver stub (built from instrumentation/afl-compiler-
        # rt.o.c against this same LLVM 11 toolchain -- see this repo's
        # top-level Dockerfile). Without it the resulting binary has no
        # __afl_start_forkserver() at all: it was never compiled via
        # afl-cc.c, so nothing else provides one, and AFL_DTAINT_BINARY's
        # forkserver handshake fails immediately ("Fork server handshake
        # failed" in afl-fuzz).
        "${RT_DIR}/afl-compiler-rt-llvm11.o"
        -Wl,--whole-archive "${DFSAN_RT_A}" -Wl,--no-whole-archive
        -Wl,--dynamic-list="${DFSAN_RT_A}.syms"
        "${RT_DIR}/libdtaint-legacy-rt.a"
        -lstdc++ -lrt -ldl -lpthread -lm
        -Wl,--no-as-needed -Wl,--gc-sections
    )
fi

# angora_clang.c always recompiles at -g -O3 -funroll-loops (stripping any
# -O1/-O2/-O3 the build system itself passes) unless ANGORA_DONT_OPTIMIZE is
# set -- this was a real gap: without it, this wrapper left optimization at
# clang's default -O0, producing different codegen from Angora's own -O3
# build of the identical source. Matching this is correctness/fidelity to
# Angora's actual recipe on its own terms, not a fix for any specific
# observed discrepancy: A/B testing on the same seed before/after this
# change showed byte-identical dtaint output, so the -O0-vs-O3 gap was
# *not* the cause of the small systematic taint-shape mismatch found when
# cross-validating this build's output against Angora-reusing's own on the
# same seeds (still under investigation -- see dfsan_legacy/README.md).
# clang takes the last -O flag on the command line, so appending ours
# after "$@" is sufficient without needing to strip the build system's own
# -O2/etc first.
opt_flags=()
if [ -z "$ANGORA_DONT_OPTIMIZE" ]; then
    opt_flags=( -g -O3 -funroll-loops )
fi

exec "$CLANG" \
    "${pass_flags[@]}" \
    -pie -fpic -Qunused-arguments \
    -I "${HERE}/../include" -I "${HERE}/../dtaint_runtime" \
    "$@" \
    "${opt_flags[@]}" \
    "${link_flags[@]}"
