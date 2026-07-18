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
# /home/yunseo/Angora_original exactly (same -Xclang -load sequence, same
# -mllvm flags, same runtime link recipe), simplified to a shell script
# since this tool only ever needs TRACK mode (there is no FAST/PIN mode
# here -- AFL++'s own coverage instrumentation already covers that role).
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
CLANG="${LLVM_DIR}/bin/clang"

if [ ! -x "$CLANG" ]; then
    echo "angora_dfsan_clang.sh: no clang at $CLANG (set DFSAN_LEGACY_LLVM_DIR)" >&2
    exit 1
fi

PASS_DIR="${HERE}/build_pass"
RT_DIR="${HERE}/build_rt"
DFSAN_RT_A="${HERE}/build/dfsan_rt/libdfsan_rt-x86_64.a"
RULES_DIR="${HERE}/rules"

exec "$CLANG" \
    -Xclang -load -Xclang "${PASS_DIR}/libUnfoldBranchPass.so" \
    -Xclang -load -Xclang "${PASS_DIR}/libAngoraPass.so" \
    -mllvm -TrackMode \
    -mllvm "-angora-dfsan-abilist=${RULES_DIR}/angora_abilist.txt" \
    -mllvm "-angora-dfsan-abilist=${RULES_DIR}/dfsan_abilist.txt" \
    -mllvm "-angora-exploitation-list=${RULES_DIR}/exploitation_list.txt" \
    -Xclang -load -Xclang "${PASS_DIR}/libDFSanPass.so" \
    -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/angora_abilist.txt" \
    -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/dfsan_abilist.txt" \
    -pie -fpic -Qunused-arguments \
    -I "${HERE}/../include" -I "${HERE}/../dtaint_runtime" \
    "$@" \
    -Wl,--whole-archive "${DFSAN_RT_A}" -Wl,--no-whole-archive \
    -Wl,--dynamic-list="${DFSAN_RT_A}.syms" \
    "${RT_DIR}/libdtaint-legacy-rt.a" \
    -lstdc++ -lrt -ldl -lpthread -lm \
    -Wl,--no-as-needed -Wl,--gc-sections
