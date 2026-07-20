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
# A third edge case, found via a real hang debugging `cflow`'s ./configure:
# when a *combined* compile+link invocation (source file(s) + -o prog, no
# -c -- exactly what autoconf's AC_LINK_IFELSE/AC_RUN_IFELSE probes do) also
# needs our runtime archives appended, mixing -Xclang -load pass-loading
# flags with a positional .a argument in the *same* clang invocation hits a
# real clang-11 driver bug: it misidentifies the .a as C source needing its
# own -cc1 compile job (confirmed via `ps` catching a live `-cc1 -E -x c
# ... libdfsan_rt-x86_64.a` process spinning at 100% CPU trying to
# preprocess a multi-megabyte binary archive as text -- indistinguishable
# from an unkillable hang from the outside). An explicit `-x none` before
# our appended files does *not* prevent this. The actual fix: never mix
# -Xclang -load with .o/.a file arguments in one invocation -- split into a
# real two-phase compile-then-link whenever there's source to compile *and*
# linking is also requested (compile_and_link, below).
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
source_files=()

for arg in "$@"; do
    case "$arg" in
        *.s|*.S) maybe_assembler=1 ;;
    esac
    case "$arg" in
        -c|-S|-E|-shared) maybe_linking=0 ;;
    esac
    case "$arg" in
        *.c|*.cc|*.cpp|*.cxx|*.C) source_files+=( "$arg" ) ;;
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
        # Environment-compatibility fix, not target-specific like
        # ANGORA_TAINT_RULE_LIST below -- always applied. See
        # runtime/dtaint_legacy_hooks.c's __dfsw___isoc23_* wrappers.
        -mllvm "-angora-dfsan-abilist=${RULES_DIR}/isoc23_abilist.txt"
        -mllvm "-angora-dfsan-abilist=${RULES_DIR}/zlib_custom_abilist.txt"
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
        -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/isoc23_abilist.txt"
        -mllvm "-angora-dfsan-abilist2=${RULES_DIR}/zlib_custom_abilist.txt"
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

# No -I into our own include/ or dtaint_runtime/ dirs here -- a real bug
# found via a real target: AFL++'s top-level include/ has its own
# config.h and hash.h (AFL++ tunables / hash function, nothing to do with
# autoconf), and putting that dir ahead of a target's *own* -I. -I.. put
# AFL++'s config.h in front of cflow's real, autoconf-generated one for any
# quote-include, silently breaking every gnulib header that guards itself
# on config.h's own include-once macro ("Please include config.h first.").
# Nothing this wrapper compiles on a *target's* behalf needs our internal
# runtime headers anyway -- those are only included when io_func.c/
# dtaint_legacy_hooks.c/etc. are compiled directly (see the top-level
# Dockerfile), never through this script.
common_includes=( -pie -fpic -Qunused-arguments )

if [ "$maybe_linking" -eq 1 ] && [ "${#source_files[@]}" -gt 0 ] && [ "$maybe_assembler" -eq 0 ]; then
    # compile_and_link: a combined "compile this source and link it into a
    # binary" invocation (autoconf probes, or a trivial `cc -o prog prog.c`
    # build step) -- see this file's header comment for why this can't be
    # one clang invocation like the -c-only and link-only cases below.
    # Phase 1: compile each source file to a temp .o *with* the
    # instrumentation passes, nothing link-related on this command line at
    # all (no runtime archives, no -Wl flags -- exactly like a real -c step).
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    objs=()
    other_args=()
    skip_next=0
    prev_was_o=0
    for arg in "$@"; do
        if [ "$skip_next" -eq 1 ]; then skip_next=0; continue; fi
        case "$arg" in
            -o) skip_next=1; continue ;;
        esac
        case "$arg" in
            *.c|*.cc|*.cpp|*.cxx|*.C) continue ;;  # handled via source_files
        esac
        other_args+=( "$arg" )
    done

    n=0
    for src in "${source_files[@]}"; do
        n=$((n + 1))
        obj="${tmpdir}/obj${n}.o"
        "$CLANG" "${pass_flags[@]}" "${common_includes[@]}" "${other_args[@]}" \
            "${opt_flags[@]}" -c "$src" -o "$obj"
        objs+=( "$obj" )
    done

    # Phase 2: link the freshly-compiled .o(s) together with whatever
    # other .o/.a/-l arguments were on the original command line, plus our
    # own runtime archives -- a plain link, no -Xclang -load in sight, so
    # the driver never has a reason to misidentify any .a as source.
    out="a.out"
    skip_next=0
    for arg in "$@"; do
        if [ "$skip_next" -eq 1 ]; then out="$arg"; skip_next=0; continue; fi
        case "$arg" in
            -o) skip_next=1 ;;
        esac
    done

    exec "$CLANG" "${common_includes[@]}" "${other_args[@]}" "${objs[@]}" \
        "${opt_flags[@]}" "${link_flags[@]}" -o "$out"
fi

# -c-only (no linking) or link-only (no source files, e.g. linking
# already-compiled .o files from separate earlier -c invocations) cases:
# a single invocation is safe here since pass_flags and .a/.o positional
# args never both appear together (pass_flags is only meaningful when
# there's source to instrument, i.e. maybe_linking is 0 here, or this is a
# no-source link where -Xclang -load wouldn't do anything anyway and could
# still trip the same driver bug, so skip it).
if [ "$maybe_linking" -eq 1 ]; then
    pass_flags=()
fi

exec "$CLANG" \
    "${pass_flags[@]}" \
    "${common_includes[@]}" \
    "$@" \
    "${opt_flags[@]}" \
    "${link_flags[@]}"
