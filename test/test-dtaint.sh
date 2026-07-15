#!/bin/bash
# Minimal validation-slice test for dynamic taint tracking (see the scoping
# plan this was built from). Exercises verification steps 3-4 from that plan:
# full afl-cc compile, then a direct run (no forkserver) with the resulting
# track file hand-checked against the four comparisons in test-dtaint.c.
#
# Requires LLVM 14-21 + clang on PATH -- untested in the environment this was
# written in (no clang/llvm-config available there). Run from repo root
# after `make` (or at least `make -f GNUmakefile.llvm`) has built
# ./afl-clang-fast and ./afl-llvm-dtaint-pass.so, and `make -C dtaint_runtime`
# has built dtaint_runtime/libdtaint-rt.a.

cd "$(dirname "$0")/.." || exit 1

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
FAIL=0

if [ ! -x ./afl-clang-fast ]; then
    echo "afl-clang-fast not found -- build with 'make' first"
    exit 1
fi

if [ ! -f dtaint_runtime/libdtaint-rt.a ]; then
    echo "dtaint_runtime/libdtaint-rt.a not found -- run 'make -C dtaint_runtime' first"
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "[*] Compiling test-dtaint.c with AFL_LLVM_DTAINT=1 ..."
# -I include: unlike CmpLog (whose target-facing hooks are purely
# compiler-inserted, invisible to target source), this slice's taint source
# is an explicit call the harness makes itself (dtaint_source_buf), so the
# harness needs dtaint.h's declaration.
AFL_LLVM_DTAINT=1 AFL_DONT_OPTIMIZE=1 ./afl-clang-fast -I include \
    -o "$TMP/test-dtaint" test/test-dtaint.c dtaint_runtime/libdtaint-rt.a
if [ $? -ne 0 ]; then
    printf "${RED}[-] compile failed${NC}\n"
    exit 1
fi

# bytes: 'A' 'B' 0x34 0x12 10 90  -> cmp#3 wants buf[2]|(buf[3]<<8)==0x1234,
# cmp#4 wants buf[4]+buf[5]==100 (10+90)
printf 'AB\x34\x12\x0a\x5a' > "$TMP/in.bin"

echo "[*] Running directly (no forkserver) ..."
AFL_DTAINT_TRACK_FILE="$TMP/track.bin" "$TMP/test-dtaint" "$TMP/in.bin"

if [ ! -f "$TMP/track.bin" ]; then
    printf "${RED}[-] no track file produced${NC}\n"
    exit 1
fi

# Small inline parser (mirrors .dtaint_scratch/parse_track.c used to validate
# the runtime in isolation) -- reads the flat struct-array format from
# include/dtaint.h and prints one CSV-ish line per record for both human
# reading and this script's own assertion below.
cat > "$TMP/parse.c" << 'EOF'
#include <stdio.h>
#include "dtaint.h"
int main(int argc, char **argv) {
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }
    struct dtaint_file_header hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) return 1;
    if (hdr.magic != DTAINT_FILE_MAGIC) { fprintf(stderr, "bad magic\n"); return 1; }
    for (u32 i = 0; i < hdr.n_records; i++) {
        struct dtaint_record r;
        if (fread(&r, sizeof(r), 1, fp) != 1) return 1;
        printf("cmpid=%u cond=%u arg1=%llu arg2=%llu offsets={", r.cmpid, r.cond,
               (unsigned long long)r.arg1, (unsigned long long)r.arg2);
        for (u32 j = 0; j < r.n_offsets; j++) {
            u32 off;
            if (fread(&off, sizeof(off), 1, fp) != 1) return 1;
            printf("%s%u", j ? "," : "", off);
        }
        printf("}\n");
    }
    return 0;
}
EOF
cc -I include -O0 -g "$TMP/parse.c" -o "$TMP/parse"
echo "[*] Track file contents:"
OUT=$("$TMP/parse" "$TMP/track.bin")
echo "$OUT"

# cmpid numbers aren't part of the contract (they're a per-function counter
# over *every* instrumented comparison, including argc/fd/n checks earlier in
# test-dtaint.c's control flow that happen to run before dtaint_source_buf,
# not just this harness's four target comparisons) -- so assert on the last
# four records' offsets/values instead of specific cmpids.
EXPECTED='offsets={0}
offsets={1}
offsets={2,3}
offsets={4,5}'
ACTUAL=$(echo "$OUT" | tail -4 | grep -o 'offsets={[0-9,]*}')

if [ "$ACTUAL" = "$EXPECTED" ]; then
    printf "${GREEN}[+] PASS: all four comparisons' offsets reconstructed correctly${NC}\n"
else
    printf "${RED}[-] FAIL: expected offsets:\n%s\ngot:\n%s${NC}\n" "$EXPECTED" "$ACTUAL"
    FAIL=1
fi

exit $FAIL
