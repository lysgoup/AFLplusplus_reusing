#!/bin/bash
# Validation-slice test for dynamic taint tracking (Piece 4: Angora-parity
# taint info). Exercises a full afl-cc compile, then a direct run (no
# forkserver) with the resulting track file parsed and asserted against
# test-dtaint.c's six comparison sites (icmp x4, switch, cmpfn).
#
# Requires LLVM 14-21 + clang on PATH. Run from repo root after `make` (or
# at least `make -f GNUmakefile.llvm`) has built ./afl-clang-fast and
# ./afl-llvm-dtaint-pass.so, and `make -C dtaint_runtime` has built
# dtaint_runtime/libdtaint-rt.a.

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
AFL_LLVM_DTAINT=1 AFL_DONT_OPTIMIZE=1 ./afl-clang-fast -I include \
    -o "$TMP/test-dtaint" test/test-dtaint.c dtaint_runtime/libdtaint-rt.a
if [ $? -ne 0 ]; then
    printf "${RED}[-] compile failed${NC}\n"
    exit 1
fi

# bytes: 'A' 'B' 0x34 0x12 10 90 <case=2> 'T' 'E' 'S' 'T'
# cmp#3 wants buf[2]|(buf[3]<<8)==0x1234, cmp#4 wants buf[4]+buf[5]==100
# (10+90), switch(buf[6]) hits case 2, strcmp(local,"TEST") matches.
printf 'AB\x34\x12\x0a\x5a\x02TEST' > "$TMP/in.bin"

echo "[*] Running directly (no forkserver) ..."
AFL_DTAINT_TRACK_FILE="$TMP/track.bin" "$TMP/test-dtaint" "$TMP/in.bin"

if [ ! -f "$TMP/track.bin" ]; then
    printf "${RED}[-] no track file produced${NC}\n"
    exit 1
fi

# Parser for the Piece-4 wire format (include/dtaint.h): header, then
# n_conds cond records, then n_tags (tag_record + inline segs), then
# n_magic_bytes (magic_bytes_record + inline bytes). Resolves each cond's
# lb1/lb2 against the tags table to print reconstructed offsets, mirroring
# what a real consumer would do (none exists yet -- see README).
cat > "$TMP/parse.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "dtaint.h"

#define MAX_TAGS 256
static u32 tag_labels[MAX_TAGS];
static struct dtaint_tag_seg_wire tag_segs[MAX_TAGS][32];
static u32 tag_nsegs[MAX_TAGS];
static u32 n_tags_loaded = 0;

static void print_offsets(u32 lb) {
    if (lb == 0) { printf("-"); return; }
    for (u32 i = 0; i < n_tags_loaded; i++) {
        if (tag_labels[i] == lb) {
            printf("{");
            for (u32 j = 0; j < tag_nsegs[i]; j++)
                printf("%s%u-%u", j ? "," : "", tag_segs[i][j].begin, tag_segs[i][j].end);
            printf("}");
            return;
        }
    }
    printf("?%u", lb);
}

int main(int argc, char **argv) {
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }

    struct dtaint_file_header hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) return 1;
    if (hdr.magic != DTAINT_FILE_MAGIC) { fprintf(stderr, "bad magic\n"); return 1; }

    struct dtaint_cond_record *conds = malloc(sizeof(struct dtaint_cond_record) * hdr.n_conds);
    for (u32 i = 0; i < hdr.n_conds; i++)
        if (fread(&conds[i], sizeof(conds[i]), 1, fp) != 1) return 1;

    for (u32 i = 0; i < hdr.n_tags; i++) {
        struct dtaint_tag_record rec;
        if (fread(&rec, sizeof(rec), 1, fp) != 1) return 1;
        if (i < MAX_TAGS) {
            tag_labels[i] = rec.label;
            tag_nsegs[i] = rec.n_segs > 32 ? 32 : rec.n_segs;
            n_tags_loaded++;
        }
        for (u32 j = 0; j < rec.n_segs; j++) {
            struct dtaint_tag_seg_wire w;
            if (fread(&w, sizeof(w), 1, fp) != 1) return 1;
            if (i < MAX_TAGS && j < 32) tag_segs[i][j] = w;
        }
    }

    for (u32 i = 0; i < hdr.n_conds; i++) {
        struct dtaint_cond_record *c = &conds[i];
        printf("cmpid=%u order=%u cond=%u op=0x%x size=%u arg1=%llu arg2=%llu lb1=",
               c->cmpid, c->order, c->condition, c->op, c->size,
               (unsigned long long)c->arg1, (unsigned long long)c->arg2);
        print_offsets(c->lb1);
        printf(" lb2=");
        print_offsets(c->lb2);
        printf("\n");
    }

    for (u32 i = 0; i < hdr.n_magic_bytes; i++) {
        struct dtaint_magic_bytes_record rec;
        if (fread(&rec, sizeof(rec), 1, fp) != 1) return 1;
        char b1[513], b2[513];
        if (rec.len1) { if (fread(b1, 1, rec.len1, fp) != rec.len1) return 1; }
        if (rec.len2) { if (fread(b2, 1, rec.len2, fp) != rec.len2) return 1; }
        b1[rec.len1] = 0; b2[rec.len2] = 0;
        printf("magic cond_index=%u a=\"%s\" b=\"%s\"\n", rec.cond_index, b1, b2);
    }

    return 0;
}
EOF
cc -I include -O0 -g "$TMP/parse.c" -o "$TMP/parse"
echo "[*] Track file contents:"
OUT=$("$TMP/parse" "$TMP/track.bin")
echo "$OUT"

# Assert the four numeric comparisons' reconstructed offsets, the switch's
# offset + DONE_ST match (condition==2 on case index 1 == case value 2),
# and the cmpfn magic-bytes snapshot.
FAIL=0

check() {
    if ! echo "$OUT" | grep -qF "$1"; then
        printf "${RED}[-] missing expected line containing: %s${NC}\n" "$1"
        FAIL=1
    fi
}

check "lb1={0-1} lb2=-"       # cmp#1: buf[0]=='A'
check "lb1={1-2} lb2=-"       # cmp#2: buf[1]=='B'
check "lb1={2-3,3-4} lb2=-"   # cmp#3: buf[2]|(buf[3]<<8) -- two 1-byte
                              # BinaryOperator combines, no shape inference
                              # applied (that's load-only, see tag_set.rs)
check "lb1={4-5,5-6} lb2=-"   # cmp#4: buf[4]+buf[5], same reasoning
check "lb1={6-7} lb2=-"       # cmp#5: switch(buf[6]), single-byte load
check "cond=2 op=0xff"       # switch's matching case gets DTAINT_COND_DONE_ST (2)
check 'magic cond_index='    # cmpfn record produced a magic_bytes entry
check 'a="TEST" b="TEST"'    # both sides captured correctly

if [ $FAIL -eq 0 ]; then
    printf "${GREEN}[+] PASS: all Piece-4 comparison sites reconstructed correctly${NC}\n"
else
    FAIL=1
fi

exit $FAIL
