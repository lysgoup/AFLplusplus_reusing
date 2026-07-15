/*
   Minimal validation harness for the dynamic taint tracking slice
   (instrumentation/afl-llvm-dtaint-pass.so.cc + dtaint_runtime/).

   Deliberately not a libFuzzer-style LLVMFuzzerTestOneInput harness (unlike
   test-cmplog.c): this slice's taint source is an explicit runtime call the
   harness makes itself (dtaint_source_buf), not something wired into a
   fuzzer-driven entry point yet, so a plain argv[1]-file harness is clearer
   for standalone verification.

   Build (once a machine with LLVM 14-21 is available -- untested in the
   environment this was written in):

     AFL_LLVM_DTAINT=1 AFL_DONT_OPTIMIZE=1 \
       ./afl-clang-fast -o test-dtaint test/test-dtaint.c dtaint_runtime/libdtaint-rt.a

   Run:

     AFL_DTAINT_TRACK_FILE=/tmp/track.bin ./test-dtaint /tmp/in.bin

   The four nested comparisons below exercise all four instrumented
   instruction categories in afl-llvm-dtaint-pass.so.cc: plain ICmpInst
   (cmp #1, #2), a multi-byte load combined via BinaryOperator Or/Shl
   (cmp #3), and an Add BinaryOperator feeding an ICmpInst (cmp #4).
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "dtaint.h"

#define INLEN 6

int main(int argc, char **argv) {

  if (argc < 2) {

    fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
    return 1;

  }

  unsigned char buf[INLEN];
  int           fd = open(argv[1], O_RDONLY);
  if (fd < 0) { perror("open"); return 1; }

  ssize_t n = read(fd, buf, INLEN);
  close(fd);
  if (n < INLEN) {

    fprintf(stderr, "input too short, need %d bytes\n", INLEN);
    return 1;

  }

  /* Explicit taint source seed -- see file header. */
  dtaint_source_buf(buf, INLEN);

  if (buf[0] == 'A') {                            /* cmp #1: offset {0} */

    if (buf[1] == 'B') {                          /* cmp #2: offset {1} */

      unsigned short v = buf[2] | (buf[3] << 8);
      if (v == 0x1234) {                          /* cmp #3: offsets {2,3} */

        if (buf[4] + buf[5] == 100) {             /* cmp #4: offsets {4,5} */

          printf("all four comparisons matched\n");

        }

      }

    }

  }

  return 0;

}
