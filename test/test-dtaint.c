/*
   Validation harness for dynamic taint tracking (Piece 4: Angora-parity
   taint info -- instrumentation/afl-llvm-dtaint-pass.so.cc + dtaint_runtime/).

   Build:

     AFL_LLVM_DTAINT=1 AFL_DONT_OPTIMIZE=1 \
       ./afl-clang-fast -o test-dtaint test/test-dtaint.c dtaint_runtime/libdtaint-rt.a

   Run:

     AFL_DTAINT_TRACK_FILE=/tmp/track.bin ./test-dtaint /tmp/in.bin

   Unlike the original minimal-slice harness, this one does *not* call
   dtaint_source_buf explicitly -- `read()` below gets redirected by the
   pass to the ABI-list wrapper __dtaint_read (see
   instrumentation/README.dtaint.md's "ABI list" section), so `buf` is
   tainted automatically, exactly like a real Angora-instrumented binary
   reading its input.

   Exercises: plain ICmpInst (cmp #1, #2), a multi-byte load combined via
   Or/Shl (cmp #3), an Add feeding an ICmpInst (cmp #4), a switch statement
   (cmp #5, one record per case), and a strcmp call redirected to the cmpfn
   wrapper __dtaint_strcmp (cmp #6) after a memcpy propagates taint into a
   local buffer.
*/

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define INLEN 11

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

  if (buf[0] == 'A') {                            /* cmp #1: offset {0} */

    if (buf[1] == 'B') {                          /* cmp #2: offset {1} */

      unsigned short v = buf[2] | (buf[3] << 8);
      if (v == 0x1234) {                          /* cmp #3: offsets {2,3} */

        if (buf[4] + buf[5] == 100) {             /* cmp #4: offsets {4,5} */

          printf("first four comparisons matched\n");

        }

      }

    }

  }

  switch (buf[6]) {                               /* cmp #5: offset {6} */

    case 1: printf("case1\n"); break;
    case 2: printf("case2\n"); break;
    case 3: printf("case3\n"); break;
    default: printf("default\n"); break;

  }

  char local[8];
  memset(local, 0, sizeof(local));
  memcpy(local, buf + 7, 4);                      /* propagate {7,8,9,10} */
  if (strcmp(local, "TEST") == 0) {               /* cmp #6: cmpfn */

    printf("matched TEST\n");

  }

  return 0;

}
