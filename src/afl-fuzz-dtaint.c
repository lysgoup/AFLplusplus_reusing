/*
   american fuzzy lop++ - dynamic taint tracking execution routines
   --------------------------------------------------------------------

   Minimal validation slice, ported from the Angora fuzzer -- mirrors
   src/afl-fuzz-cmplog.c's shape, but there is deliberately no
   common_fuzz_cmplog_stuff()-equivalent consumer here: run_one_dtaint()
   just triggers exactly one run of the dtaint binary and lets the caller
   inspect the resulting track file afterward. No mutation-strategy
   integration in this slice -- see the scoping plan this was built from.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include "afl-fuzz.h"
#include "dtaint.h"

/* Unlike cmplog_exec_child, there is no argv[0]/target_path rewrite trick
   needed here: afl->dtaint_fsrv.target_path is set to the dtaint binary
   directly at setup time (src/afl-fuzz.c), since this forkserver never runs
   the main coverage binary at all -- only ever the dtaint one. */
void dtaint_exec_child(afl_forkserver_t *fsrv, char **argv) {

  execv(fsrv->target_path, argv);

}

/* Runs `out_buf` (len bytes) through the dtaint binary exactly once, with
   AFL_DTAINT_TRACK_FILE pointed at `track_file_path` -- the caller is
   responsible for reading that file back afterward; nothing here does. */
u8 run_one_dtaint(afl_state_t *afl, u8 *out_buf, u32 len,
                   const u8 *track_file_path) {

  setenv(DTAINT_TRACK_ENV_VAR, (const char *)track_file_path, 1);

  u32 tmp_len = write_to_testcase(afl, (void **)&out_buf, len, 0);
  if (likely(tmp_len)) { len = tmp_len; }

  u8 fault = fuzz_run_target(afl, &afl->dtaint_fsrv, afl->fsrv.exec_tmout);

  return fault;

}
