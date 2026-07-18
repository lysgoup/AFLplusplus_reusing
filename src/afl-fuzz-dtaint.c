/*
   american fuzzy lop++ - dynamic taint tracking execution routines
   --------------------------------------------------------------------

   Ported from the Angora fuzzer -- mirrors src/afl-fuzz-cmplog.c's shape,
   but there is deliberately no common_fuzz_cmplog_stuff()-equivalent
   consumer here: run_one_dtaint() just triggers exactly one run of the
   dtaint binary and lets the caller inspect the resulting track file
   afterward. log_dtaint_for_new_input() is that caller, invoked from
   save_if_interesting() (src/afl-fuzz-bitmap.c) right when a new queue
   entry is added -- mirroring Angora's own policy of only running the
   taint/pin binary when a new branch is actually found, not on every
   execution. Nothing reads the resulting files back into a mutation
   strategy yet -- see instrumentation/README.dtaint.md's "Known gaps".

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

/* Runs `out_buf` (len bytes) through the dtaint binary exactly once. Any
   resulting track file lands at the *fixed* per-session scratch path
   (AFL_DTAINT_TRACK_FILE, set once in src/afl-fuzz.c before this
   forkserver's one-time execve() -- see include/dtaint.h's comment on
   DTAINT_TRACK_ENV_VAR for why this can't vary per call). The caller is
   responsible for consuming/renaming that scratch file afterward; nothing
   here does. */
u8 run_one_dtaint(afl_state_t *afl, u8 *out_buf, u32 len) {

  u32 tmp_len = write_to_testcase(afl, (void **)&out_buf, len, 0);
  if (likely(tmp_len)) { len = tmp_len; }

  u8 fault = fuzz_run_target(afl, &afl->dtaint_fsrv, afl->fsrv.exec_tmout);

  return fault;

}

/* Called only when afl->dtaint_binary is set (the dtaint forkserver was
   started -- see src/afl-fuzz.c), right after a genuinely new queue entry
   is created. Runs the input through run_one_dtaint(), then renames
   whatever landed at the fixed scratch path to a per-input destination
   under <out_dir>/dtaint_logs/ named after the queue entry -- that
   renamed file *is* the log this phase was asked to produce; nothing
   parses it back yet. If the scratch file doesn't exist afterward, the
   target simply had nothing taint-worthy to report for this input
   (dtaint_logger_fini() skips writing when its cond_list is empty) --
   not an error. */
void log_dtaint_for_new_input(afl_state_t *afl, u8 *mem, u32 len,
                              u8 *queue_fname) {

  run_one_dtaint(afl, mem, len);

  u8 *scratch_path =
      alloc_printf("%s/dtaint_logs/%s", afl->out_dir, DTAINT_SCRATCH_NAME);

  if (access((char *)scratch_path, F_OK) != 0) {

    ck_free(scratch_path);
    return;

  }

  const char *base = strrchr((const char *)queue_fname, '/');
  base = base ? base + 1 : (const char *)queue_fname;

  u8 *dest_path = alloc_printf("%s/dtaint_logs/%s.dtaint", afl->out_dir, base);

  if (rename((char *)scratch_path, (char *)dest_path)) {

    WARNF("Could not rename dtaint scratch file to '%s'", dest_path);

  }

  ck_free(dest_path);
  ck_free(scratch_path);

}
