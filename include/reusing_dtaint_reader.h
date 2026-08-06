/*
   american fuzzy lop++ - reusing pool: .dtaint file reader
   -----------------------------------------------------------------

   dtaint_runtime/dtaint_logger.c only ever WRITES a .dtaint file (from
   inside the instrumented target, once, at process exit). Nothing on the
   fuzzer side reads one back -- this is that missing other half: load a
   file written in the format include/dtaint.h documents (header, then
   n_conds dtaint_cond_record entries, then n_tags (dtaint_tag_record +
   its n_segs dtaint_tag_seg_wire entries) groups, then n_magic_bytes
   (dtaint_magic_bytes_record + len1 + len2 raw bytes) groups) into an
   in-memory form a caller can actually use: the cond_list array as-is,
   plus O(1) lookup from a cond_list entry's lb1/lb2 label to its resolved
   byte segments, and from a cond_list index to its magic-bytes snapshot
   (if any).

   Doesn't interpret any of it -- turning a resolved segment list into a
   reusing_pattern_t is include/reusing_pattern.h's job, and deciding
   which candidates to keep is include/reusing_filter.h's. This is purely
   the file-format boundary.

   Defensive by necessity, not just habit: a .dtaint file is written by a
   destructor in a child process AFL itself may kill mid-run (timeout,
   crash, SIGKILL from the forkserver) -- a short/truncated file on disk
   is an expected, routine occurrence, not a corruption bug. Every load
   failure (missing file, bad magic/version, truncated read at any point)
   returns NULL rather than aborting.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _AFL_REUSING_DTAINT_READER_H
#define _AFL_REUSING_DTAINT_READER_H

#include "dtaint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One resolved "tags" table entry -- label plus its owned byte-segment
   list (dtaint_tag_seg_wire, the same wire struct the file stores). */
typedef struct {

  u32                         label;
  struct dtaint_tag_seg_wire *segs; /* heap-allocated, n_segs entries */
  u32                         n_segs;

} dtaint_reader_tag_t;

/* One resolved "magic_bytes" table entry -- the raw operand snapshots at
   a COND_FN_OP site, keyed by cond_list index. */
typedef struct {

  u32 cond_index;
  u8 *buf1; /* heap-allocated, len1 bytes (NULL if len1 == 0) */
  u32 len1;
  u8 *buf2; /* heap-allocated, len2 bytes (NULL if len2 == 0) */
  u32 len2;

} dtaint_reader_magic_t;

/* A fully-loaded .dtaint file. Opaque to callers beyond the accessors
   below -- the hash tables backing label/cond_index lookup are an
   implementation detail. */
typedef struct dtaint_reader dtaint_reader_t;

/* Loads and parses `path`. Returns NULL on any failure (file missing,
   bad magic/version, truncated/short read at any point) -- callers
   should treat that as "no taint data for this run", not a fatal error
   (see this header's own comment on why truncation is routine, not a
   bug). On success, everything is copied into reader-owned memory; the
   file is fully read and closed before this returns. */
dtaint_reader_t *dtaint_reader_load(const char *path);

void dtaint_reader_free(dtaint_reader_t *reader);

/* The raw cond_list, in file order -- same array/indexing dtaint_cond_
   record.belong / dtaint_magic_bytes_record.cond_index and this reader's
   own dtaint_reader_get_magic() below refer to by index. */
const struct dtaint_cond_record *dtaint_reader_conds(const dtaint_reader_t *reader,
                                                      u32 *n_conds_out);

/* Resolves a cond_list entry's lb1 or lb2 label to its byte segments.
   Returns NULL (and sets *n_segs_out = 0) for DTAINT_NO_LABEL (0) or any
   label the file's tags table has no entry for -- both are normal (a
   comparison can have only one side tainted, or an untainted constant
   operand). The returned pointer is reader-owned; valid until
   dtaint_reader_free(). */
const struct dtaint_tag_seg_wire *dtaint_reader_resolve_label(
    const dtaint_reader_t *reader, u32 label, u32 *n_segs_out);

/* Looks up the magic-bytes snapshot for cond_list[cond_index], if any --
   most cond_list entries have none (only COND_FN_OP sites do). Returns
   NULL if there's no entry for that index. Reader-owned; valid until
   dtaint_reader_free(). */
const dtaint_reader_magic_t *dtaint_reader_get_magic(const dtaint_reader_t *reader,
                                                      u32 cond_index);

#ifdef __cplusplus
}
#endif

#endif
