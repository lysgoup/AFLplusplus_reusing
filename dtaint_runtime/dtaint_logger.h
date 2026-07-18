/*
   american fuzzy lop++ - dynamic taint tracking: track-file writer
   -----------------------------------------------------------------

   C port of Angora's runtime/src/logger.rs + common/src/log_data.rs. Owns
   the in-memory cond_list/tags/magic_bytes buffers and writes them out (via
   an atexit-style destructor) in the wire format declared in
   include/dtaint.h.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _DTAINT_LOGGER_H
#define _DTAINT_LOGGER_H

#include "dtaint.h"

/* Saves one comparison-site record, mirrors Logger::save: drops it silently
   if both labels are untainted, extracts a len_label sidecar record if
   present, computes `order` and drops the record if it exceeds
   DTAINT_MAX_COND_ORDER (repeated-site-per-execution cutoff), and resolves
   (dedup'd) both labels' TagSeg lists into the tags table. Returns the
   pushed record's index (>= 0) so a caller that also has magic bytes to
   attach (only COND_FN_OP sites) can call dtaint_logger_save_magic_bytes
   right after, or -1 if the record was dropped. */
int dtaint_logger_save(struct dtaint_cond_record *cond);

/* Attaches a raw-byte snapshot pair to the record at `cond_index` (as
   returned by dtaint_logger_save). Mirrors Logger::save_magic_bytes. */
void dtaint_logger_save_magic_bytes(int cond_index, const void *buf1, u32 len1,
                                    const void *buf2, u32 len2);

#endif
