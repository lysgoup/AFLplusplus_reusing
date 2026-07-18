/*
   american fuzzy lop++ - dynamic taint tracking: length labels
   -----------------------------------------------------------------

   C port of Angora's runtime/src/len_label.rs. A "length label" is a
   special marker packed into the *same* u32 as a normal TagSet label id,
   used to flag "this value is actually a byte count returned by a
   source call (read/fread/...), not raw tainted data" -- so a later
   comparison against that count can be logged as an extra COND_LEN_OP
   record carrying (source_offset, source_size) instead of a normal
   byte-offset-provenance record. This is what lets Angora's search
   recognize and mutate length-prefixed formats effectively.

   Bit layout mirrors len_label.rs exactly: bits [0,22) are a normal TagSet
   label id (see dtaint_tagset.h's LABEL_WIDTH), bits [22,32) are a "len
   sub-label" id indexing into a side table of (offset, size) pairs.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _DTAINT_LEN_LABEL_H
#define _DTAINT_LEN_LABEL_H

#include <stdint.h>

#include "dtaint_tagset.h"

/* Forward-declared here to avoid a circular include with dtaint_logger.h;
   defined in dtaint.h (the wire-format / CondStmtBase-equivalent). */
struct dtaint_cond_record;

int      dtaint_len_label_is_len(dtaint_label_t lb);
dtaint_label_t dtaint_len_label_get_normal(dtaint_label_t lb);

/* Records that the `size` bytes at file offset `offset` were the source of
   a length value (e.g. the return value of a read() call), and returns a
   fresh fat label for it. Mirrors __angora_get_len_label. */
dtaint_label_t dtaint_len_label_new(uint32_t offset, uint32_t size);

/* If `cond`'s lb1 or lb2 carries a length sub-label, strips it back down to
   the plain normal label in-place and returns 1, writing a second
   COND_LEN_OP-flavored record (mirroring len_label::get_len_cond) into
   `*len_cond` whose lb1/lb2 are repurposed to carry (offset, size) instead
   of TagSet label ids. Returns 0 (and leaves `*len_cond` untouched) if
   neither operand carried a length label. */
int dtaint_len_label_extract(struct dtaint_cond_record *cond,
                             struct dtaint_cond_record *len_cond);

#endif
