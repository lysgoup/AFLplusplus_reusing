/*
   american fuzzy lop++ - dynamic taint tracking runtime
   -------------------------------------------------------

   Minimal DFSan-style runtime, ported from Angora's runtime/src/tag_set.rs
   (label combine-tree) and runtime/src/logger.rs (track-file writer) --
   see include/dtaint.h and the plan this was scoped from for the full
   context and the deliberate simplifications this slice makes:

     - shadow_table below is a fixed-size, direct-mapped, address-hashed
       array, NOT real shadow memory (no page-remapped address translation).
       Collisions across unrelated live allocations are possible in a long
       session; acceptable only for this slice's short validation runs.
     - label_arena is a minimal combine-tree (mirrors tag_set.rs's TagNode
       DAG) with no shape-inference/interval-range sophistication.
     - Track-file records are buffered in memory and flushed once at exit,
       not streamed incrementally -- fine for a handful of comparisons, not
       a general solution.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dtaint.h"

/* ---------------------------------------------------------------------- */
/* Address-keyed shadow store (NOT real shadow memory -- see file header). */
/* ---------------------------------------------------------------------- */

#define DTAINT_SHADOW_BITS 24
#define DTAINT_SHADOW_SIZE (1U << DTAINT_SHADOW_BITS)
#define DTAINT_SHADOW_MASK (DTAINT_SHADOW_SIZE - 1U)

static u32 shadow_table[DTAINT_SHADOW_SIZE];

static inline u32 shadow_slot(const void *ptr) {

  /* No shift: this table is addressed at *byte* granularity, so each
     distinct byte address needs its own slot. An earlier version shifted
     by 2 (a word-alignment hash), which silently collided every 4
     consecutive byte addresses onto the same slot -- confirmed by direct
     testing (adjacent single-byte loads returned identical labels). */
  return (u32)((uintptr_t)ptr & DTAINT_SHADOW_MASK);

}

/* ---------------------------------------------------------------------- */
/* Label arena: minimal combine-tree, mirrors tag_set.rs's TagNode DAG.    */
/* Label 0 (DTAINT_NO_LABEL) is reserved and never a valid arena index.    */
/* ---------------------------------------------------------------------- */

#define DTAINT_MAX_LABELS (1U << 20)

struct dtaint_node {

  u32 left;         /* 0,0 => leaf */
  u32 right;
  u32 byte_offset;  /* valid only when left == right == 0 */

};

static struct dtaint_node label_arena[DTAINT_MAX_LABELS];
static u32                label_count = 1; /* 0 reserved for "no taint" */

u32 __dtaint_combine(u32 l1, u32 l2) {

  if (l1 == DTAINT_NO_LABEL) return l2;
  if (l2 == DTAINT_NO_LABEL || l1 == l2) return l1;

  if (label_count >= DTAINT_MAX_LABELS) {

    /* Saturate rather than crash -- acceptable for this slice's tiny test
       programs; a real target would need a bigger arena or a proper
       hash-consed tree. */
    return l1;

  }

  u32 lb = label_count++;
  label_arena[lb].left = l1;
  label_arena[lb].right = l2;
  label_arena[lb].byte_offset = 0;
  return lb;

}

static u32 new_leaf_label(u32 byte_offset) {

  if (label_count >= DTAINT_MAX_LABELS) return DTAINT_NO_LABEL;

  u32 lb = label_count++;
  label_arena[lb].left = 0;
  label_arena[lb].right = 0;
  label_arena[lb].byte_offset = byte_offset;
  return lb;

}

/* Recursive walk of the combine-tree back down to leaf byte-offsets --
   the "which bytes does this label's provenance cover" answer this whole
   slice exists to validate. `cap` bounds `out` to avoid overflow; silently
   stops collecting past it (fine for this slice's small test programs). */
static void collect_offsets(u32 label, u32 *out, u32 *out_n, u32 cap) {

  if (label == DTAINT_NO_LABEL || *out_n >= cap) return;

  struct dtaint_node *n = &label_arena[label];

  if (n->left == 0 && n->right == 0) {

    out[(*out_n)++] = n->byte_offset;
    return;

  }

  collect_offsets(n->left, out, out_n, cap);
  collect_offsets(n->right, out, out_n, cap);

}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

void dtaint_source_buf(const void *ptr, u64 len) {

  for (u64 i = 0; i < len; i++) {

    u32 lb = new_leaf_label((u32)i);
    shadow_table[shadow_slot((const char *)ptr + i)] = lb;

  }

}

u32 __dtaint_load(void *ptr, u64 size) {

  u32 lb = DTAINT_NO_LABEL;

  for (u64 i = 0; i < size; i++) {

    u32 cur = shadow_table[shadow_slot((char *)ptr + i)];
    lb = __dtaint_combine(lb, cur);

  }

  return lb;

}

void __dtaint_store(void *ptr, u64 size, u32 label) {

  for (u64 i = 0; i < size; i++)
    shadow_table[shadow_slot((char *)ptr + i)] = label;

}

/* ---------------------------------------------------------------------- */
/* Track-file writer: buffered in memory, flushed at process exit.        */
/* ---------------------------------------------------------------------- */

#define DTAINT_MAX_RECORDS 65536
#define DTAINT_MAX_OFFSETS_PER_RECORD 256

struct buffered_record {

  struct dtaint_record hdr;
  u32                  offsets[DTAINT_MAX_OFFSETS_PER_RECORD];

};

static struct buffered_record *records = NULL;
static u32                     record_count = 0;

void __dtaint_trace_cmp(u32 cmpid, u32 op, u32 size, u64 arg1, u64 arg2, u32 cond,
                         u32 l1, u32 l2) {

  if (l1 == DTAINT_NO_LABEL && l2 == DTAINT_NO_LABEL) return;

  if (!records) {

    records = calloc(DTAINT_MAX_RECORDS, sizeof(struct buffered_record));
    if (!records) return;

  }

  if (record_count >= DTAINT_MAX_RECORDS) return; /* drop, don't crash */

  struct buffered_record *r = &records[record_count];
  u32                     n = 0;

  collect_offsets(l1, r->offsets, &n, DTAINT_MAX_OFFSETS_PER_RECORD);
  collect_offsets(l2, r->offsets, &n, DTAINT_MAX_OFFSETS_PER_RECORD);

  r->hdr.cmpid = cmpid;
  r->hdr.op = op;
  r->hdr.size = size;
  r->hdr.cond = cond;
  r->hdr.arg1 = arg1;
  r->hdr.arg2 = arg2;
  r->hdr.lb1 = l1;
  r->hdr.lb2 = l2;
  r->hdr.n_offsets = n;

  record_count++;

}

static void dtaint_fini(void) __attribute__((destructor));

static void dtaint_fini(void) {

  if (record_count == 0) return;

  const char *path = getenv(DTAINT_TRACK_ENV_VAR);
  if (!path) return;

  FILE *fp = fopen(path, "wb");
  if (!fp) return;

  struct dtaint_file_header header = {
      .magic = DTAINT_FILE_MAGIC,
      .version = DTAINT_FILE_VERSION,
      .n_records = record_count,
  };

  fwrite(&header, sizeof(header), 1, fp);

  for (u32 i = 0; i < record_count; i++) {

    struct buffered_record *r = &records[i];
    fwrite(&r->hdr, sizeof(r->hdr), 1, fp);
    if (r->hdr.n_offsets > 0)
      fwrite(r->offsets, sizeof(u32), r->hdr.n_offsets, fp);

  }

  fclose(fp);

}

/* Note: dtaint_exec_child (the forkserver child-exec hook) is fuzzer-side
   code that runs inside afl-fuzz's forked child, not inside the
   instrumented target -- it lives in src/afl-fuzz-dtaint.c (Piece 3), not
   here. This file only contains code that gets linked into the target
   binary itself. */
