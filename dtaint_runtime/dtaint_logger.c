/*
   american fuzzy lop++ - dynamic taint tracking: track-file writer
   -----------------------------------------------------------------

   Implementation. See dtaint_logger.h for the mapping back to
   runtime/src/logger.rs / common/src/log_data.rs.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtaint.h"
#include "dtaint_len_label.h"
#include "dtaint_tagset.h"

/* ---------------------------------------------------------------------- */
/* cond_list: Vec<CondStmtBase>                                           */
/* ---------------------------------------------------------------------- */

static struct dtaint_cond_record *cond_list = NULL;
static u32                        cond_list_len = 0;
static u32                        cond_list_cap = 0;

static int cond_list_push(struct dtaint_cond_record *c) {

  if (cond_list_len >= cond_list_cap) {

    u32 new_cap = cond_list_cap ? cond_list_cap * 2 : 1024;
    struct dtaint_cond_record *grown =
        realloc(cond_list, (size_t)new_cap * sizeof(struct dtaint_cond_record));
    if (!grown) abort();
    cond_list = grown;
    cond_list_cap = new_cap;

  }

  cond_list[cond_list_len] = *c;
  return (int)cond_list_len++;

}

/* ---------------------------------------------------------------------- */
/* tags: HashMap<u32, Vec<TagSeg>> -- dedup'd, resolved once per unique    */
/* label the first time any cond references it (mirrors Logger::save_tag).*/
/* ---------------------------------------------------------------------- */

#define TAG_SEGS_CAP 32

typedef struct {

  u32              label;
  u32              n_segs;
  dtaint_tag_seg_t segs[TAG_SEGS_CAP];

} tag_entry_t;

static tag_entry_t *tags = NULL;
static u32          tags_len = 0;
static u32          tags_cap = 0;

/* 1 bit per label id, sized to TagSet's own MAX_LB (1<<22) -- see
   dtaint_tagset.c. Allocated once, up front: 1<<22 bits = 512KiB, trivial
   next to the label arena itself. */
#define TAGS_SEEN_BITS ((size_t)1 << 22)
static uint8_t *tags_seen = NULL;

static int tag_seen(u32 label) {

  return (tags_seen[label >> 3] >> (label & 7)) & 1;

}

static void tag_mark_seen(u32 label) {

  tags_seen[label >> 3] |= (uint8_t)(1U << (label & 7));

}

static void save_tag(u32 lb) {

  if (lb == 0) return;

  if (!tags_seen) {

    tags_seen = calloc(TAGS_SEEN_BITS / 8, 1);
    if (!tags_seen) abort();

  }

  if (tag_seen(lb)) return;
  tag_mark_seen(lb);

  if (tags_len >= tags_cap) {

    u32 new_cap = tags_cap ? tags_cap * 2 : 256;
    tag_entry_t *grown = realloc(tags, (size_t)new_cap * sizeof(tag_entry_t));
    if (!grown) abort();
    tags = grown;
    tags_cap = new_cap;

  }

  tag_entry_t *e = &tags[tags_len++];
  e->label = lb;
  e->n_segs = dtaint_tagset_find(lb, e->segs, TAG_SEGS_CAP);
  if (e->n_segs > TAG_SEGS_CAP) e->n_segs = TAG_SEGS_CAP; /* see find()'s cap contract */

}

/* ---------------------------------------------------------------------- */
/* magic_bytes: HashMap<usize, (Vec<u8>, Vec<u8>)>                        */
/* ---------------------------------------------------------------------- */

#define MAGIC_BYTES_CAP 512

typedef struct {

  u32     cond_index;
  u32     len1;
  u32     len2;
  uint8_t buf1[MAGIC_BYTES_CAP];
  uint8_t buf2[MAGIC_BYTES_CAP];

} magic_bytes_entry_t;

static magic_bytes_entry_t *magic_bytes = NULL;
static u32                  magic_bytes_len = 0;
static u32                  magic_bytes_cap = 0;

void dtaint_logger_save_magic_bytes(int cond_index, const void *buf1, u32 len1,
                                    const void *buf2, u32 len2) {

  if (cond_index < 0) return;

  if (magic_bytes_len >= magic_bytes_cap) {

    u32 new_cap = magic_bytes_cap ? magic_bytes_cap * 2 : 128;
    magic_bytes_entry_t *grown =
        realloc(magic_bytes, (size_t)new_cap * sizeof(magic_bytes_entry_t));
    if (!grown) abort();
    magic_bytes = grown;
    magic_bytes_cap = new_cap;

  }

  magic_bytes_entry_t *e = &magic_bytes[magic_bytes_len++];
  e->cond_index = (u32)cond_index;
  e->len1 = (len1 > MAGIC_BYTES_CAP) ? MAGIC_BYTES_CAP : len1;
  e->len2 = (len2 > MAGIC_BYTES_CAP) ? MAGIC_BYTES_CAP : len2;
  if (e->len1) memcpy(e->buf1, buf1, e->len1);
  if (e->len2) memcpy(e->buf2, buf2, e->len2);

}

/* ---------------------------------------------------------------------- */
/* order_map: HashMap<(cmpid, context), u32> -- context is always 0 in    */
/* this port (see include/dtaint.h), so the key reduces to cmpid, and     */
/* since cmpid is a dense per-build monotonic counter, a plain growable    */
/* array indexed by cmpid stands in for the Rust HashMap. Mirrors          */
/* Logger::get_order exactly.                                              */
/* ---------------------------------------------------------------------- */

static u32 *order_counts = NULL;
static u32  order_counts_cap = 0;

static u32 get_order(struct dtaint_cond_record *cond) {

  u32 cmpid = cond->cmpid;

  if (cmpid >= order_counts_cap) {

    u32 new_cap = order_counts_cap ? order_counts_cap * 2 : 1024;
    while (cmpid >= new_cap) new_cap *= 2;
    u32 *grown = realloc(order_counts, (size_t)new_cap * sizeof(u32));
    if (!grown) abort();
    memset(grown + order_counts_cap, 0, (size_t)(new_cap - order_counts_cap) * sizeof(u32));
    order_counts = grown;
    order_counts_cap = new_cap;

  }

  u32 *order = &order_counts[cmpid];

  if (cond->order == 0) *order = *order + 1;
  cond->order += *order;

  return *order;

}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

int dtaint_logger_save(struct dtaint_cond_record *cond_in) {

  struct dtaint_cond_record cond = *cond_in;

  if (cond.lb1 == 0 && cond.lb2 == 0) return -1;

  struct dtaint_cond_record len_cond;
  int has_len = dtaint_len_label_extract(&cond, &len_cond);

  u32 order = 0;
  if (cond.op < DTAINT_COND_AFL_OP || cond.op == DTAINT_COND_FN_OP)
    order = get_order(&cond);

  if (order > DTAINT_MAX_COND_ORDER) return -1;

  save_tag(cond.lb1);
  save_tag(cond.lb2);
  int idx = cond_list_push(&cond);

  if (has_len) {

    len_cond.order = 0x10000U + order;
    cond_list_push(&len_cond);

  }

  return idx;

}

/* ---------------------------------------------------------------------- */
/* File writer -- fires once at process exit, mirrors Logger::fini.       */
/* ---------------------------------------------------------------------- */

static void dtaint_logger_fini(void) __attribute__((destructor));

static void dtaint_logger_fini(void) {

  if (cond_list_len == 0) return;

  const char *path = getenv(DTAINT_TRACK_ENV_VAR);
  if (!path) return;

  FILE *fp = fopen(path, "wb");
  if (!fp) return;

  struct dtaint_file_header header = {

      .magic = DTAINT_FILE_MAGIC,
      .version = DTAINT_FILE_VERSION,
      .n_conds = cond_list_len,
      .n_tags = tags_len,
      .n_magic_bytes = magic_bytes_len,

  };

  fwrite(&header, sizeof(header), 1, fp);
  if (cond_list_len) fwrite(cond_list, sizeof(struct dtaint_cond_record), cond_list_len, fp);

  for (u32 i = 0; i < tags_len; i++) {

    tag_entry_t *e = &tags[i];
    struct dtaint_tag_record rec = { .label = e->label, .n_segs = e->n_segs };
    fwrite(&rec, sizeof(rec), 1, fp);

    for (u32 j = 0; j < e->n_segs; j++) {

      struct dtaint_tag_seg_wire w = {
          .sign = e->segs[j].sign, .begin = e->segs[j].begin, .end = e->segs[j].end };
      fwrite(&w, sizeof(w), 1, fp);

    }

  }

  for (u32 i = 0; i < magic_bytes_len; i++) {

    magic_bytes_entry_t *e = &magic_bytes[i];
    struct dtaint_magic_bytes_record rec = {
        .cond_index = e->cond_index, .len1 = e->len1, .len2 = e->len2 };
    fwrite(&rec, sizeof(rec), 1, fp);
    if (e->len1) fwrite(e->buf1, 1, e->len1, fp);
    if (e->len2) fwrite(e->buf2, 1, e->len2, fp);

  }

  fclose(fp);

}
