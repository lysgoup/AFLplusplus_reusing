/*
   american fuzzy lop++ - dynamic taint tracking: length labels
   -----------------------------------------------------------------

   Implementation. See dtaint_len_label.h for the mapping back to
   runtime/src/len_label.rs.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdlib.h>

#include "dtaint.h"
#include "dtaint_len_label.h"

#define NORMAL_LABEL_WIDTH 22U
#define MAX_NORMAL_LABEL   ((1U << NORMAL_LABEL_WIDTH) - 1U)
#define MAX_LEN_LABEL      ((1U << 10) - 1U)
#define NORMAL_LABEL_MASK  MAX_NORMAL_LABEL
#define LEN_LABEL_MASK     MAX_LEN_LABEL

typedef struct { uint32_t offset; uint32_t size; } len_info_ent_t;

/* Index 0 is a reserved dummy, mirrors Rust's `vec![(0, 1)]` initial
   element (len sub-label ids start counting from index 1 in practice, since
   dtaint_len_label_new below only ever hands out ids >= len_info_len at
   push time, starting from len_info_len == 1). */
static len_info_ent_t *len_info = NULL;
static uint32_t        len_info_len = 0;
static uint32_t        len_info_cap = 0;

static void len_info_push(uint32_t offset, uint32_t size) {

  if (len_info_len >= len_info_cap) {

    uint32_t new_cap = len_info_cap ? len_info_cap * 2 : 256;
    len_info_ent_t *grown = realloc(len_info, (size_t)new_cap * sizeof(len_info_ent_t));
    if (!grown) { abort(); }
    len_info = grown;
    len_info_cap = new_cap;

  }

  len_info[len_info_len].offset = offset;
  len_info[len_info_len].size = size;
  len_info_len++;

}

int dtaint_len_label_is_len(dtaint_label_t lb) {

  return lb > MAX_NORMAL_LABEL;

}

static dtaint_label_t get_len_sublabel(dtaint_label_t lb) {

  return (lb >> NORMAL_LABEL_WIDTH) & LEN_LABEL_MASK;

}

dtaint_label_t dtaint_len_label_get_normal(dtaint_label_t lb) {

  return lb & NORMAL_LABEL_MASK;

}

static dtaint_label_t fat_label(dtaint_label_t normal_lb, dtaint_label_t len_lb) {

  return (len_lb << NORMAL_LABEL_WIDTH) | normal_lb;

}

dtaint_label_t dtaint_len_label_new(uint32_t offset, uint32_t size) {

  if (len_info_len == 0) len_info_push(0, 1); /* mirrors vec![(0,1)] seed */

  if (len_info_len < MAX_LEN_LABEL) {

    uint32_t lb = len_info_len;
    len_info_push(offset, size);
    return fat_label(0, lb);

  }

  return 0;

}

int dtaint_len_label_extract(struct dtaint_cond_record *cond,
                             struct dtaint_cond_record *len_cond) {

  uint32_t len_lb;

  if (dtaint_len_label_is_len(cond->lb1)) {

    len_lb = get_len_sublabel(cond->lb1);
    cond->lb1 = dtaint_len_label_get_normal(cond->lb1);

  } else if (dtaint_len_label_is_len(cond->lb2)) {

    len_lb = get_len_sublabel(cond->lb2);
    cond->lb2 = dtaint_len_label_get_normal(cond->lb2);

  } else {

    return 0;

  }

  if (len_lb > MAX_LEN_LABEL || len_lb >= len_info_len) return 0;

  *len_cond = *cond;
  len_cond->op = DTAINT_COND_LEN_OP;
  len_cond->lb1 = len_info[len_lb].offset;
  len_cond->lb2 = len_info[len_lb].size;

  return 1;

}
