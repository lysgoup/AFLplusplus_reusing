/*
   american fuzzy lop++ - dynamic taint tracking: label tree (TagSet)
   --------------------------------------------------------------------

   Implementation. See dtaint_tagset.h for the API-level mapping back to
   runtime/src/tag_set.rs; comments here focus on where this C port departs
   mechanically from the Rust (growable array via realloc instead of Vec,
   explicit stack arrays instead of Vec<usize>, Option<usize> modeled as a
   `0 means None` sentinel since label 0 is reserved and never a real
   match) -- the *algorithm* is an unmodified line-for-line translation.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtaint_tagset.h"

/* Mirrors tag_set.rs's LABEL_WITDH/MAX_LB exactly: labels share their u32
   with len_label.rs's fat-label bit-packing (a len sub-label id lives in the
   upper 10 bits, see dtaint_len_label.h), so the "normal" label space is
   capped at 22 bits, not the full 32. */
#define LABEL_WIDTH 22
#define MAX_LB      ((1U << LABEL_WIDTH) - 1U)
#define ROOT        0U

typedef struct {

  uint32_t left;
  uint32_t right;
  uint32_t parent;
  uint8_t  and_op;
  uint8_t  sign;
  uint32_t begin;
  uint32_t end;

} tag_node_t;

static tag_node_t *nodes = NULL;
static uint32_t    nodes_len = 0;
static uint32_t    nodes_cap = 0;

static inline uint32_t seg_size(uint32_t lb) {

  return nodes[lb].end - nodes[lb].begin;

}

void dtaint_tagset_init(void) {

  if (nodes) return;

  nodes_cap = 1U << 12;
  nodes = calloc(nodes_cap, sizeof(tag_node_t));
  if (!nodes) { perror("dtaint_tagset: calloc"); abort(); }

  /* nodes[ROOT] = TagNode::new(ROOT, 0, 0) -- already all-zero via calloc. */
  nodes_len = 1;

}

static uint32_t new_node(uint32_t parent, uint32_t begin, uint32_t end) {

  if (nodes_len >= MAX_LB) {

    fprintf(stderr, "[dtaint] more than %u label nodes..\n", MAX_LB);
    abort();

  }

  if (nodes_len >= nodes_cap) {

    uint32_t new_cap = nodes_cap * 2;
    tag_node_t *grown = realloc(nodes, (size_t)new_cap * sizeof(tag_node_t));
    if (!grown) { perror("dtaint_tagset: realloc"); abort(); }
    memset(grown + nodes_cap, 0, (size_t)(new_cap - nodes_cap) * sizeof(tag_node_t));
    nodes = grown;
    nodes_cap = new_cap;

  }

  uint32_t lb = nodes_len++;
  nodes[lb].left = 0;
  nodes[lb].right = 0;
  nodes[lb].parent = parent;
  nodes[lb].and_op = 0;
  nodes[lb].sign = 0;
  nodes[lb].begin = begin;
  nodes[lb].end = end;
  return lb;

}

/* Mirrors TagSet::insert_n_zeros. */
static uint32_t insert_n_zeros(uint32_t cur_lb, uint32_t num, uint32_t last_one_lb) {

  uint32_t n = num;

  while (n != 0) {

    uint32_t next = nodes[cur_lb].left;
    uint32_t next_size = seg_size(next);

    if (next == 0) {

      uint32_t off = nodes[cur_lb].end;
      uint32_t new_lb = new_node(last_one_lb, off, off + n);
      nodes[cur_lb].left = new_lb;
      cur_lb = new_lb;
      n = 0;

    } else if (next_size > n) {

      uint32_t off = nodes[cur_lb].end;
      uint32_t new_lb = new_node(last_one_lb, off, off + n);
      nodes[cur_lb].left = new_lb;
      nodes[new_lb].left = next;
      nodes[next].begin = off + n;
      cur_lb = new_lb;
      n = 0;

    } else {

      cur_lb = next;
      n -= next_size;

    }

  }

  return cur_lb;

}

/* Mirrors TagSet::insert_n_ones. */
static uint32_t insert_n_ones(uint32_t cur_lb, uint32_t num, uint32_t last_one_lb) {

  uint32_t n = num;

  while (n != 0) {

    uint32_t next = nodes[cur_lb].right;
    uint32_t last_end = nodes[cur_lb].end;

    if (next == 0) {

      uint32_t off = last_end;
      uint32_t new_lb = new_node(last_one_lb, off, off + n);
      nodes[cur_lb].right = new_lb;
      cur_lb = new_lb;
      n = 0;

    } else {

      uint32_t next_end = nodes[next].end;
      uint32_t next_size = next_end - last_end;

      if (next_size > n) {

        uint32_t off = last_end;
        uint32_t new_lb = new_node(last_one_lb, off, off + n);
        nodes[cur_lb].right = new_lb;
        nodes[new_lb].right = next;
        nodes[next].parent = new_lb;
        nodes[next].begin = off + n;
        cur_lb = new_lb;
        n = 0;

      } else {

        cur_lb = next;
        n -= next_size;

      }

    }

    last_one_lb = cur_lb;

  }

  return cur_lb;

}

dtaint_label_t dtaint_tagset_insert(uint32_t offset) {

  /* Lazy self-init: in the real-DFSan build, the first call into this
     module can happen from a source wrapper (e.g. __dfsw_read) called
     during normal execution, well after any unsafe-to-malloc early-init
     window -- but there is no other guaranteed call site that runs first,
     so every public entry point guards itself. Confirmed necessary by a
     real SIGSEGV (nodes was still NULL here without this). */
  dtaint_tagset_init();

  uint32_t cur_lb = insert_n_zeros(ROOT, offset, ROOT);
  cur_lb = insert_n_ones(cur_lb, 1, ROOT);
  return cur_lb;

}

void dtaint_tagset_set_sign(dtaint_label_t lb) {

  if (lb != 0 && lb < nodes_len) nodes[lb].sign = 1;

}

int dtaint_tagset_get_sign(dtaint_label_t lb) {

  return (lb != 0 && lb < nodes_len) ? nodes[lb].sign : 0;

}

void dtaint_tagset_combine_and(dtaint_label_t lb) {

  if (lb != 0 && lb < nodes_len) nodes[lb].and_op = 1;

}

/* Mirrors TagSet::split_and_op -- note the Rust always returns its `lb`
   argument unchanged (it only ever mutates seg.begin in place / inserts
   nodes elsewhere in the tree), so this C port does too. */
static uint32_t split_and_op(uint32_t lb) {

  uint32_t begin = nodes[lb].begin;
  uint32_t end = nodes[lb].end;

  if (end - begin > 1) {

    uint32_t p = nodes[lb].parent;

    if (p != ROOT && nodes[p].begin >= begin) {

      if (nodes[p].end < end) {

        uint32_t cur_lb = p;
        while (cur_lb != lb) cur_lb = insert_n_ones(cur_lb, 1, cur_lb);

      }

      nodes[lb].begin = end - 1;

    }

  }

  return lb;

}

/* Mirrors TagSet::infer_shape (internal helper of combine_n). Returns 0
   (ROOT, never a valid match) to mean Rust's None. */
static uint32_t infer_shape(uint32_t l1, uint32_t l2, uint32_t len) {

  if (len != 2 && len != 4 && len != 8) return 0;

  /* assume l1 < l2 */
  if (nodes[l1].parent == ROOT && nodes[l2].parent == ROOT &&
      nodes[l1].begin + len == nodes[l2].end) {

    uint32_t cur_lb = insert_n_ones(l1, len - 1, l1);
    nodes[cur_lb].begin = nodes[l1].begin;
    return cur_lb;

  }

  return 0;

}

void dtaint_tagset_infer_shape2(dtaint_label_t lb, uint32_t len) {

  /* Bounds check before the first nodes[] access, unlike set_sign/get_sign/
     combine_and above -- this was the site of a real SIGSEGV: a length
     label (see dtaint_len_label.h) that reached here unstripped decodes to
     a huge out-of-range "label" (e.g. 1<<22), and this function, unlike
     those three, had no `lb < nodes_len` guard at all. The actual fix is
     stripping length labels before they ever reach here (dfsan.cc's
     dfsan_infer_shape_in_math_op, dtaint_legacy_hooks.c's cmp/switch
     hooks); this bounds check is defense in depth, not a substitute. */
  if (lb == ROOT || lb >= nodes_len || nodes[lb].begin + 1 < nodes[lb].end) return;

  uint32_t cur_lb = lb;

  for (uint32_t i = 0; i + 1 < len; i++) {

    cur_lb = nodes[cur_lb].parent;
    if (cur_lb == ROOT) return;

  }

  if (nodes[cur_lb].parent == ROOT) {

    if (nodes[cur_lb].begin + len == nodes[lb].end)
      nodes[lb].begin = nodes[cur_lb].begin;

  }

}

dtaint_label_t dtaint_tagset_combine(dtaint_label_t l1, dtaint_label_t l2) {

  dtaint_tagset_init(); /* defensive; see dtaint_tagset_insert()'s comment */

  if (l1 == 0) return l2;
  if (l2 == 0 || l1 == l2) return l1;

  if (l1 > l2) { uint32_t t = l1; l1 = l2; l2 = t; }

  /* Rust uses an unbounded Vec<usize> stack here; this slice caps it -- see
     dtaint_tagset.h's documented scale cutoffs. Deep combine chains (many
     thousands of distinct byte-offset ancestors merged into one label)
     would need a growable stack; not expected for validation-scale
     targets. */
  #define COMBINE_STACK_CAP 8192
  static uint32_t lb_st[COMBINE_STACK_CAP];
  uint32_t        lb_st_n = 0;

  uint32_t last_begin = MAX_LB;

  while (l1 > 0 && l1 != l2) {

    uint32_t b1 = nodes[l1].begin;
    uint32_t b2 = nodes[l2].begin;

    if (b1 < b2) {

      if (b2 < last_begin) {

        if (lb_st_n < COMBINE_STACK_CAP) lb_st[lb_st_n++] = l2;
        last_begin = b2;

      }

      l2 = nodes[l2].parent;

    } else {

      if (b1 < last_begin) {

        if (lb_st_n < COMBINE_STACK_CAP) lb_st[lb_st_n++] = l1;
        last_begin = b1;

      }

      l1 = nodes[l1].parent;

    }

  }

  uint32_t cur_lb = (l1 > 0) ? l1 : l2;

  while (lb_st_n > 0) {

    uint32_t cur_end = nodes[cur_lb].end;
    uint32_t next = lb_st[--lb_st_n];
    uint32_t next_begin = nodes[next].begin;
    uint32_t next_end = nodes[next].end;
    uint8_t  next_sign = nodes[next].sign;

    if (cur_end >= next_begin) {

      if (next_end > cur_end) cur_lb = insert_n_ones(cur_lb, next_end - cur_end, cur_lb);

    } else {

      uint32_t last_lb = cur_lb;
      uint32_t gap = next_begin - cur_end;
      cur_lb = insert_n_zeros(cur_lb, gap, last_lb);
      uint32_t size = next_end - next_begin;
      cur_lb = insert_n_ones(cur_lb, size, last_lb);

    }

    if (next_sign) nodes[cur_lb].sign = 1;

  }

  #undef COMBINE_STACK_CAP
  return cur_lb;

}

dtaint_label_t dtaint_tagset_combine_n(const dtaint_label_t *lbs, uint32_t n, int infer) {

  dtaint_tagset_init(); /* defensive; see dtaint_tagset_insert()'s comment */

  uint32_t i = 0;
  while (i < n && lbs[i] == ROOT) i++;

  if (i >= n) return ROOT;

  uint32_t cur_lb = lbs[i];
  uint32_t last_lb = lbs[n - 1];

  uint32_t next_i = i + 1;
  if (next_i >= n) return cur_lb;

  if (infer) {

    uint32_t shaped = infer_shape(cur_lb, last_lb, n - i);
    if (shaped != 0) return shaped;

  }

  for (; next_i < n; next_i++) cur_lb = dtaint_tagset_combine(cur_lb, lbs[next_i]);

  return cur_lb;

}

uint32_t dtaint_tagset_find(dtaint_label_t lb, dtaint_tag_seg_t *out, uint32_t cap) {

  dtaint_tagset_init(); /* defensive; see dtaint_tagset_insert()'s comment */

  /* Defensive bounds check, same rationale as dtaint_tagset_infer_shape2:
     an out-of-range (e.g. unstripped length-label) `lb` must never reach
     nodes[lb] below. */
  if (lb >= nodes_len) return 0;

  uint32_t n = 0;
  uint32_t last_begin = MAX_LB;

  /* Collect in descending-offset order first (walking parent pointers, like
     the Rust does), then reverse into ascending order at the end -- mirrors
     TagSet::find's `if tag_list.len() > 1 { tag_list.reverse(); }`. Buffered
     locally (not directly into `out`) so we can report the true total count
     even when it exceeds `cap`, same contract as the header documents. */
  #define FIND_STACK_CAP 4096
  static dtaint_tag_seg_t tmp[FIND_STACK_CAP];

  while (lb > 0) {

    if (nodes[lb].and_op) lb = split_and_op(lb);

    uint32_t begin = nodes[lb].begin;
    uint32_t end = nodes[lb].end;
    uint8_t  sign = nodes[lb].sign;

    if (begin < last_begin) {

      if (n < FIND_STACK_CAP) {

        tmp[n].sign = sign;
        tmp[n].begin = begin;
        tmp[n].end = end;

      }

      n++;
      last_begin = begin;

    }

    lb = nodes[lb].parent;

  }

  uint32_t total = n;
  uint32_t written = (n > FIND_STACK_CAP) ? FIND_STACK_CAP : n;

  if (written > cap) written = cap;

  /* tmp[] is in descending-begin order; reverse into `out`. */
  for (uint32_t k = 0; k < written; k++) out[k] = tmp[(n > FIND_STACK_CAP ? FIND_STACK_CAP : n) - 1 - k];

  #undef FIND_STACK_CAP
  return total;

}

uint32_t dtaint_tagset_num_nodes(void) {

  return nodes_len;

}
