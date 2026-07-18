/*
   american fuzzy lop++ - dynamic taint tracking: label tree (TagSet)
   --------------------------------------------------------------------

   Faithful C port of Angora's runtime/src/tag_set.rs. This is the label
   representation Angora uses to make dynamic taint tracking efficient: each
   label is a node in a binary trie built over sorted, range-compressed
   segments of input-byte offsets (a `TagSeg { sign, begin, end }`), not a
   naive combine-tree of individual bytes -- combining two labels reuses
   shared ancestor structure instead of re-copying the offsets each already
   covers, and `find()` walks parent pointers to reconstruct the minimal set
   of TagSeg ranges a label covers.

   Ported algorithm-for-algorithm (insert/insert_n_zeros/insert_n_ones/
   combine/combine_n/infer_shape/infer_shape2/split_and_op/set_sign/
   get_sign/find) -- see tag_set.rs for the original comments explaining
   *why* each piece of the tree-shape logic exists; this file mirrors that
   structure rather than re-deriving it.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _DTAINT_TAGSET_H
#define _DTAINT_TAGSET_H

#include <stdint.h>

typedef uint32_t dtaint_label_t;

/* Mirrors tag_set.rs's TagSeg (angora_common::tag::TagSeg). */
typedef struct {

  uint8_t  sign;
  uint32_t begin;
  uint32_t end;

} dtaint_tag_seg_t;

#define DTAINT_TAGSET_ROOT 0

/* Must be called once before any other dtaint_tagset_* call. */
void dtaint_tagset_init(void);

/* Inserts a fresh single-byte label at file offset `offset` (a new leaf
   segment [offset, offset+1)). Mirrors TagSet::insert. */
dtaint_label_t dtaint_tagset_insert(uint32_t offset);

/* Unions two labels into one covering both their offset ranges.
   DTAINT_TAGSET_ROOT (0) is the identity element. Mirrors TagSet::combine. */
dtaint_label_t dtaint_tagset_combine(dtaint_label_t l1, dtaint_label_t l2);

/* Combines a sequence of labels (e.g. the per-byte labels underlying a
   multi-byte load), optionally applying shape inference (`infer`): if the
   labels are `len` (2, 4, or 8) *adjacent*, single-offset, unrelated labels,
   they're recognized as one grouped variable instead of `len` separate
   single-byte segments. Mirrors TagSet::combine_n. */
dtaint_label_t dtaint_tagset_combine_n(const dtaint_label_t *lbs, uint32_t n,
                                       int infer);

/* Marks a label's underlying value as coming from a signed context (e.g. a
   signed icmp/sdiv/srem/ashr, or an nsw-flagged binop). Mirrors
   TagSet::set_sign / DFSan's DFSanMarkSignedFn. */
void dtaint_tagset_set_sign(dtaint_label_t lb);
int  dtaint_tagset_get_sign(dtaint_label_t lb);

/* Marks a label as having been masked with a compile-time-constant via `&`
   (e.g. `x & 0xFF`) -- find() will lazily split its segment shape to reflect
   that only the masked bits are really "one variable" the next time it's
   looked up. Mirrors TagSet::combine_and / DFSan's DFSanCombineAndFn. */
void dtaint_tagset_combine_and(dtaint_label_t lb);

/* Shape inference for arithmetic (not load) contexts: if `lb`'s underlying
   value is one byte of a `len`-byte group (walking `len - 1` parent hops
   lands on a common ancestor of the right size), widen `lb`'s segment to
   cover the whole group. Mirrors TagSet::infer_shape2 / DFSan's
   dfsan_infer_shape_in_math_op, called from the cmp-site hook on both
   operands (mirrors track.rs's infer_shape wrapper). */
void dtaint_tagset_infer_shape2(dtaint_label_t lb, uint32_t len);

/* Reconstructs the minimal list of TagSeg ranges `lb` covers, writing up to
   `cap` entries into `out` (in ascending-offset order) and returning the
   true count (may exceed `cap`; only the first `cap` were written). Mirrors
   TagSet::find. A no-op / returns 0 for lb == DTAINT_TAGSET_ROOT. */
uint32_t dtaint_tagset_find(dtaint_label_t lb, dtaint_tag_seg_t *out,
                            uint32_t cap);

/* Diagnostic only, mirrors TagSet::get_num_nodes. */
uint32_t dtaint_tagset_num_nodes(void);

#endif
