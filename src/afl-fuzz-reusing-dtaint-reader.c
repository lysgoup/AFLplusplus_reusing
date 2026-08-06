/*
   american fuzzy lop++ - reusing pool: .dtaint file reader
   -----------------------------------------------------------------

   Implementation. See include/reusing_dtaint_reader.h for the contract
   and dtaint_runtime/dtaint_logger.c for the writer this mirrors --
   every read here matches a fwrite there field-for-field, in the same
   order (header, cond_list, tags (+segs each), magic_bytes (+buf1/buf2
   each)).

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include <stdio.h>
#include <stdlib.h>

#include "reusing_dtaint_reader.h"

#define READER_HASH_EMPTY 0xFFFFFFFFU

struct dtaint_reader {

  struct dtaint_cond_record *conds;
  u32                        n_conds;

  dtaint_reader_tag_t *tags;
  u32                  n_tags;
  u32                 *tag_hash_keys; /* label, or READER_HASH_EMPTY */
  u32                 *tag_hash_vals; /* index into tags[] */
  u32                  tag_hash_cap;

  dtaint_reader_magic_t *magic;
  u32                    n_magic;
  u32                   *magic_hash_keys; /* cond_index, or READER_HASH_EMPTY */
  u32                   *magic_hash_vals; /* index into magic[] */
  u32                    magic_hash_cap;

};

/* Plain open-addressing insert/lookup, same shape as dtaint_logger.c's
   order_map and reusing_pool.c's slots table -- but sized once up front
   here (both key spaces' final sizes are known from the file header
   before any entry is read) rather than grown incrementally, so there's
   no separate grow() path to keep in sync with insert()'s probing. */
static void hash_insert(u32 *keys, u32 *vals, u32 cap, u32 key, u32 val) {

  u32 idx = key % cap;
  while (keys[idx] != READER_HASH_EMPTY) idx = (idx + 1) % cap;
  keys[idx] = key;
  vals[idx] = val;

}

static int hash_lookup(const u32 *keys, const u32 *vals, u32 cap, u32 key,
                       u32 *val_out) {

  if (cap == 0) return 0;

  u32 idx = key % cap;
  u32 probed = 0;

  while (keys[idx] != READER_HASH_EMPTY) {

    if (keys[idx] == key) { *val_out = vals[idx]; return 1; }
    idx = (idx + 1) % cap;
    if (++probed >= cap) break; /* table is full of misses -- not found */

  }

  return 0;

}

void dtaint_reader_free(dtaint_reader_t *reader) {

  if (!reader) return;

  free(reader->conds);

  for (u32 i = 0; i < reader->n_tags; i++) free(reader->tags[i].segs);
  free(reader->tags);
  free(reader->tag_hash_keys);
  free(reader->tag_hash_vals);

  for (u32 i = 0; i < reader->n_magic; i++) {

    free(reader->magic[i].buf1);
    free(reader->magic[i].buf2);

  }

  free(reader->magic);
  free(reader->magic_hash_keys);
  free(reader->magic_hash_vals);

  free(reader);

}

dtaint_reader_t *dtaint_reader_load(const char *path) {

  FILE *fp = fopen(path, "rb");
  if (!fp) return NULL;

  struct dtaint_file_header header;
  if (fread(&header, sizeof(header), 1, fp) != 1) { fclose(fp); return NULL; }

  if (header.magic != DTAINT_FILE_MAGIC || header.version != DTAINT_FILE_VERSION) {

    fclose(fp);
    return NULL;

  }

  dtaint_reader_t *reader = calloc(1, sizeof(dtaint_reader_t));
  if (!reader) abort();

  /* cond_list */

  reader->n_conds = header.n_conds;

  if (reader->n_conds) {

    reader->conds = malloc((size_t)reader->n_conds * sizeof(struct dtaint_cond_record));
    if (!reader->conds) abort();

    if (fread(reader->conds, sizeof(struct dtaint_cond_record), reader->n_conds, fp) !=
        reader->n_conds) {

      dtaint_reader_free(reader);
      fclose(fp);
      return NULL;

    }

  }

  /* tags: n_tags * (dtaint_tag_record + n_segs dtaint_tag_seg_wire) */

  reader->n_tags = header.n_tags;

  if (reader->n_tags) {

    reader->tags = calloc(reader->n_tags, sizeof(dtaint_reader_tag_t));
    if (!reader->tags) abort();

    reader->tag_hash_cap = reader->n_tags * 2;
    reader->tag_hash_keys = malloc((size_t)reader->tag_hash_cap * sizeof(u32));
    reader->tag_hash_vals = malloc((size_t)reader->tag_hash_cap * sizeof(u32));
    if (!reader->tag_hash_keys || !reader->tag_hash_vals) abort();
    for (u32 i = 0; i < reader->tag_hash_cap; i++) reader->tag_hash_keys[i] = READER_HASH_EMPTY;

    for (u32 i = 0; i < reader->n_tags; i++) {

      struct dtaint_tag_record rec;
      if (fread(&rec, sizeof(rec), 1, fp) != 1) { dtaint_reader_free(reader); fclose(fp); return NULL; }

      reader->tags[i].label = rec.label;
      reader->tags[i].n_segs = rec.n_segs;

      if (rec.n_segs) {

        reader->tags[i].segs = malloc((size_t)rec.n_segs * sizeof(struct dtaint_tag_seg_wire));
        if (!reader->tags[i].segs) abort();

        if (fread(reader->tags[i].segs, sizeof(struct dtaint_tag_seg_wire), rec.n_segs, fp) !=
            rec.n_segs) {

          dtaint_reader_free(reader);
          fclose(fp);
          return NULL;

        }

      }

      hash_insert(reader->tag_hash_keys, reader->tag_hash_vals, reader->tag_hash_cap, rec.label, i);

    }

  }

  /* magic_bytes: n_magic_bytes * (dtaint_magic_bytes_record + len1 + len2 raw bytes) */

  reader->n_magic = header.n_magic_bytes;

  if (reader->n_magic) {

    reader->magic = calloc(reader->n_magic, sizeof(dtaint_reader_magic_t));
    if (!reader->magic) abort();

    reader->magic_hash_cap = reader->n_magic * 2;
    reader->magic_hash_keys = malloc((size_t)reader->magic_hash_cap * sizeof(u32));
    reader->magic_hash_vals = malloc((size_t)reader->magic_hash_cap * sizeof(u32));
    if (!reader->magic_hash_keys || !reader->magic_hash_vals) abort();
    for (u32 i = 0; i < reader->magic_hash_cap; i++) reader->magic_hash_keys[i] = READER_HASH_EMPTY;

    for (u32 i = 0; i < reader->n_magic; i++) {

      struct dtaint_magic_bytes_record rec;
      if (fread(&rec, sizeof(rec), 1, fp) != 1) { dtaint_reader_free(reader); fclose(fp); return NULL; }

      reader->magic[i].cond_index = rec.cond_index;
      reader->magic[i].len1 = rec.len1;
      reader->magic[i].len2 = rec.len2;

      if (rec.len1) {

        reader->magic[i].buf1 = malloc(rec.len1);
        if (!reader->magic[i].buf1) abort();
        if (fread(reader->magic[i].buf1, 1, rec.len1, fp) != rec.len1) {

          dtaint_reader_free(reader);
          fclose(fp);
          return NULL;

        }

      }

      if (rec.len2) {

        reader->magic[i].buf2 = malloc(rec.len2);
        if (!reader->magic[i].buf2) abort();
        if (fread(reader->magic[i].buf2, 1, rec.len2, fp) != rec.len2) {

          dtaint_reader_free(reader);
          fclose(fp);
          return NULL;

        }

      }

      hash_insert(reader->magic_hash_keys, reader->magic_hash_vals, reader->magic_hash_cap,
                 rec.cond_index, i);

    }

  }

  fclose(fp);
  return reader;

}

const struct dtaint_cond_record *dtaint_reader_conds(const dtaint_reader_t *reader,
                                                      u32 *n_conds_out) {

  if (n_conds_out) *n_conds_out = reader->n_conds;
  return reader->conds;

}

const struct dtaint_tag_seg_wire *dtaint_reader_resolve_label(
    const dtaint_reader_t *reader, u32 label, u32 *n_segs_out) {

  if (n_segs_out) *n_segs_out = 0;
  if (label == DTAINT_NO_LABEL) return NULL;

  u32 idx;
  if (!hash_lookup(reader->tag_hash_keys, reader->tag_hash_vals, reader->tag_hash_cap, label,
                   &idx)) {

    return NULL;

  }

  if (n_segs_out) *n_segs_out = reader->tags[idx].n_segs;
  return reader->tags[idx].segs;

}

const dtaint_reader_magic_t *dtaint_reader_get_magic(const dtaint_reader_t *reader,
                                                      u32 cond_index) {

  u32 idx;
  if (!hash_lookup(reader->magic_hash_keys, reader->magic_hash_vals, reader->magic_hash_cap,
                   cond_index, &idx)) {

    return NULL;

  }

  return &reader->magic[idx];

}
