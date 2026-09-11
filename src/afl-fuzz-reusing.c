/*
   american fuzzy lop++ - reusing taint data
   -----------------------------------------

   Loads what afl-taint-scan produced ahead of time for this target,
   pointed at by -r:

     value_pool.dict     - value candidates, one entry per line, each entry
                           one or more segments (see struct value_pool_entry)
     unsolved_condition  - (cmpid, context) sites never seen going more than
                           one way

   Both are currently mandatory once -r is given: a missing or unreadable
   file is FATAL. That is deliberately strict for now -- while the reuse
   path is being built out, a campaign that quietly fuzzed on with an empty
   pool would be indistinguishable from a baseline run afterwards. Relax to
   a warning plus an empty structure once running without a pool is a
   meaningful configuration.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include "afl-fuzz.h"

#include <ctype.h>

/* Must stay >= afl-taint-scan's own WORKER_DICT_MAX_ENTRY_LEN, which
   is what actually bounds segment width on the writing side. A segment
   longer than this is treated as a malformed line rather than overrunning
   the decode buffer. */
#define REUSING_MAX_SEG_LEN 4096

/* Segments per entry, bounding a value_pool.dict line together with the
   above: dict_add_group() refuses a group wider than this. */
#define REUSING_MAX_SEGS_PER_ENTRY 64

/* Longest value_pool.dict line the worker can therefore emit, since
   dict_write_escaped() expands one byte to at most 4 characters (\xNN),
   plus the quotes and commas around each segment and the brackets. Derived
   rather than picked so the two sides cannot drift apart silently. */
#define REUSING_MAX_LINE \
  (REUSING_MAX_SEGS_PER_ENTRY * (REUSING_MAX_SEG_LEN * 4 + 3) + 16)

/* unsolved_condition lines are two fixed-width fields ("cmpid=%u
   context=%u"), so they need nothing like the above. */
#define REUSING_MAX_UNSOLVED_LINE 256

/* Decodes one "..." segment starting at *pp (which must point at the
   opening quote), mirroring dict_write_escaped()'s output in reverse:
   printable ASCII passes through, \\ and \" unescape, everything else
   arrives as \xNN. Advances *pp past the closing quote. Returns the byte
   count, or -1 if the segment is malformed or over-long; on success `out`
   holds the decoded bytes. */

static s32 unescape_segment(u8 **pp, u8 *out) {

  u8 *p = *pp;

  if (*p != '"') { return -1; }
  ++p;

  u32 len = 0;

  while (*p && *p != '"') {

    if (len >= REUSING_MAX_SEG_LEN) { return -1; }

    if (*p == '\\') {

      ++p;

      if (*p == '\\' || *p == '"') {

        out[len++] = *(p++);

      } else if (*p == 'x' && isxdigit(p[1]) && isxdigit(p[2])) {

        u8 hi = (u8)(isdigit(p[1]) ? p[1] - '0' : tolower(p[1]) - 'a' + 10);
        u8 lo = (u8)(isdigit(p[2]) ? p[2] - '0' : tolower(p[2]) - 'a' + 10);
        out[len++] = (u8)((hi << 4) | lo);
        p += 3;

      } else {

        return -1;

      }

    } else {

      out[len++] = *(p++);

    }

  }

  if (*p != '"') { return -1; }

  *pp = p + 1;
  return (s32)len;

}

/* Reads one value_pool.dict line -- ["seg"] or ["seg","seg",...] -- into
   `entry`. Returns 0 on success (entry owns freshly allocated segments), 1
   if the line is not an entry line at all (comment, blank), -1 if it looked
   like one but did not parse. */

static s32 parse_pool_line(u8 *line, struct value_pool_entry *entry,
                           u8 *segbuf) {

  while (isspace(*line)) {

    ++line;

  }

  if (*line != '[') { return 1; }
  ++line;

  entry->segs = NULL;
  entry->n_segs = 0;

  while (1) {

    while (isspace(*line) || *line == ',') {

      ++line;

    }

    if (*line == ']' || !*line) { break; }

    s32 seg_len = unescape_segment(&line, segbuf);

    if (seg_len < 0) { goto bad_line; }

    /* A zero-length segment carries no value and would make the entry's
       taint pattern disagree with any real offset span, so treat the whole
       line as malformed rather than storing a hole. */
    if (!seg_len) { goto bad_line; }

    entry->segs = ck_realloc(entry->segs,
                             (entry->n_segs + 1) * sizeof(struct value_pool_seg));
    entry->segs[entry->n_segs].data = ck_alloc((u32)seg_len);
    memcpy(entry->segs[entry->n_segs].data, segbuf, (u32)seg_len);
    entry->segs[entry->n_segs].len = (u32)seg_len;
    ++entry->n_segs;

  }

  if (!entry->n_segs) { goto bad_line; }

  return 0;

bad_line:

  for (u32 i = 0; i < entry->n_segs; i++) {

    ck_free(entry->segs[i].data);

  }

  if (entry->segs) { ck_free(entry->segs); }

  entry->segs = NULL;
  entry->n_segs = 0;

  return -1;

}

/* value_pool.dict -> afl->value_pool. */

static void load_value_pool(afl_state_t *afl) {

  u8   *fname = alloc_printf("%s/value_pool.dict", afl->reusing_dir);
  FILE *f = fopen((char *)fname, "r");

  if (!f) {

    FATAL("No value pool at '%s': %s", fname, strerror(errno));

  }

  u8 *line = ck_alloc(REUSING_MAX_LINE);
  u8 *segbuf = ck_alloc(REUSING_MAX_SEG_LEN);
  u32 malformed = 0, cur_line = 0;

  while (fgets((char *)line, REUSING_MAX_LINE, f)) {

    struct value_pool_entry entry;

    ++cur_line;

    /* fgets() splits an over-long line rather than failing, so the tail
       would come back as a bogus extra line and every line number after it
       would be wrong. Escaped bytes never include a literal newline, so a
       missing one means truncation, not a value that happens to contain
       one. Drain the remainder and say so instead of guessing. */

    if (!strchr((char *)line, '\n') && !feof(f)) {

      int c;

      while ((c = fgetc(f)) != EOF && c != '\n') {}

      WARNF("Over-long line %u in %s (over %u bytes) -- skipped.", cur_line,
            fname, (u32)REUSING_MAX_LINE);
      ++malformed;
      continue;

    }

    s32 ret = parse_pool_line(line, &entry, segbuf);

    if (ret == 1) { continue; }

    if (ret < 0) {

      if (malformed < 5) {

        WARNF("Malformed value pool entry at %s line %u.", fname, cur_line);

      }

      ++malformed;
      continue;

    }

    afl->value_pool = ck_realloc(
        afl->value_pool,
        (afl->value_pool_cnt + 1) * sizeof(struct value_pool_entry));
    afl->value_pool[afl->value_pool_cnt++] = entry;
    afl->value_pool_segs += entry.n_segs;

  }

  fclose(f);
  ck_free(line);
  ck_free(segbuf);

  if (malformed) {

    WARNF("Skipped %u malformed value pool entr%s.", malformed,
          malformed == 1 ? "y" : "ies");

  }

  OKF("Loaded %u value pool entr%s (%u segments) from '%s'.",
      afl->value_pool_cnt, afl->value_pool_cnt == 1 ? "y" : "ies",
      afl->value_pool_segs, fname);

  /* Re-emit what we decoded, in the file's own escaping, so it can be
     diffed straight against value_pool.dict -- the entry and segment counts
     alone say nothing about whether the bytes came back right. */

  if (afl->debug) {

    for (u32 i = 0; i < afl->value_pool_cnt; i++) {

      fprintf(stderr, "[D] value_pool[%u] = [", i);

      for (u32 s = 0; s < afl->value_pool[i].n_segs; s++) {

        u8 *d = afl->value_pool[i].segs[s].data;
        u32 l = afl->value_pool[i].segs[s].len;

        if (s) { fputc(',', stderr); }
        fputc('"', stderr);

        for (u32 b = 0; b < l; b++) {

          if (d[b] == '\\' || d[b] == '"') {

            fprintf(stderr, "\\%c", d[b]);

          } else if (d[b] >= 32 && d[b] < 127) {

            fputc(d[b], stderr);

          } else {

            fprintf(stderr, "\\x%02x", d[b]);

          }

        }

        fputc('"', stderr);

      }

      fprintf(stderr, "]\n");

    }

  }

  ck_free(fname);

}

static int cmp_unsolved_site(const void *a, const void *b) {

  const struct unsolved_site *x = a, *y = b;

  if (x->cmpid != y->cmpid) { return x->cmpid < y->cmpid ? -1 : 1; }
  if (x->context != y->context) { return x->context < y->context ? -1 : 1; }
  return 0;

}

/* unsolved_condition -> afl->unsolved, deduped and sorted. Lines look like
   "cmpid=<n> context=<n>". */

static void load_unsolved_sites(afl_state_t *afl) {

  u8   *fname = alloc_printf("%s/unsolved_condition", afl->reusing_dir);
  FILE *f = fopen((char *)fname, "r");

  if (!f) {

    FATAL("No unsolved conditions at '%s': %s", fname, strerror(errno));

  }

  u8                   *line = ck_alloc(REUSING_MAX_UNSOLVED_LINE);
  u32                   cap = 0, n = 0, lines = 0, overlong = 0;
  struct unsolved_site *sites = NULL;

  while (fgets((char *)line, REUSING_MAX_UNSOLVED_LINE, f)) {

    u32 cmpid, context;

    /* Same fgets() split as above. Harmless here -- a tail fragment simply
       fails the sscanf() below -- but count it so a silently ignored file
       does not look like an empty one. */

    if (!strchr((char *)line, '\n') && !feof(f)) {

      int c;

      while ((c = fgetc(f)) != EOF && c != '\n') {}

      ++overlong;
      continue;

    }

    if (line[0] == '#') { continue; }

    if (sscanf((char *)line, "cmpid=%u context=%u", &cmpid, &context) != 2) {

      continue;

    }

    ++lines;

    if (n == cap) {

      cap = cap ? cap * 2 : 1024;
      sites = ck_realloc(sites, cap * sizeof(struct unsolved_site));

    }

    sites[n].cmpid = cmpid;
    sites[n].context = context;
    ++n;

  }

  fclose(f);
  ck_free(line);

  if (overlong) {

    WARNF("Skipped %u over-long line%s (over %u bytes) in %s.", overlong,
          overlong == 1 ? "" : "s", (u32)REUSING_MAX_UNSOLVED_LINE, fname);

  }

  /* Sorted so lookups can bsearch(); deduped in case the file ever repeats a
     pair. */

  if (n) {

    qsort(sites, n, sizeof(struct unsolved_site), cmp_unsolved_site);

    u32 uniq = 1;

    for (u32 i = 1; i < n; i++) {

      if (cmp_unsolved_site(&sites[i], &sites[uniq - 1])) {

        sites[uniq++] = sites[i];

      }

    }

    n = uniq;
    sites = ck_realloc(sites, n * sizeof(struct unsolved_site));

  }

  afl->unsolved = sites;
  afl->unsolved_cnt = n;

  OKF("Loaded %u unsolved comparison site%s (from %u line%s) from '%s'.", n,
      n == 1 ? "" : "s", lines, lines == 1 ? "" : "s", fname);

  ck_free(fname);

}

void load_reusing_data(afl_state_t *afl) {

  if (!afl->reusing_mode) { return; }

  ACTF("Loading reusing taint data from '%s'...", afl->reusing_dir);

  load_value_pool(afl);
  load_unsolved_sites(afl);

}

void destroy_reusing_data(afl_state_t *afl) {

  for (u32 i = 0; i < afl->value_pool_cnt; i++) {

    for (u32 s = 0; s < afl->value_pool[i].n_segs; s++) {

      ck_free(afl->value_pool[i].segs[s].data);

    }

    ck_free(afl->value_pool[i].segs);

  }

  if (afl->value_pool) { ck_free(afl->value_pool); }

  afl->value_pool = NULL;
  afl->value_pool_cnt = 0;
  afl->value_pool_segs = 0;

  if (afl->unsolved) { ck_free(afl->unsolved); }

  afl->unsolved = NULL;
  afl->unsolved_cnt = 0;

}

/* Brings a dry-run seed's precomputed .dtaint across from the -r pool into
   <out_dir>/taint/, renaming it from the seed's own filename (which is how
   afl-taint-scan keyed it) to the name the entry just got in the queue.
   Everything downstream then looks taint data up by queue entry name alone,
   with no need to know whether an entry came from a seed or was discovered
   later.

   Called from perform_dry_run()'s pivot, where both names are still in hand
   -- a moment later q->fname is overwritten with the queue path and the
   seed's own name is gone.

   A seed with no .dtaint is normal, not an error: afl-taint-scan writes no
   track file for an input the target had nothing taint-worthy to say about.
   Counted so the dry-run summary can show the real coverage. */

void reusing_copy_seed_taint(afl_state_t *afl, u8 *seed_name, u8 *queue_name) {

  u8 *src = alloc_printf("%s/%s.dtaint", afl->reusing_dir, seed_name);

  if (access((char *)src, R_OK)) {

    ++afl->taint_missing;
    ck_free(src);
    return;

  }

  u8 *dst = alloc_printf("%s/taint/%s.dtaint", afl->out_dir, queue_name);

  /* Hard link first: the pool is read-only and shared by every trial of
     every campaign against this corpus, so not duplicating gigabytes of
     track files per campaign is worth a try. Falls back to a copy when the
     pool is on another filesystem (the usual case under Docker, where it is
     a separate read-only bind mount). */

  if (link((char *)src, (char *)dst)) {

    s32 sfd = open((char *)src, O_RDONLY);
    s32 dfd = sfd < 0
                  ? -1
                  : open((char *)dst, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);

    if (sfd < 0 || dfd < 0) {

      WARNF("Could not copy taint data '%s' -> '%s': %s", src, dst,
            strerror(errno));
      if (sfd >= 0) { close(sfd); }
      ++afl->taint_missing;
      ck_free(src);
      ck_free(dst);
      return;

    }

    u8 *buf = ck_alloc(64 * 1024);
    ssize_t rd;

    while ((rd = read(sfd, buf, 64 * 1024)) > 0) {

      ck_write(dfd, buf, rd, dst);

    }

    ck_free(buf);
    close(sfd);
    close(dfd);

    if (rd < 0) {

      WARNF("Short read on taint data '%s': %s", src, strerror(errno));
      ++afl->taint_missing;
      ck_free(src);
      ck_free(dst);
      return;

    }

  }

  ++afl->taint_success;

  ck_free(src);
  ck_free(dst);

}

/* The reusing stage itself: rewrite `buf` at the taint offsets this input's
   .dtaint reports, using values from the pool that share the same taint
   pattern, and run the target on each. `orig_buf` is the pristine input to
   restore from between mutations.

   Returns 1 if the caller should give up on this queue entry (same contract
   as input_to_state_stage()), 0 otherwise.

   Not implemented yet -- the call site exists so the gating is in place and
   can be seen firing; the mutation work lands next. */

u8 reusing_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) {

  (void)orig_buf;
  (void)buf;

  if (afl->debug) {

    fprintf(stderr, "[D] reusing_stage: '%s' len=%u pool=%u\n",
            afl->queue_cur->fname, len, afl->value_pool_cnt);

  }

  return 0;

}
