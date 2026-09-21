/*
   american fuzzy lop++ - reusing stage tunables
   --------------------------------------------

   Constants for the -r reusing stage, split out of config.h so that changing
   one rebuilds afl-fuzz and nothing else: tools/build.sh hashes config.h into
   the instrumentation toolchain (a change there rebuilds the base image and
   all 19 unibench targets, ~20 minutes) and include/reusing_* into the
   fuzzer. Nothing under instrumentation/ includes this.

   Everything here is dead weight without -r.

 */

#ifndef _HAVE_REUSING_CONFIG_H
#define _HAVE_REUSING_CONFIG_H

/* Floor and ceiling on what one reusing stage (-r) may spend on a queue
   entry, around the per-range-set budget below. The floor keeps a visit
   worthwhile for an input whose taint covers only a handful of ranges (jq's
   median seed has 16); the ceiling stops one input with an unusual number of
   them from holding the stage for tens of seconds while every other entry
   waits. Whatever a visit does not get through is picked up by the next one,
   so between the two this only decides how finely the work is sliced.

   The ceiling is slack on the corpora measured so far -- nm's heaviest seed
   carries 1835 range sets, so 5505 executions -- and is there as a guard,
   not as a limit meant to bind. */

#define REUSING_MIN_EXEC 256U
#define REUSING_MAX_EXEC 8192U

/* -r only. Pool values one reusing stage tries against each distinct range
   set of a queue entry before moving on, and so the stage's budget: that
   many per range set still holding untried values, held between
   REUSING_MIN_EXEC and REUSING_MAX_EXEC and capped by what is actually
   left.

   Range sets, not comparison sites: sites reading exactly the same bytes
   share one, since the same value would be written for all of them. Sets
   with nothing left in the pool -- a lone tainted byte is the common case,
   over half of them on jq/mujs/imginfo, and Angora files no 1-byte values --
   are left out of the count, so this stays a real per-set figure.

   Small on purpose. An nm seed can carry a thousand range sets over half a
   million pool values, so the stage can never work through one input; the
   choice is between trying a few values at many sites and many values at a
   few, and the first few values a site gets are the ones its pool entry was
   derived for. */

#define REUSING_TRIES_PER_OFFSETS 3U

/* -r only. Multiplier on the energy of an entry this campaign found for
   itself, as opposed to one that came in with -i. Those have no .dtaint, so
   the reusing stage does nothing for them and the ordinary mutators are all
   they get -- and reusing saturates early (measured on objdump: 88% of its
   24 h coverage gain landed in the first 8 h), so the rest of the campaign
   is better spent on the new ground it turned up. Capped at the usual havoc
   ceiling times the same factor. Seeds keep their ordinary energy, a
   .dtaint-less one included: it is still corpus a previous campaign already
   fuzzed, not new ground. */

#define REUSING_NEW_ENERGY_MULT 8U

/* -r only. Divisor on the energy of a seed, .dtaint or not. Its deterministic
   stages are already skipped (see fuzz_one) and what is left -- havoc and
   splice -- is the part a previous campaign already ran over this same corpus
   for 24 h, so it is the natural place to take the time the reusing stage and
   the new finds want. Halving, not removing: havoc is the only thing on a
   seed that can change a length or splice two inputs, and so is where the new
   finds come from in the first place. HAVOC_MIN still floors the stage, so
   this cannot silence it. */

#define REUSING_SEED_ENERGY_DIV 2U

#endif                                              /* !_HAVE_REUSING_CONFIG_H */
