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

/* Executions one reusing stage (-r) may spend on a queue entry. Whatever it
   does not get through is picked up on the next visit, so this only decides
   how finely the work is sliced. Same order as a havoc round. */

#define REUSING_MAX_EXEC 256U

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
