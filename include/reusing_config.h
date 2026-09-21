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

#endif                                              /* !_HAVE_REUSING_CONFIG_H */
