#
# american fuzzy lop++ - dynamic taint tracking runtime
# ------------------------------------------------------
#
# Minimal DFSan-style taint runtime, ported from the Angora fuzzer as a
# validation slice -- see include/dtaint.h and the scoping plan this was
# built from.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

CFLAGS      ?= -O0 -g
override CFLAGS += -I ../include/ -Wall

SRCS = dtaint-rt.c dtaint_abi.c dtaint_tagset.c dtaint_len_label.c dtaint_logger.c
OBJS = $(SRCS:.c=.o)
HDRS = ../include/dtaint.h dtaint_tagset.h dtaint_len_label.h dtaint_logger.h \
       dtaint_internal.h

all: libdtaint-rt.a

# Static archive, not a .so: this gets linked directly into the target
# binary at compile time (via afl-cc.c's add_runtime(), the same mechanism
# afl-compiler-rt.o already uses), not dlopen'd/LD_PRELOADed the way
# libdislocator.so/libtokencap.so are.
libdtaint-rt.a: $(OBJS)
	ar rcs $@ $(OBJS)
	cp -fv libdtaint-rt.a ../

%.o: %.c $(HDRS) ../config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.NOTPARALLEL: clean

clean:
	rm -f *.o *.a *~ a.out core core.[1-9][0-9]*
	rm -f ../libdtaint-rt.a

install: all
	install -m 755 -d $${DESTDIR}$(HELPER_PATH)
	install -m 644 ../libdtaint-rt.a $${DESTDIR}$(HELPER_PATH)
