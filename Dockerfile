# syntax=docker/dockerfile:1
#
# This Dockerfile for AFLplusplus uses Ubuntu 24.04 and
# installs LLVM 19 for afl-clang-lto support.
#
# GCC 11 is used instead of 12 because genhtml for afl-cov doesn't like it.
#

FROM ubuntu:24.04 AS aflplusplus
LABEL "maintainer"="AFL++ team <afl@aflplus.plus>"
LABEL "about"="AFL++ docker container image"

### Comment out to enable these features
# Only available on specific ARM64 boards
ENV NO_CORESIGHT=1
# Possible but unlikely in a docker container
ENV NO_NYX=1

### Only change these if you know what you are doing:
# Set only to a version that is available in the used Ubuntu released
ENV LLVM_VERSION=20
# GCC 12 is producing compile errors for some targets so we stay at GCC 11
ENV GCC_VERSION=11

### No changes beyond the point unless you know what you are doing :)

ARG DEBIAN_FRONTEND=noninteractive

ENV NO_ARCH_OPT=1
ENV IS_DOCKER=1

RUN apt-get update && apt-get full-upgrade -y && \
    apt-get install -y --no-install-recommends wget ca-certificates apt-utils && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
    make cmake automake meson ninja-build bison flex \
    git xz-utils bzip2 wget jupp nano bash-completion less vim joe ssh psmisc \
    python3 python3-dev python3-pip python-is-python3 python3-venv \
    libtool libtool-bin libglib2.0-dev \
    apt-transport-https gnupg dialog \
    gnuplot-nox libpixman-1-dev bc \
    gcc-${GCC_VERSION} g++-${GCC_VERSION} gcc-${GCC_VERSION}-plugin-dev gdb lcov \
    clang-${LLVM_VERSION} clang-tools-${LLVM_VERSION} libc++1-${LLVM_VERSION} \
    libc++-${LLVM_VERSION}-dev libc++abi1-${LLVM_VERSION} libc++abi-${LLVM_VERSION}-dev \
    libclang1-${LLVM_VERSION} libclang-${LLVM_VERSION}-dev \
    libclang-common-${LLVM_VERSION}-dev libclang-rt-${LLVM_VERSION}-dev libclang-cpp${LLVM_VERSION} \
    libclang-cpp${LLVM_VERSION}-dev liblld-${LLVM_VERSION} \
    liblld-${LLVM_VERSION}-dev liblldb-${LLVM_VERSION} liblldb-${LLVM_VERSION}-dev \
    libllvm${LLVM_VERSION} libomp-${LLVM_VERSION}-dev libomp5-${LLVM_VERSION} \
    lld-${LLVM_VERSION} lldb-${LLVM_VERSION} llvm-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-runtime llvm-${LLVM_VERSION}-tools \
    $([ "$(dpkg --print-architecture)" = "amd64" ] && echo gcc-${GCC_VERSION}-multilib gcc-multilib) \
    $([ "$(dpkg --print-architecture)" = "arm64" ] && echo libcapstone-dev) && \
    rm -rf /var/lib/apt/lists/*
    # gcc-multilib is only used for -m32 support on x86
    # libcapstone-dev is used for coresight_mode on arm64

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-${GCC_VERSION} 0 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-${GCC_VERSION} 0 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-${GCC_VERSION} 0 && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_VERSION} 0 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 0

# Needed by unicornafl
RUN wget -qO- https://sh.rustup.rs | CARGO_HOME=/etc/cargo sh -s -- -y -q --no-modify-path
ENV PATH=$PATH:/etc/cargo/bin

RUN apt clean -y

ENV LLVM_CONFIG=llvm-config-${LLVM_VERSION}
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

RUN git clone --depth=1 https://github.com/AFLplusplus/cov-analysis && \
    (cd cov-analysis && make install) && rm -rf cov-analysis

WORKDIR /AFLplusplus
# src/afl-taint-scan.c is excluded here and copied in separately,
# right before the step that actually builds it (after the expensive
# make distrib/install above) -- same reasoning as dfsan_legacy's own
# split further down: this file is the one still actively iterating,
# and it doesn't participate in make distrib/install at all (a fully
# standalone new binary, see GNUmakefile's own target), so there's no
# reason a one-line change to it should invalidate that ~10 minute step.
COPY --exclude=src/afl-taint-scan.c . .

ARG CC=gcc-$GCC_VERSION
ARG CXX=g++-$GCC_VERSION

# Used in CI to prevent a 'make clean' which would remove the binaries to be tested
ARG TEST_BUILD

RUN python3 -m venv .venv
ENV PATH="/AFLplusplus/.venv/bin:$PATH"

# The CFLAGS_FLTO neutering (2nd -e) works around a GCC 11 LTO
# internal-compiler-error (ICE) in XXH3_hashLong_64b_default's SSE2
# intrinsics during whole-program codegen. Confirmed by testing: passing
# CFLAGS_FLTO= to a link that reuses ALREADY-LTO-compiled .o's still fails
# (they contain GIMPLE-bytecode-only objects, so the linker still invokes
# lto-wrapper) -- only actually fixes it once EVERYTHING involved, .o's
# included, is (re)compiled without LTO from a clean state, which `make
# clean` right after this sed already guarantees here.
RUN sed -i.bak -e 's/^	-/	/g' -e 's/CFLAGS_FLTO ?= -flto.*/CFLAGS_FLTO ?=/' GNUmakefile && \
    make clean && make distrib && \
    ([ "${TEST_BUILD}" ] || (make install)) && \
    mv GNUmakefile.bak GNUmakefile

# afl-taint-scan: standalone, links only against the generic
# forkserver .o's (see GNUmakefile's own target comment) -- built and
# installed here so it ships in the same base image as afl-fuzz. Copied in
# separately (excluded from the main COPY . . above) so iterating on it
# doesn't invalidate the make distrib/install layer above.
COPY src/afl-taint-scan.c src/afl-taint-scan.c
RUN make afl-taint-scan && install -m 755 afl-taint-scan /usr/local/bin/

# --- Real DFSan (Angora-parity) dynamic taint tracking ---------------------
# See dfsan_legacy/README.md for the full rationale and verification notes:
# modern LLVM's own DFSan (the LLVM_VERSION installed above) cannot give
# per-input-byte provenance (its label is an 8-bit bitmask), so this vendors
# Angora's actual LLVM 11.1.0 DataFlowSanitizer fork as a second, separate
# toolchain used only to build AFL_DTAINT_BINARY companion binaries via
# dfsan_legacy/angora_dfsan_clang.sh -- it never touches the main AFL++
# build above. Ported over from real-dfsan-vendor (this branch's afl-fuzz.c
# itself does NOT read AFL_DTAINT_BINARY -- see that branch instead for the
# in-process consumer; this base image just needs the toolchain present so
# aflplusplus-reusing-target/Dockerfile's dtaint stage can produce binaries
# and cmpid_locs.txt logs, whether or not anything in this process ever
# reads AFL_DTAINT_BINARY itself).
RUN wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz -O /tmp/llvm11.tar.xz && \
    mkdir -p /opt && tar -xf /tmp/llvm11.tar.xz -C /opt && \
    mv /opt/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04 /opt/clang+llvm-11 && \
    rm /tmp/llvm11.tar.xz

ENV DFSAN_LEGACY_LLVM_DIR=/opt/clang+llvm-11

# The three vendored passes (verified to compile against this exact LLVM
# release with zero source changes).
RUN cd /AFLplusplus/dfsan_legacy && mkdir -p build_pass build_rt && \
    for p in UnfoldBranchPass AngoraPass DFSanPass; do \
      /opt/clang+llvm-11/bin/clang++ $(/opt/clang+llvm-11/bin/llvm-config --cxxflags) -fno-rtti -fpic -shared \
        -I include -DLLVM_VERSION_MAJOR=11 -DLLVM_VERSION_MINOR=1 -DMAP_SIZE_POW2=23 \
        -Wl,-znodelete "pass/${p}.cc" -o "build_pass/lib${p}.so" $(/opt/clang+llvm-11/bin/llvm-config --ldflags); \
    done

# dfsan_rt (the vendored compiler-rt DFSan runtime, with dfsan.cc's label
# storage redirected to dtaint_runtime/dtaint_tagset.c) via its own CMake.
RUN cd /AFLplusplus/dfsan_legacy && mkdir -p build && cd build && \
    cmake -DCMAKE_C_COMPILER=/opt/clang+llvm-11/bin/clang \
          -DCMAKE_CXX_COMPILER=/opt/clang+llvm-11/bin/clang++ \
          -DCMAKE_INSTALL_PREFIX=/AFLplusplus/dfsan_legacy/install .. && \
    make -j"$(nproc)"

# Our own C runtime pieces, Angora's io_func.c (ABI-list source functions),
# the comparison-tracing hooks, and AFL's own forkserver stub (needed so a
# dtaint binary can participate in AFL_DTAINT_BINARY's forkserver protocol
# at all -- it isn't compiled via afl-cc.c, so nothing else provides one).
RUN cd /AFLplusplus/dfsan_legacy && \
    for f in dtaint_tagset dtaint_logger dtaint_len_label dtaint_heapmap; do \
      /opt/clang+llvm-11/bin/clang -c -O2 -fPIC -I ../include -I ../dtaint_runtime \
        "../dtaint_runtime/${f}.c" -o "build_rt/${f}.o"; \
    done && \
    /opt/clang+llvm-11/bin/clang -c -O2 -fPIC -I include -I ../include -I ../dtaint_runtime \
      -I dfsan_rt -I dfsan_rt/dfsan runtime/io_func.c -o build_rt/io_func.o && \
    /opt/clang+llvm-11/bin/clang -c -O2 -fPIC -I include -I ../include -I ../dtaint_runtime \
      -I dfsan_rt -I dfsan_rt/dfsan runtime/dtaint_legacy_hooks.c -o build_rt/dtaint_legacy_hooks.o && \
    /opt/clang+llvm-11/bin/clang -c -O2 -fPIC -I include -I ../include -I ../dtaint_runtime \
      -I dfsan_rt -I dfsan_rt/dfsan runtime/dtaint_stdalloc.c -o build_rt/dtaint_stdalloc.o && \
    /opt/clang+llvm-11/bin/llvm-ar rcs build_rt/libdtaint-legacy-rt.a build_rt/*.o && \
    /opt/clang+llvm-11/bin/clang -c -O0 -fPIC -Wno-unused-result -I ../include -I ../instrumentation \
      ../instrumentation/afl-compiler-rt.o.c -o build_rt/afl-compiler-rt-llvm11.o

RUN echo "set encoding=utf-8" > /root/.vimrc && \
    echo ". /etc/bash_completion" >> ~/.bashrc && \
    echo 'alias joe="joe --wordwrap --joe_state -nobackup"' >> ~/.bashrc && \
    echo "export PS1='"'[AFL++ \h] \w \$ '"'" >> ~/.bashrc
