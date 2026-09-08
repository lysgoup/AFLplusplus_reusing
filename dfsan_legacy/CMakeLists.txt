# Builds only dfsan_rt/ (the vendored, patched compiler-rt DFSan runtime --
# see dfsan_rt/dfsan/dfsan.cc's redirected FFI calls into
# dtaint_runtime/dtaint_tagset.c). Deliberately does NOT build pass/ or
# runtime/ here (those are built via simple direct clang invocations in
# build.sh, already validated faster/simpler than adding them as CMake
# targets too) -- this file's only job is the ~150-file compiler-rt tree
# under dfsan_rt/, which genuinely benefits from CMake's existing, proven
# build logic (add_compiler_rt_runtime etc., vendored unmodified from
# Angora_original/llvm_mode/dfsan_rt/CMakeLists.txt's own dependents).
#
# Must be configured against the vendored LLVM 11.1.0 toolchain, e.g.:
#   cmake -DCMAKE_C_COMPILER=/opt/clang+llvm-11/bin/clang \
#         -DCMAKE_CXX_COMPILER=/opt/clang+llvm-11/bin/clang++ \
#         -DLLVM_DIR=/opt/clang+llvm-11/lib/cmake/llvm \
#         -DCMAKE_INSTALL_PREFIX=<dfsan_legacy>/install ..

cmake_minimum_required(VERSION 3.4)
project(dtaint_dfsan_rt VERSION 1.0.0 LANGUAGES C CXX ASM)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/dfsan_rt/cmake")

# dfsan.cc's FFI redirection (see its own file header) needs our C tagset
# API instead of Angora's original ../../../runtime/include/tag_set.h.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../dtaint_runtime)
# Angora's own local headers (defs.h, abilist.h, ...), vendored into
# dfsan_legacy/include/ -- needed by dfsan.h/dfsan_platform.h for the
# dfsan_label typedef (uint32_t, widened from the original 16-bit).
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(ANGORA_LIB_DIR "lib")
set(ANGORA_RULE_DIR "rules")

add_subdirectory(dfsan_rt)
