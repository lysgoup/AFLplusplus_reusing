/*
   Angora's angora_abilist.txt marks malloc/calloc/free/realloc/reallocarray
   as `custom`, so DFSanPass emits calls to __dfsw_malloc/__dfsw_calloc/
   __dfsw_free/__dfsw_realloc/__dfsw_reallocarray instead of the plain libc
   symbols -- without these, linking any target that (transitively) calls
   any of them fails with "undefined reference to `__dfsw_malloc'" etc.
   (confirmed: this exact failure is what building tiffsplit against this
   toolchain surfaced).

   Ported from Angora_original/llvm_mode/external_lib/stdalloc.c: same
   logic (call the real allocator, then track/propagate labels across
   realloc()'s address-changing case via a base->size map), with
   heapmap.h's Rust-FFI heap size tracker swapped for our own C port
   (dtaint_heapmap.c/h).
 */

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "./defs.h"
#include "./dfsan_interface.h"
#include "dtaint_heapmap.h"

__attribute__((visibility("default"))) void *
__dfsw_malloc(size_t size, dfsan_label size_label, dfsan_label *ret_label) {

  *ret_label = 0;
  DEBUG_PRINTF("============ In __dfsw_malloc() ============\n");
  DEBUG_PRINTF("Called with size = %lu\n", size);
  void *ptr = malloc(size);
  DEBUG_PRINTF("[+] malloc() returned %p\n", ptr);

  if (ptr) dtaint_heapmap_set(ptr, size);

  return ptr;

}

__attribute__((visibility("default"))) void __dfsw_free(void *ptr,
                                                         dfsan_label ptr_label) {

  DEBUG_PRINTF("============ In __dfsw_free() ============\n");
  DEBUG_PRINTF("[+] free() called with pointer %p\n", ptr);
  free(ptr);
  dtaint_heapmap_invalidate(ptr);

}

__attribute__((visibility("default"))) void *
__dfsw_calloc(size_t nmemb, size_t size, dfsan_label nmemb_label,
             dfsan_label size_label, dfsan_label *ret_label) {

  DEBUG_PRINTF("============ In __dfsw_calloc() ============\n");
  DEBUG_PRINTF("[+] calloc() called with nmemb = %lu, size = %lu\n", nmemb,
              size);
  *ret_label = 0;
  void *ptr = calloc(nmemb, size);
  DEBUG_PRINTF("[+] calloc() returned %p\n", ptr);

  /* Matches Angora's own stdalloc.c: nmemb * size may overflow, but this
     mirrors the upstream implementation exactly rather than diverging. */
  if (ptr) dtaint_heapmap_set(ptr, nmemb * size);

  return ptr;

}

__attribute__((visibility("default"))) void *
__dfsw_reallocarray(void *ptr, size_t nmemb, size_t size,
                    dfsan_label ptr_label, dfsan_label nmemb_label,
                    dfsan_label size_label, dfsan_label *ret_label) {

  /* Unimplemented upstream in Angora's own stdalloc.c too -- reallocarray
     is rare enough in practice that this hasn't been a real blocker there
     either. */
  abort();
  return NULL;

}

__attribute__((visibility("default"))) void *
__dfsw_realloc(void *ptr, size_t size, dfsan_label ptr_label,
              dfsan_label size_label, dfsan_label *ret_label) {

  DEBUG_PRINTF("============ In __dfsw_realloc() ============\n");
  DEBUG_PRINTF("[+] Called with ptr = %p, size = %lu\n", ptr, size);
  *ret_label = 0;

  size_t old_size = dtaint_heapmap_get(ptr);
  DEBUG_PRINTF("[+] Retrieved old size as %lu\n", old_size);

  void *ret = realloc(ptr, size);

  DEBUG_PRINTF("[+] realloc() returned with %p\n", ret);

  if (ret) {

    if (ptr && ret != ptr && old_size > 0) {

      DEBUG_PRINTF("[+] Base address changed. Copying labels to new area.\n");

      const dfsan_label *old_label_area = dfsan_shadow_for(ptr);
      dfsan_label *new_label_area = dfsan_shadow_for(ret);

      memcpy(new_label_area, old_label_area, sizeof(dfsan_label) * old_size);

      dtaint_heapmap_invalidate(ptr);

    }

    dtaint_heapmap_set(ret, size);

  }

  return ret;

}
