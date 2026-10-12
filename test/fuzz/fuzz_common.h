/* Bounded mock transport and allocator; production protocol limits stay intact. */
#ifndef CHC_FUZZ_COMMON_H
#define CHC_FUZZ_COMMON_H

#include <assert.h>
#include "../test_common.h"
#include "../test_block_compare.h"

#define FUZZ_MEMORY_LIMIT (8u * 1024u * 1024u)

static void *
fuzz_alloc(void *ud, size_t n)
{
    test_fail_alloc *a = ud;
    if (n > FUZZ_MEMORY_LIMIT - a->live_bytes) return NULL;
    return test_fail_alloc_alloc(ud, n);
}

static void *
fuzz_realloc(void *ud, void *p, size_t old_n, size_t new_n)
{
    test_fail_alloc *a = ud;
    assert(old_n <= a->live_bytes);
    if (new_n > FUZZ_MEMORY_LIMIT - (a->live_bytes - old_n)) return NULL;
    return test_fail_alloc_realloc(ud, p, old_n, new_n);
}

static chc_alloc
fuzz_allocator(test_fail_alloc *a, size_t fail_at)
{
    chc_alloc al = test_fail_alloc_init(a, fail_at);
    al.alloc = fuzz_alloc;
    al.realloc = fuzz_realloc;
    return al;
}

static void
fuzz_no_leaks(const test_fail_alloc *a)
{
    assert(a->live == 0);
    assert(a->live_bytes == 0);
}

typedef struct {
    test_mem_src src;
    size_t chunk;
} fuzz_source;

static int
fuzz_read(void *ud, void *buf, size_t n, size_t *out_n, chc_err *err)
{
    fuzz_source *s = ud;
    if (n > s->chunk) n = s->chunk;
    return test_mem_read(&s->src, buf, n, out_n, err);
}

static int
fuzz_discard(void *ud, const void *buf, size_t n, chc_err *err)
{
    (void) ud; (void) buf; (void) n; (void) err;
    return CHC_OK;
}

static int
fuzz_write(void *ud, const void *buf, size_t n, chc_err *err)
{
    test_mem_sink *s = ud;
    if (n > FUZZ_MEMORY_LIMIT - s->len) return CHC_ERR_OOM;
    return test_mem_sink_write(ud, buf, n, err);
}

static size_t
fuzz_fail_at(uint8_t control)
{
    return control == 255 ? SIZE_MAX : control;
}

#endif
