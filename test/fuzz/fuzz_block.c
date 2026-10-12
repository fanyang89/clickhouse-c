#define CHC_IMPLEMENTATION
#include "clickhouse.h"
#include "fuzz_common.h"

static int
decode(const uint8_t *data, size_t size, size_t chunk, bool async,
       const chc_alloc *al, const chc_block_opts *opts, chc_block **out,
       uint64_t *consumed)
{
    fuzz_source src = { .src = { .data = data, .len = size }, .chunk = chunk };
    chc_io io = { .ud = &src, .read = fuzz_read };
    chc_in in = {};
    chc_err err = {};
    int rc = async ? chc_in_init_ioless(&in, al)
                   : chc_in_init(&in, &io, al, chunk, &err);
    if (rc == CHC_OK && !async) {
        rc = chc_block_read(&in, al, opts, out, &err);
    } else if (rc == CHC_OK) {
        size_t fed = 0, next_col = 0;
        for (;;) {
            rc = chc__block_resume_in(&in, al, opts, out, &next_col, &err);
            if (rc != CHC_WOULD_BLOCK || fed == size) break;
            size_t n = size - fed < chunk ? size - fed : chunk;
            rc = chc_in_submit(&in, data + fed, n, &err);
            if (rc != CHC_OK) break;
            fed += n;
        }
        if (rc != CHC_OK) {
            chc_block_destroy(*out, al);
            *out = NULL;
        }
    }
    *consumed = in.consumed;
    chc_in_free(&in);
    return rc;
}

static void
roundtrip(const chc_block *block, const chc_alloc *al)
{
    chc_err err = {};
    size_t n = chc_block_n_columns(block);
    chc_block_col *cols = calloc(n ? n : 1, sizeof *cols);
    assert(cols);
    for (size_t i = 0; i < n; i++) {
        cols[i].name = chc_block_column_name(block, i, &cols[i].name_len);
        cols[i].type = chc_block_column_type(block, i);
        cols[i].col = chc_block_column(block, i);
        /* Validation is explicitly required before traversing untrusted columns. */
        if (chc_column_validate(cols[i].col, &err) != CHC_OK) {
            free(cols);
            return;
        }
    }
    test_mem_sink sink = {};
    chc_io io = { .ud = &sink, .write = fuzz_write };
    int rc = chc_block_write_cols(&io, cols, n, chc_block_n_rows(block), NULL, &err);
    if (rc == CHC_OK) {
        chc_block *copy = NULL;
        uint64_t consumed;
        chc_block_opts opts = {};
        rc = decode(sink.data, sink.len, 64, false, al, &opts, &copy, &consumed);
        assert(rc == CHC_OK || rc == CHC_ERR_OOM);
        if (rc == CHC_OK) {
            assert(copy);
            assert(consumed == sink.len);
            assert(chc_block_n_rows(copy) == chc_block_n_rows(block));
            assert(chc_block_n_columns(copy) == n);
            /* Writer normalizes BlockInfo, so compare column payloads only. */
            for (size_t i = 0; i < n; i++) {
                size_t len;
                const char *name = chc_block_column_name(copy, i, &len);
                assert(len == cols[i].name_len);
                assert(!len || memcmp(name, cols[i].name, len) == 0);
                assert(test_type_eq(cols[i].type, chc_block_column_type(copy, i)));
                assert(test_col_eq(cols[i].col, chc_block_column(copy, i)));
            }
        }
        chc_block_destroy(copy, al);
    }
    test_mem_sink_free(&sink);
    free(cols);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return 0;
    chc_block_opts opts = {
        .has_block_info = (data[0] & 1) != 0,
        .has_custom_serialization = (data[0] & 2) != 0,
    };
    size_t chunk = 1 + data[1] % 64;
    size_t fail_at = fuzz_fail_at(data[2]);
    data += 3; size -= 3;
    test_fail_alloc a, b;
    chc_alloc al = fuzz_allocator(&a, SIZE_MAX), bl = fuzz_allocator(&b, SIZE_MAX);
    chc_block *sync = NULL, *async = NULL;
    uint64_t sc, ac;
    int sr = decode(data, size, chunk, false, &al, &opts, &sync, &sc);
    int ar = decode(data, size, chunk, true, &bl, &opts, &async, &ac);
    if (sr == CHC_OK && sync && ar != CHC_ERR_OOM) {
        assert(ar == CHC_OK);
        assert(sc == ac);
        assert(test_block_eq(sync, async));
        roundtrip(sync, &al);
    }
    chc_block_destroy(sync, &al);
    chc_block_destroy(async, &bl);
    fuzz_no_leaks(&a); fuzz_no_leaks(&b);
    /* Separate fault runs: allocation counts differ across buffering modes. */
    for (int mode = 0; mode < 2; mode++) {
        al = fuzz_allocator(&a, fail_at);
        chc_block *block = NULL;
        (void) decode(data, size, chunk, mode != 0, &al, &opts, &block, &sc);
        chc_block_destroy(block, &al);
        fuzz_no_leaks(&a);
    }
    return 0;
}
