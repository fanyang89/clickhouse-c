#define CHC_IMPLEMENTATION
#include "clickhouse.h"
#include "clickhouse-compression.h"
#include "fuzz_common.h"

static void
read_frame(const uint8_t *data, size_t size, size_t chunk, size_t fail_at,
           const chc_codec *codec)
{
    test_fail_alloc a;
    chc_alloc al = fuzz_allocator(&a, fail_at);
    fuzz_source src = { .src = { .data = data, .len = size }, .chunk = chunk };
    chc_io io = { .ud = &src, .read = fuzz_read }, dio;
    chc_err err = {};
    chc_in in = {};
    if (chc_in_init(&in, &io, &al, chunk, &err) == CHC_OK) {
        chc__decomp_src ds;
        chc__decomp_src_init(&ds, &in, codec, &al, &dio);
        (void) chc__decomp_read_frame(&ds, &err);
        chc__decomp_src_free(&ds);
    }
    chc_in_free(&in);
    fuzz_no_leaks(&a);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    size_t chunk = 1 + data[0] % 64;
    size_t fail_at = fuzz_fail_at(data[1]);
    data += 2; size -= 2;
    chc_codec codec = {};
    chc_lz4_codec_init(&codec);
    chc_zstd_codec_init(&codec);
    read_frame(data, size, chunk, SIZE_MAX, &codec);
    read_frame(data, size, chunk, fail_at, &codec);
    if (size >= 25) {
        /* Repair only the checksum, leaving malformed header sizes intact.
         * Otherwise mutations almost always stop before codec dispatch. */
        uint8_t *frame = malloc(size);
        assert(frame);
        memcpy(frame, data, size);
        uint64_t lo, hi;
        chc_cityhash128(frame + 16, size - 16, &lo, &hi);
        for (int i = 0; i < 8; i++) {
            frame[i] = (uint8_t) (lo >> (8 * i));
            frame[8 + i] = (uint8_t) (hi >> (8 * i));
        }
        read_frame(frame, size, chunk, SIZE_MAX, &codec);
        free(frame);
    }
    if (!size) return 0;
    /* Also fuzz the encoder and assert real LZ4/ZSTD frame round trips. */
    for (int mode = CHC_COMP_LZ4; mode <= CHC_COMP_ZSTD; mode++) {
        test_fail_alloc a;
        chc_alloc al = fuzz_allocator(&a, SIZE_MAX);
        test_mem_sink sink = {};
        chc_io io = { .ud = &sink, .write = fuzz_write };
        chc_err err = {};
        int rc = chc__comp_emit_frame(&io, &codec, (chc_compression) mode,
                                      data, size, &al, &err);
        assert(rc == CHC_OK);
        test_mem_src src;
        chc_io rio, dio;
        test_mem_src_init(&src, &rio, sink.data, sink.len);
        chc_in in;
        rc = chc_in_init(&in, &rio, &al, 64, &err);
        assert(rc == CHC_OK);
        chc__decomp_src ds;
        chc__decomp_src_init(&ds, &in, &codec, &al, &dio);
        rc = chc__decomp_read_frame(&ds, &err);
        assert(rc == CHC_OK);
        assert(ds.frame_fill == size);
        assert(memcmp(ds.frame_buf, data, size) == 0);
        chc__decomp_src_free(&ds);
        chc_in_free(&in);
        test_mem_sink_free(&sink);
        fuzz_no_leaks(&a);
    }
    return 0;
}
