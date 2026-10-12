/* Generate deterministic, valid seeds using the existing golden fixtures. */
#define CHC_PROVIDE_STDLIB_ALLOC
#define CHC_IMPLEMENTATION
#include "clickhouse.h"
#include "clickhouse-compression.h"
#include "clickhouse-client.h"
#include "../test_golden_blocks.h"

#include <assert.h>

static void
save(const char *root, const char *target, const char *name,
     const uint8_t *controls, size_t control_len, const void *data, size_t size)
{
    char path[4096];
    int n = snprintf(path, sizeof path, "%s/%s/%s", root, target, name);
    assert(n > 0 && (size_t) n < sizeof path);
    FILE *f = fopen(path, "wb");
    assert(f);
    assert(!control_len || fwrite(controls, 1, control_len, f) == control_len);
    assert(!size || fwrite(data, 1, size, f) == size);
    assert(fclose(f) == 0);
}

static void
var(chc_io *io, uint64_t value)
{
    chc_err err = {};
    int rc = chc__write_varuint(io, value, &err);
    assert(rc == CHC_OK);
}

static void
str(chc_io *io, const char *value)
{
    chc_err err = {};
    int rc = chc__write_string(io, value, strlen(value), &err);
    assert(rc == CHC_OK);
}

int
main(int argc, char **argv)
{
    assert(argc == 2);
    const char *root = argv[1];
    chc_alloc al = chc_alloc_stdlib();
    chc_codec codec = {};
    chc_lz4_codec_init(&codec);
    chc_zstd_codec_init(&codec);
    chc_err err = {};
    const char *types[] = {
        "UInt8", "Int256", "String", "FixedString(7)", "Decimal(20, 4)",
        "Decimal256(4)", "DateTime64(6, 'UTC')", "Time64(3)", "UUID", "IPv6",
        "Enum16('a' = -1, 'b' = 2)", "Array(Nullable(Int32))",
        "Tuple(`a b` UInt32, y Array(String))", "Tuple(Int32, String)",
        "Map(String, Array(LowCardinality(String)))", "Nested(a UInt32, b String)",
        "LowCardinality(Nullable(String))", "Point", "MultiPolygon",
        "QBit(Float32, 16)", "Nothing", "SimpleAggregateFunction(sum, UInt64)",
        "AggregateFunction(quantiles((0.5)), Float64)",
        "AggregateFunction(2, sumMap, UInt8, UInt8)",
        "JSON(max_dynamic_paths=16, SKIP REGEXP 'a(b)c', a.b UInt32)",
        "Object('json')", "Variant(Int32, String)", "Dynamic", "NoSuchType",
        "Enum8('unterminated = 1)", "FixedString(99999999999999999999999999)",
    };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        char name[32];
        snprintf(name, sizeof name, "type-%zu", i);
        save(root, "type", name, NULL, 0, types[i], strlen(types[i]));
    }
    for (int flags = 0; flags < 4; flags++) {
        chc_block_opts opts = { .has_block_info = (flags & 1) != 0,
                               .has_custom_serialization = (flags & 2) != 0 };
        for (int shape = 0; shape < 3; shape++) {
            test_mem_sink block;
            chc_io bio;
            test_mem_sink_init(&block, &bio);
            int rc = shape == 0 ? test_write_uint_string_block(&bio, &al, &opts, 4, &err)
                   : shape == 1 ? test_write_nullable_array_block(&bio, &al, &opts, &err)
                                : test_write_lc_string_block(&bio, &al, &opts, &err);
            assert(rc == CHC_OK);
            char name[32];
            snprintf(name, sizeof name, "block-%d-%d", flags, shape);
            uint8_t controls[] = { (uint8_t) flags, 6, 255 };
            save(root, "block", name, controls, sizeof controls, block.data, block.len);
            if (flags == 3) {
                for (int mode = 0; mode < 3; mode++) {
                    test_mem_sink packet;
                    chc_io pio;
                    test_mem_sink_init(&packet, &pio);
                    var(&pio, CHC_PKT_DATA); str(&pio, "");
                    if (mode) {
                        rc = chc__comp_emit_chunks(&pio, &codec, (chc_compression) mode,
                                                   block.data, block.len, &al, &err);
                        assert(rc == CHC_OK);
                        uint8_t fc[] = { 6, 255 };
                        snprintf(name, sizeof name, "frame-%d-%d", mode, shape);
                        save(root, "compression", name, fc, sizeof fc,
                             packet.data + 2, packet.len - 2);
                    } else {
                        assert(test_mem_sink_write(&packet, block.data, block.len, &err) == CHC_OK);
                    }
                    var(&pio, CHC_PKT_END_OF_STREAM);
                    uint8_t pc[] = { 0, (uint8_t) mode, 3, 6, 255 };
                    snprintf(name, sizeof name, "data-%d-%d", mode, shape);
                    save(root, "client", name, pc, sizeof pc, packet.data, packet.len);
                    test_mem_sink_free(&packet);
                }
            }
            test_mem_sink_free(&block);
        }
    }
    test_mem_sink packet;
    chc_io io;
    test_mem_sink_init(&packet, &io);
    var(&io, CHC_PKT_HELLO); str(&io, "ClickHouse");
    var(&io, 26); var(&io, 1); var(&io, CHC_CLIENT_REVISION);
    str(&io, "UTC"); str(&io, "mock"); var(&io, 1);
    var(&io, 1); str(&io, "^.{8,}$"); str(&io, "8 chars");
    uint8_t nonce[8] = {};
    assert(test_mem_sink_write(&packet, nonce, sizeof nonce, &err) == CHC_OK);
    var(&io, CHC_PKT_PONG); var(&io, CHC_PKT_END_OF_STREAM);
    uint8_t pc[] = { 1, 0, 3, 0, 255 };
    save(root, "client", "hello", pc, sizeof pc, packet.data, packet.len);
    test_mem_sink_free(&packet);

    test_mem_sink_init(&packet, &io);
    var(&io, CHC_PKT_PROGRESS);
    for (int i = 1; i <= 7; i++) var(&io, (uint64_t) i);
    var(&io, CHC_PKT_TIMEZONE_UPDATE); str(&io, "Asia/Tokyo");
    var(&io, CHC_PKT_PROFILE_INFO);
    for (int i = 0; i < 6; i++) var(&io, 1);
    var(&io, CHC_PKT_PONG); var(&io, CHC_PKT_END_OF_STREAM);
    pc[0] = 0;
    save(root, "client", "control-packets", pc, sizeof pc, packet.data, packet.len);
    test_mem_sink_free(&packet);

    test_mem_sink_init(&packet, &io);
    var(&io, CHC_PKT_EXCEPTION);
    uint8_t code[] = { 42, 0, 0, 0 };
    assert(test_mem_sink_write(&packet, code, sizeof code, &err) == CHC_OK);
    str(&io, "DB::Exception"); str(&io, "mock failure"); str(&io, "stack");
    var(&io, 0);
    save(root, "client", "exception", pc, sizeof pc, packet.data, packet.len);
    pc[0] = 1;
    save(root, "client", "hello-exception", pc, sizeof pc, packet.data, packet.len);
    test_mem_sink_free(&packet);
    return 0;
}
