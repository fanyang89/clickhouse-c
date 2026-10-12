#define CHC_IMPLEMENTATION
#include "clickhouse.h"
#include "clickhouse-compression.h"
#include "clickhouse-client.h"
#include "clickhouse-async.h"
#include "fuzz_common.h"

static void
packet_equal(const chc_packet *a, const chc_packet *b)
{
    assert(a->kind == b->kind);
    switch (a->kind) {
    case CHC_PKT_DATA: case CHC_PKT_TOTALS: case CHC_PKT_EXTREMES:
    case CHC_PKT_LOG: case CHC_PKT_PROFILE_EVENTS:
        assert(test_block_eq(a->block, b->block));
        break;
    case CHC_PKT_EXCEPTION:
        assert(a->exception && b->exception);
        assert(a->exception->code == b->exception->code);
#define SAME_STRING(field) do { \
    assert(a->exception->field##_len == b->exception->field##_len); \
    assert(!a->exception->field##_len || \
           memcmp(a->exception->field, b->exception->field, a->exception->field##_len) == 0); \
} while (0)
        SAME_STRING(name); SAME_STRING(display_text); SAME_STRING(stack_trace);
#undef SAME_STRING
        break;
    case CHC_PKT_PROGRESS:
#define SAME(field) assert(a->progress.field == b->progress.field)
        SAME(rows); SAME(bytes); SAME(total_rows); SAME(total_bytes);
        SAME(written_rows); SAME(written_bytes); SAME(elapsed_ns);
#undef SAME
        break;
    case CHC_PKT_PROFILE_INFO:
#define SAME(field) assert(a->profile.field == b->profile.field)
        SAME(rows); SAME(blocks); SAME(bytes); SAME(rows_before_limit);
        SAME(applied_limit); SAME(calculated_rows_before_limit);
#undef SAME
        break;
    default: break;
    }
}

static int
async_drive(chc_async_client *c, bool handshake, const uint8_t *data, size_t size,
            size_t chunk, size_t *fed, chc_packet *packet, chc_exception **exc)
{
    chc_err err = {};
    for (;;) {
        int rc = handshake ? chc_async_handshake(c, exc, &err)
                           : chc_async_recv_packet(c, packet, &err);
        if (rc != CHC_WOULD_BLOCK || *fed == size) return rc;
        size_t n = size - *fed < chunk ? size - *fed : chunk;
        rc = chc_async_submit(c, data + *fed, n, &err);
        if (rc != CHC_OK) return rc;
        *fed += n;
    }
}

static void
exercise(const uint8_t *data, size_t size, bool handshake, uint64_t revision,
         chc_compression compression, const chc_codec *codec, size_t chunk,
         size_t fail_at)
{
    test_fail_alloc a, b;
    chc_alloc al = fuzz_allocator(&a, fail_at), bl = fuzz_allocator(&b, fail_at);
    fuzz_source src = { .src = { .data = data, .len = size }, .chunk = chunk };
    chc_io io = { .ud = &src, .read = fuzz_read, .write = fuzz_discard };
    chc_client_opts opts = { .compression = compression, .codec = codec,
                             .read_buffer_bytes = chunk };
    chc_async_client *async = NULL;
    chc_client *sync = NULL;
    chc_client seeded = { .al = &al, .io = &io, .codec = codec,
                          .compression = compression };
    seeded.server.revision = revision;
    chc_err err = {};
    int ar = chc_async_client_init(&async, &opts, &bl, &err);
    if (ar != CHC_OK) goto out;
    size_t fed = 0;
    if (handshake) {
        chc_exception *se = NULL, *ae = NULL;
        int sr = chc_client_init(&sync, &opts, &al, &io, &se, &err);
        ar = async_drive(async, true, data, size, chunk, &fed, NULL, &ae);
        if (fail_at == SIZE_MAX && sr == CHC_OK && ar != CHC_ERR_OOM) {
            assert(ar == CHC_OK);
            const chc_server_info *si = chc_client_server_info(sync);
            const chc_server_info *ai = chc_async_server_info(async);
            assert(si->revision == ai->revision);
            assert(si->version_major == ai->version_major);
            assert(si->version_minor == ai->version_minor);
            assert(si->version_patch == ai->version_patch);
            assert(strcmp(si->name, ai->name) == 0);
            assert(strcmp(si->timezone, ai->timezone) == 0);
            assert(strcmp(si->display_name, ai->display_name) == 0);
        }
        chc_exception_free(se, &al);
        chc_exception_free(ae, &bl);
        if (sr != CHC_OK || ar != CHC_OK) goto out;
    } else {
        int sr = chc_in_init(&seeded.in, &io, &al, chunk, &err);
        if (sr != CHC_OK) goto out;
        sync = &seeded;
        /* Match existing mock tests: bypass Hello to explore arbitrary packets. */
        async->hs_phase = CHC__HS_DONE;
        async->cli.server.revision = revision;
    }
    for (int i = 0; i < 32; i++) {
        chc_packet sp = {}, ap = {};
        int sr = chc_client_recv_packet(sync, &sp, &err);
        ar = async_drive(async, false, data, size, chunk, &fed, &ap, NULL);
        if (fail_at == SIZE_MAX && sr == CHC_OK && ar != CHC_ERR_OOM) {
            if (ar != CHC_OK)
                fprintf(stderr, "packet %d: sync kind=%d, async rc=%d, consumed=%llu/%llu, fed=%zu/%zu\n",
                        i, sp.kind, ar, (unsigned long long) sync->in.consumed,
                        (unsigned long long) async->cli.in.consumed, fed, size);
            assert(ar == CHC_OK);
            packet_equal(&sp, &ap);
            assert(strcmp(sync->server.timezone, async->cli.server.timezone) == 0);
            assert(sync->in.consumed == async->cli.in.consumed);
        }
        chc_packet_clear(sync, &sp);
        chc_async_packet_clear(async, &ap);
        if (sr != CHC_OK || ar != CHC_OK) break;
        chc_in_reset(&async->cli.in);
        const uint8_t *pending;
        size_t pending_len;
        chc_async_pending_out(async, &pending, &pending_len);
        chc_async_consume_out(async, pending_len);
    }
out:
    if (sync && sync != &seeded) chc_client_close(sync);
    chc__client_recv_state_free(&seeded);
    if (seeded.in.al) chc_in_free(&seeded.in);
    chc_async_client_free(async);
    fuzz_no_leaks(&a); fuzz_no_leaks(&b);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 5) return 0;
    bool handshake = (data[0] & 1) != 0;
    chc_compression compression = (chc_compression) (data[1] % 3);
    uint64_t revision = CHC_SERVER_MIN_REVISION + data[2] % 4;
    size_t chunk = 1 + data[3] % 64;
    size_t fail_at = fuzz_fail_at(data[4]);
    chc_codec codec = {};
    chc_lz4_codec_init(&codec);
    chc_zstd_codec_init(&codec);
    data += 5; size -= 5;
    exercise(data, size, handshake, revision, compression, &codec, chunk, SIZE_MAX);
    exercise(data, size, handshake, revision, compression, &codec, chunk, fail_at);
    return 0;
}
