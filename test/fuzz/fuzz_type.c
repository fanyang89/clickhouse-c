#define CHC_IMPLEMENTATION
#include "clickhouse.h"
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    for (int fault = 0; fault < 2; fault++) {
        test_fail_alloc a;
        chc_alloc al = fuzz_allocator(&a, fault && size ? data[0] % 32 : SIZE_MAX);
        chc_type *t = NULL;
        chc_err err = {};
        int rc = chc_type_parse((const char *) data, size, &al, &t, &err);
        if (rc == CHC_OK) {
            assert(t);
            size_t n = chc_type_format(t, NULL, 0);
            char small[8];
            assert(chc_type_format(t, small, sizeof small) == n);
            assert(small[n < sizeof small ? n : sizeof small - 1] == '\0');
            char *name = malloc(n + 1);
            assert(name);
            assert(chc_type_format(t, name, n + 1) == n);
            /* Disable injected failures for the format/parse oracle. */
            a.fail_at = SIZE_MAX;
            chc_type *copy = NULL;
            rc = chc_type_parse(name, n, &al, &copy, &err);
            assert(rc == CHC_OK || rc == CHC_ERR_OOM);
            if (rc == CHC_OK) {
                assert(test_type_eq(t, copy));
                assert(chc_type_kind(t) == chc_type_kind(copy));
                assert(chc_type_n_children(t) == chc_type_n_children(copy));
            }
            chc_type_destroy(copy, &al);
            free(name);
        } else {
            assert(t == NULL);
        }
        chc_type_destroy(t, &al);
        fuzz_no_leaks(&a);
    }
    return 0;
}
