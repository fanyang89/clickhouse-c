#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-clang}
FUZZ_OUT=${FUZZ_OUT:-$PWD/fuzz-out}
FUZZ_SECONDS=${FUZZ_SECONDS:-60}
targets=(type block client compression)
if (( $# )); then targets=("$@"); fi
for target in "${targets[@]}"; do
    case "$target" in type|block|client|compression) ;;
        *) echo "unknown fuzz target: $target" >&2; exit 2 ;;
    esac
done

cflags=() ldflags=() args=()
read -r -a cflags <<< "${CFLAGS:-}"
read -r -a ldflags <<< "${LDFLAGS:-}"
read -r -a args <<< "${FUZZ_ARGS:-}"
mkdir -p "$FUZZ_OUT/bin"
for target in type block client compression; do
    mkdir -p "$FUZZ_OUT/corpus/$target" "$FUZZ_OUT/artifacts/$target"
done
"$CC" -std=c11 -O1 -g -I. "${cflags[@]}" -UNDEBUG test/fuzz/seed_corpus.c \
    -o "$FUZZ_OUT/bin/seed_corpus" "${ldflags[@]}" -llz4 -lzstd
"$FUZZ_OUT/bin/seed_corpus" "$FUZZ_OUT/corpus"

for target in "${targets[@]}"; do
    libs=()
    [[ $target == client || $target == compression ]] && libs=(-llz4 -lzstd)
    "$CC" -std=c11 -O1 -g -Wall -Wextra -Wno-unused-function \
        -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=all -I. "${cflags[@]}" -UNDEBUG \
        "test/fuzz/fuzz_$target.c" -o "$FUZZ_OUT/bin/fuzz_$target" \
        "${ldflags[@]}" "${libs[@]}"
done

# Keep ASan's freed-allocation quarantine from consuming the RSS budget during
# repeated large, attacker-controlled allocation requests.
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1:quarantine_size_mb=32}
pids=()
for target in "${targets[@]}"; do
    echo "== fuzz $target (${FUZZ_SECONDS}s); log: $FUZZ_OUT/$target.log =="
    "$FUZZ_OUT/bin/fuzz_$target" "$FUZZ_OUT/corpus/$target" \
        -dict=test/fuzz/native.dict -max_total_time="$FUZZ_SECONDS" \
        -max_len=4096 -timeout=5 -rss_limit_mb=1024 -malloc_limit_mb=128 \
        -seed=1 -print_final_stats=1 \
        -artifact_prefix="$FUZZ_OUT/artifacts/$target/" \
        "${args[@]}" > "$FUZZ_OUT/$target.log" 2>&1 &
    pids+=("$!")
done
failed=0
for i in "${!targets[@]}"; do
    target=${targets[$i]}
    if wait "${pids[$i]}"; then
        echo "PASS: $target"
        tail -n 7 "$FUZZ_OUT/$target.log"
    else
        echo "FAIL: $target" >&2
        tail -n 70 "$FUZZ_OUT/$target.log" >&2
        failed=1
    fi
done
exit "$failed"
