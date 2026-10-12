# Fuzz testing

Run coverage-guided fuzzing without a ClickHouse executable, server, network,
or credentials:

```sh
./fuzz.sh                         # all four targets concurrently, 60s each
FUZZ_SECONDS=600 ./fuzz.sh block client
FUZZ_ARGS='-runs=10000' ./fuzz.sh  # bounded smoke run
```

Requirements: Clang with libFuzzer/ASan/UBSan runtimes, LZ4 and ZSTD development
libraries. `CC`, `CFLAGS` and `LDFLAGS` work like `test.sh`; `CC` must support
`-fsanitize=fuzzer,address,undefined`. Assertions remain enabled even if
`CFLAGS` contains `-DNDEBUG`. Upstream engine reference:
[libFuzzer](https://llvm.org/docs/LibFuzzer.html).

## Targets and oracles

| Target | Input | Checks |
| --- | --- | --- |
| `type` | Arbitrary, length-delimited type text | Parse/reject, truncated formatting, format/parse equivalence, allocation-failure cleanup |
| `block` | 3 control bytes, then Native block bytes | Blocking memory I/O versus incremental ioless decoding; equal columns and consumed bytes; validated decode/write/decode round trips; OOM cleanup |
| `client` | 5 control bytes, then server packet bytes | Public synchronous/asynchronous handshakes and packet streams; equal packets, revisions, timezones and consumed bytes; compressed resumption; OOM cleanup |
| `compression` | 2 control bytes, then compressed frame bytes | Raw malformed frames; checksum-repaired mutations reaching real LZ4/ZSTD decoders; real encode/decode round trips; OOM cleanup |

The transport mocks only byte delivery, using 1–64-byte short reads/submissions
and EOF at input exhaustion. The parser, protocol state machines, CityHash and
codecs are real. Seeds reuse `test_golden_blocks.h` and add Hello, Exception,
Progress, ProfileInfo, TimezoneUpdate, EOS and compressed Data packets. A shared
dictionary helps mutations retain type names and wire-format boundaries.

Every library allocator has an 8 MiB live-byte budget; oversized wire requests
return OOM instead of exhausting the host. Library protocol limits are **not**
redefined. Independent fault runs fail one allocation at an input-selected
index, and all runs assert that teardown leaves zero live allocations/bytes.
ASan leak detection additionally checks allocations outside this mock allocator.
The default freed-allocation quarantine is 32 MiB and per-process RSS limit is
1 GiB. These budgets intentionally limit large-block coverage.

Differential assertions apply when synchronous decoding succeeds and the
asynchronous path does not hit OOM. A truncated input produces EOF in blocking
mode and WOULD_BLOCK in ioless mode; these are not compared as equal errors.
Invalid columns are validated before writer round trips. BlockInfo is normalized
by the writer, so round trips compare column names, types and payloads, not that
metadata. Zero-row columns and type names exceeding the writer's inline buffer
may legitimately be rejected by the writer.

### Control bytes

- `block`: options bitmask (`1` = BlockInfo, `2` = custom serialization),
  chunk selector, allocation-failure selector.
- `client`: handshake selector (low bit), compression selector (`% 3`),
  revision selector (`CHC_SERVER_MIN_REVISION + value % 4`), chunk selector,
  allocation-failure selector. Without handshake, the fixture starts with a
  mocked, already-negotiated connection. At most 32 packets are processed.
- `compression`: chunk selector, allocation-failure selector.
- Chunk size is `1 + selector % 64`. Failure selector `255` disables injection;
  other values fail that zero-based allocation. `type` uses its first text byte
  `% 32` for a separate fault run without stripping it from the type text.

## Logs, corpus and reproduction

`fuzz-out/` (gitignored) retains binaries, per-target logs, evolved corpora and
crash/timeout/OOM artifacts. Override its location with `FUZZ_OUT`. Subsequent
runs retain the evolved corpus. `FUZZ_SECONDS` is a per-target time budget;
`FUZZ_ARGS` adds libFuzzer flags after defaults, for example `-seed=42` or
`-max_len=16384`. Default seed is 1 and maximum input length is 4096 bytes.
The runner returns nonzero if any target fails.

Replay a saved input directly:

```sh
fuzz-out/bin/fuzz_client fuzz-out/artifacts/client/crash-HASH
```

A fuzzer artifact is a finding, not automatically a library defect: inspect
the sanitizer stack and mock/oracle contracts first. A clean bounded run is
not proof of correctness. These targets do not fuzz POSIX/OpenSSL transport
implementations or a real server, and external codec libraries are only
internally instrumented if supplied as sanitizer builds.
