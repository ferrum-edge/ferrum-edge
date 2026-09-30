# hyper: keep reading an HTTP/1 transport past one TLS record while more is ready

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.9.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588). The behaviour
it works around comes from the transport rather than from hyper itself (see
below), so the fix could equally land in tokio-rustls; the retirement trigger
accepts either.

## The problem

hyper's HTTP/1 `Buffered::poll_read_from_io` issues exactly one `poll_read` per
call. Over a plain socket that one read returns everything the kernel holds,
up to the buffer size. Over tokio-rustls it does not: `TlsStream::poll_read`
returns as soon as any plaintext is available, which is one decrypted TLS
record (at most 16 KiB), even when the socket already holds many more.

So a bulk HTTP/1 body over TLS crosses hyper 16 KiB at a time. On Ferrum's
reqwest backend leg every record became its own body chunk: a decode, a
`Bytes` through the body channel, a cross-task wakeup, a frontend write and a
TLS record on the client side. Measured on Linux in the benchmark topology
(HTTPS client → gateway → HTTPS backend, 100 workers, 1 MiB echo), Ferrum
spent 2.03 ms of CPU per request against Envoy 1.39.1's 1.61 ms; AES-GCM,
kernel copies and `memcpy` were comparable, and the difference was spread thinly
across that per-chunk path.

## Patch

Only `src/proto/h1/io.rs` changes; the unified diff is
[`hyper-greedy-h1-read.patch`](hyper-greedy-h1-read.patch).

After a successful read, if that read returned at least `GREEDY_READ_MIN`
(16 KiB, one maximum TLS record's plaintext) and the read buffer has room,
`poll_read_from_io` reads again into the same buffer, up to
`GREEDY_READ_MAX_ROUNDS` (16) extra reads. It stops at the first read that is
short, returns `Pending`, or fails, and hands over everything read so far. A
`Pending` has already registered the waker. A read error is retained and
delivered after the bytes already buffered, because the `Read` contract does
not guarantee that a transport error will recur on the next read.

- A read shorter than 16 KiB never triggers another, so small messages (a
  10 KiB request) cost no extra `recv`.
- Filling the buffer lets hyper's adaptive read strategy grow as it was
  designed to, so bulk bodies settle into 64–128 KiB reads.
- It applies to every HTTP/1 connection hyper drives: Ferrum's frontend
  listeners and its reqwest backend pools.

## Measured

Same Linux host, same image apart from this patch, HTTPS/1.1 echo, two
interleaved rounds each:

| payload | rps before → after | CPU µs per request | syscalls per request |
|---|---|---|---|
| 10 KiB | 56,297 / 57,331 → 57,497 / 57,793 | 65 → 64 | 8.2 → 8.2 |
| 70 KiB | 15,820 / 15,711 → 17,573 / 17,512 (+11%) | 208 → 180 | 28 → 23 |
| 1 MiB | 1,475 / 1,436 → 1,686 / 1,679 (+15%) | 2,033 → 1,645 | 269 → 190 |

## Regression coverage

`proto::h1::io::tests::ferrum_greedy_read_after_full_records` hands `Buffered`
two full 16 KiB reads and a short one in a single `poll_read_from_io` (and
fails with 16,384 bytes without the patch);
`ferrum_greedy_read_skips_short_reads` proves a short first read returns alone;
and `ferrum_greedy_read_preserves_read_ahead_error` proves a one-shot error
during read-ahead is delivered after the successfully read bytes.
The `Vendored Patch Regressions` CI job runs them with

```bash
cargo test --manifest-path vendor/hyper-1.9.0-ferrum-patched/Cargo.toml --features full --lib ferrum_greedy_read
```

## Retirement plan

Retire when hyper (or tokio-rustls, by filling the caller's buffer from every
record already readable) stops handing HTTP/1 bodies over one TLS record per
read, or when the vendored hyper is retired as a whole. Drop the hunk from the
vendored copy, the inventory row, the lifecycle entry and the CI command, then
regenerate `vendor/VENDOR_INTEGRITY.sha256`.
