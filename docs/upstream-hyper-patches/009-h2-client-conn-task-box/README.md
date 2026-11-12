# hyper: box the HTTP/2 client connection task so per-request tasks stay small

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. The change has no Ferrum-specific surface and
is suitable for upstream as it stands; an issue draft is at the end of this
file.

## The problem

hyper's HTTP/2 client hands its executor three kinds of future, all through one
enum, `proto::h2::client::H2ClientFuture`:

- `Task`: the connection task. One per connection. It owns the h2
  `Connection`, so it is large.
- `Send`: resolves a request's response. One per request.
- `Pipe`: writes a request body. hyper first tries to write the body inline
  and spawns `Pipe` only when that attempt is still pending, so it is at most
  one per request.

An enum is as large as its largest variant. With `Task` stored inline, every
`Send` and `Pipe` future was as large as the connection task, whatever the
body, transport and executor types. The sizes below are for one
instantiation, the one measured: Ferrum's direct HTTP/2 pool over TLS
(`H2ClientFuture<DirectH2RequestBody, TokioIo<TlsStream<TcpStream>>, TokioExecutor>`).
There the enum was about 2.5 KiB (the release binary copies 2,528 to 2,536
bytes at each site), against a few hundred bytes of per-request state. The
executor copies the future into a task allocation of that size for each
spawned future, and the runtime writes a value of the same size again when the
task finishes.

In CPU profiles of the HTTP/2 10 KiB benchmark cell on that pool (13 runs on
`main` 856ea7634, five runner CPU models) those copies were 0.5% to 1.4% of
the gateway's user CPU: a mean of 0.70% on EPYC 7763, 1.07% on EPYC 9V74,
0.52% on Xeon 8573C, 0.67% on Xeon 6973P-C and 0.67% on EPYC 9V45.

## Patch

Apply [the complete ordered stack](../README.md) for reproducible vendor source.

The change is confined to `src/proto/h2/client.rs`. The unified diff is
[`hyper-h2-client-conn-task-box.patch`](hyper-h2-client-conn-task-box.patch),
taken against the published hyper 1.10.0 crate with patches 001 to 008 applied.

`H2ClientFuture::Task` holds `Pin<Box<ConnTask<T, B>>>` instead of an inline,
pin-projected `ConnTask<T, B>`. `handshake` boxes the connection task once when
it spawns it, and the enum's `poll` forwards to the box. Nothing else changes:
the connection task is polled by the same executor task, and dropping the
future drops the connection task as before.

The cost is one allocation per connection. The enum is then as large as its
largest per-request variant.

## Measured

On hosted CI runners, Rust 1.100.0.

Size of the future the executor receives per request:

| Instantiation | Before | After |
|---|---|---|
| Direct HTTP/2 pool over TLS, release build (the size the binary copies at the spawn site) | 2,528 bytes | 368 bytes |
| The regression test's types (`Full<Bytes>` body, a zero-sized I/O type) | at least the 1,424-byte connection task | 304 bytes (`Pipe` 304, `Send` 104) |

CPU profiles of the HTTP/2 10 KiB benchmark cell, as a share of the gateway's
user CPU:

| | Without the patch (six runs: EPYC 9V74, EPYC 7763, Xeon 8370C) | With the patch (EPYC 9V74, EPYC 7763) |
|---|---|---|
| Constant-size copies on the client spawn path | 0.5% to 1.3% | 0.09%, 0.05% |
| Allocator time called from the client spawn path | 0.2% to 0.6% | 0.18%, 0.30% |

That is the whole effect: about 1% of the gateway's user CPU on this cell. A
same-job A/B of gateway CPU per request is recorded in the pull request that
added the patch.

## Regression coverage

- `proto::h2::client::ferrum_client_conn_task_box_tests` in the vendored crate
  asserts that the spawned future is no larger than its largest per-request
  variant plus the enum tag, and smaller than the connection task. Run with
  `cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_client_conn_task_box`.
- Behaviour is unchanged, so the gateway's existing live HTTP/2 client
  coverage is the behavioural regression. hyper drives the socket of every
  HTTP/2 client connection from the connection task, so a test that sends a
  request, reads the backend's SETTINGS or observes a close on a real
  connection runs through the box. In `tests/integration/http2_pool_tests.rs`
  that includes
  `direct_h2_backend_sees_matching_host_and_authority_on_non_default_port`
  (requests and responses through the direct pool),
  `test_http2_pool_does_not_pin_to_a_backend_allowing_no_streams` (the
  backend's SETTINGS reach the pool),
  `test_http2_pool_refills_a_closed_preferred_shard_in_the_background` (a
  closed connection is noticed and replaced) and
  `test_grpc_h2c_upload_coalesces_small_connection_window_increments` (a
  request body written through the gRPC pool). The tests in that file that
  never connect, or that exercise HTTP/1.1, are not coverage for this patch.

## Retirement plan

Retire when hyper stops sizing its per-request HTTP/2 client futures by the
connection task (for example by boxing `ConnTask`, or by spawning it through a
separate executor bound), or when the vendored hyper is retired as a whole.
Drop the patch's hunks from the vendored copy, the inventory row, the lifecycle
entry and this directory, remove it from `series` and from the reconstruction
verifier, then regenerate `vendor/VENDOR_INTEGRITY.sha256`.

## Upstream issue draft

**Title:** HTTP/2 client: per-request `H2ClientFuture` is sized by the connection task

`H2ClientFuture` has three variants: `Pipe` and `Send` are spawned per request,
`Task` once per connection. `Task` holds `ConnTask<T, B>` inline, which owns
the h2 `Connection` (about 2.4 KiB with a TLS transport), so every `Pipe` and
`Send` future an executor receives is that large too. With tokio this means a
2.5 KiB task allocation and copy per request for futures whose own state is a
few hundred bytes.

Boxing the connection task (`Task { task: Pin<Box<ConnTask<T, B>>> }`) costs
one allocation per connection and makes the enum as large as its largest
per-request variant. It needs no API change: the type lives in a private
module and reaches executors only through the sealed `Http2ClientConnExec`
bound, so its layout is not part of the public API.
