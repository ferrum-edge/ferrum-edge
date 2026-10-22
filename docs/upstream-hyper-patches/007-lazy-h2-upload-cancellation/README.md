# hyper: allocate upload cancellation only for a suspended body

## Status and scope

Experimental, unfiled deliberate fork owned by Ferrum Edge maintainers.
This is a source-level allocation candidate, not a measured performance result.
No upstream release or public API available in the pinned Hyper 1.10.0 exposes
this private allocation choice; a gateway workaround would have to alter body
or cancellation semantics. The comparison must retain every baseline/candidate
observation, including errors and drains. Do not infer a contribution to the
Ferrum/Envoy gap from the existence of this allocation.

[`hyper-lazy-h2-upload-cancellation.patch`](hyper-lazy-h2-upload-cancellation.patch)
applies after complete patches 001–006. Patch 007 modifies only the placement
of the existing cancellation channel in `proto/h2/client.rs`; the separate
`client/ferrum_lazy_cancel_tests.rs` file is compiled only in tests.

## Mechanism and invariants

`ClientTask::poll_pipe` used to create a futures-channel oneshot for every
request, before knowing whether a request-body task existed. Create it instead
only when the eager `PipeToSendStream` poll returns `Pending`. Install the sender
before submitting `PipeMap` to the executor, since an executor can poll it
immediately. The response mapper carries `None` on paths with no upload task.

| Path | Cancellation channels before / after | Upload tasks | Head-wait tasks |
|---|---|---|---|
| HEADERS already ends the request | 1 / 0 | 0 | 1 |
| CONNECT | 1 / 0 | 0 | 1 |
| Eager body poll completes or errors | 1 / 0 | 0 | 1 |
| Eager body poll suspends | 1 / 1 | 1 | 1 |

These are per-request source counts, excluding the existing per-connection
driver and successful CONNECT upgrade task. Dispatch envelope/callback, body
polling, response `SendWhen`, and all executor calls stay unchanged. The change
removes a dead channel allocation; it does not remove a response task or prove
which branch production requests take.

The response future still owns EOS/CONNECT stream cancellation through h2's
existing drop behavior. For a suspended upload, `SendWhen` still sends CANCEL
when its callback is abandoned and `PipeMap` resets the stream. A successful
head drops the sender normally: `PipeMap` sees the closed channel and continues
sending the upload, including its trailers. An upload completing or failing
before suspension needs no later cancellation signal. Body write-stall timers,
positive-window progress, small-window coalescing, head deadlines, reset reasons,
pool keys/width, trust retirement, and response delivery are unchanged.

This shared Hyper client path serves mesh, direct H2/gRPC, reqwest H2, and nested
H2 transports. HTTP/1, HTTP/3, and Hyper's server path have no changed call sites.

## Regression evidence and remote commands

The private test executor records whether the actual submitted `SendWhen`
contains a cancellation sender and whether an upload task was submitted. It adds
no production counter or runtime branch. Nine tests cover:

- EOS and eagerly ready DATA/trailers, followed by reusable requests and response trailers;
- eager body errors and successful CONNECT upgrade bytes;
- abandoned response-head wait for EOS and suspended uploads, wire CANCEL and reuse;
- a successful early response followed by continued upload DATA and trailers;
- 64 concurrent response waits completing behind a suspended upload;
- transport loss and backend REFUSED_STREAM with a surviving sibling;
- 32 buffered 1 KiB `Full<Bytes>` POSTs with branch/task observations.

The 1 KiB probe uses default h2 windows and an in-memory transport; its branch
receipt describes that controlled body. It does not establish eager completion
frequency for `MeshMtlsRequestBody::Streaming(SizeLimitedIncoming)`, TLS, or a
saturated production connection. A ranking must remain uninstrumented.

Run only on the authorized remote CI runner, from the repository root:

```sh
scripts/update_vendor_integrity.sh
RUSTFLAGS=--cap-lints=warn cargo update --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml -p h2 --precise 0.4.20
RUSTFLAGS=--cap-lints=warn cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_lazy_cancel_tests -- --nocapture
RUSTFLAGS=--cap-lints=warn cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_ --config 'patch.crates-io.h2.path="vendor/h2-0.4.20-ferrum-patched"'
cargo test --test integration_tests vendor_integrity
cargo test --test integration_tests http2_pool_tests
cargo test --test integration_tests mesh_hbone_tests
cargo clippy --lib --tests -p ferrum-edge -- -D warnings
cargo fmt --all -- --check
```

The existing complete `ferrum_` vendored suite includes CONNECT reset, positive
flow-control progress, write-stall timeout and slow-client/progress cases. The
normal Vendored Patch Regressions CI job already selects it with vendored h2.
Reconstruct from the checksum-pinned Hyper archive using
`.github/scripts/verify_hyper_patch_stack.py --archive <archive> --evidence <dir>`
after the approved integrity generator has produced the manifest.
No Rust build or test was executed locally during candidate preparation.
The initial preparation commit deliberately awaits the remotely generated
manifest before it can pass reconstruction/integrity gates.

## Retirement

Remove this patch if balanced remote controls show no material improvement or
any regression. If retained, propose the private allocation change upstream and
retire it when a compatible Hyper release allocates upload cancellation only
when needed (or supplies equivalent task/cancellation behavior), or when Ferrum
stops using this Hyper client. Retain cancellation/early-response/trailer
behavioral coverage when moving to an upstream implementation. Remove the
007 series entry, reconstruction metadata and lifecycle row together, then
regenerate `vendor/VENDOR_INTEGRITY.sha256` using the approved script.
