# hyper: bound how long an HTTP/2 response body may wait for client window

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. It follows up the slow-read bound of Ferrum PR
[#6998](https://github.com/ferrum-edge/ferrum-edge/pull/6998), which left
HTTP/2 flow-control stalls out of scope and named this patch series as the
place to fix them.

## The problem

hyper's HTTP/2 server sends a response body from `PipeToSendStream`
(`src/proto/h2/mod.rs`), the same pipe the client uses for request bodies.
Once the service returns the response, the pipe owns the body. When the
client grants no flow-control window, the pipe holds a chunk and parks in
`SendStream::poll_capacity`. Nothing bounds that wait:

- the client can keep the connection alive indefinitely. It answers PINGs
  and keeps reading its socket; it only withholds `WINDOW_UPDATE`;
- the transport is idle, so a write-stall bound below hyper (Ferrum's
  `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS`, #6998) never sees a blocked
  write;
- the pipe polls nothing else, so a timer inside the response body (Ferrum's
  `backend_read_timeout_ms`, which arms only on a backend `Pending`) never
  runs.

For a proxy, the parked body holds the backend connection or stream behind
it, plus every guard and permit the body carries, for as long as the client
keeps the connection open. Each stream does this independently, up to the
connection's `SETTINGS_MAX_CONCURRENT_STREAMS`, and withholding the
connection-level window parks every stream at once.

### Reproduction

`without_the_bound_a_closed_window_holds_the_response_forever` (below) is the
reproduction: an h2 client with the RFC 9113 default 65,535-byte windows
requests an endless body and reads its DATA without releasing capacity. It
receives exactly 65,535 bytes, the stream is still open ten bounds later, and
the response body has not been dropped.

At the gateway, `functional_client_write_timeout_zero_keeps_h2_client_withholding_window_update`
(`tests/functional/functional_client_write_timeout_test.rs`) shows the same
thing end to end with the bound disabled: the backend's streaming connection
stays open while the client holds the stream. Before this patch the same
client was held with the default `60` too, because the transport bound
cannot see a flow-control stall.

## Patch

The unified diff is
[`hyper-h2-response-write-timeout.patch`](hyper-h2-response-write-timeout.patch),
against the published hyper 1.10.0 crate with patches 001–007 applied. It reuses
[patch 004](../004-h2-body-write-timeout/README.md)'s write-stall timer, which
bounds the same pipe on the client side.

- **`hyper::server::conn::http2::Builder::response_write_timeout`** (new)
  takes an `Option<Duration>`, `None` by default. It is a per-connection
  setting, so it adds no per-response extension and no allocation.
- **`H2Stream`** (`src/proto/h2/server.rs`) passes the bound to each response
  body pipe through patch 004's `WriteTimeout`, which now holds the duration
  itself (`WriteTimeout::for_response`). A client request pipe still gets it
  from its `Http2BodyWriteTimeout` extension, unchanged.
- **The timer counts only a closed window.** It runs only while the pipe holds
  a chunk and the stream has **no window assigned**:
  `SendStream::capacity_and_assigned()` (h2 patch 003) reports zero for both.
  A zero capacity with window still assigned means h2's send buffer is full,
  and only the transport can drain it. That wait is the transport bound's
  job, so it ends any window stall instead of extending it. This keeps the
  server bound from cutting a client that reads its socket slowly but
  steadily with a wide window. On the client side, patch 004 keeps timing both,
  because nothing below hyper bounds a backend that stops reading.
- **Patch 005's whole-chunk fast path stays on.** A client request pipe with a
  bound keeps splitting at capacity so unsent bytes stay timed. A server
  response pipe hands a chunk its window already covers to h2 whole, because
  those bytes wait only on the transport.
- When the timer fires, the pipe resets the stream with `RST_STREAM(CANCEL)`
  and fails with `HTTP/2 response body write timed out`. `H2Stream` then
  ends, which drops the response body. Only that stream is reset: the
  connection and its other streams continue.
- **Fail closed without a timer.** A connection that sets the bound without a
  `Timer` resets each response that has a body with `INTERNAL_ERROR` before its
  headers are sent, rather than serving a body nothing bounds. Bodiless
  responses are unaffected.

Time the pipe spends waiting on the response body itself (a slow backend, an
SSE stream between events) never counts: the timer runs only while a chunk is
ready. Patch 004's lazy timer behavior carries over unchanged. A stall only
records its start, and the single sleep is re-armed at most once per bound.

### Gateway wiring

hyper-util's `server::conn::auto::Builder`, which builds both of Ferrum's
HTTP/1+HTTP/2 frontends, gains a forwarding `Http2Builder::response_write_timeout`
in [hyper-util patch 002](../../upstream-hyper-util-patches/002-forward-h2-response-write-timeout/README.md).
`handle_connection` (h2c) and `handle_tls_connection` (ALPN `h2`) in
`src/proxy/mod.rs` set it from `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` (the
`60` default; `0` disables it). This is the same env var as the transport
bound, so one setting means: when the gateway has response bytes to send, a
client that takes none of them for this long is cut. On HTTP/1.1 and HTTP/2 the
socket must accept something. On HTTP/2 the stream must also be granted window.

### What the bound cannot see

h2 exposes no count of a stream's buffered-but-unsent bytes. When the client's
window is no larger than what h2 has already buffered, the stream has no window
assigned while those bytes still wait for the socket. The timer therefore
starts while the buffered tail is still draining, not only once the client
holds back `WINDOW_UPDATE`. With the RFC default 65,535-byte window, a stream
is cut only if the client takes a whole bound to read one window's worth and
grant more. At the `60` default that is slower than about 1 KiB/s.

## Regression tests

The `proto::h2::server::ferrum_response_write_timeout_tests` in the vendored
crate run a real `hyper::server::conn::http2` connection against an in-process
h2 client on tokio's paused clock:

- `without_the_bound_a_closed_window_holds_the_response_forever`: the
  reproduction and negative control;
- `a_client_that_never_opens_its_window_has_the_response_reset`: the stream
  is reset with `CANCEL` after exactly one bound. The response body is dropped,
  and the connection serves the next request;
- `a_client_that_keeps_opening_its_window_is_never_cut`: one stream-window
  frame every ¾ bound, for eight bounds;
- `an_idle_body_behind_a_closed_window_never_trips_the_bound`: a body with
  nothing more to send never arms the timer;
- `a_full_send_buffer_with_window_in_hand_is_not_a_stall`: a client with a wide
  window that stops reading its socket for ten bounds still gets the whole
  body. This test fails if the bound times send-buffer waits too. It needs the
  vendored h2: stock h2 reports `capacity()` for both values, so it cannot tell
  the two waits apart;
- `a_bound_without_a_timer_resets_the_stream`: fail closed.

```bash
cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full \
  --lib ferrum_response_write_timeout \
  --config 'patch.crates-io.h2.path="vendor/h2-0.4.20-ferrum-patched"'
```

The `test-vendor-patches` CI job runs them in its vendored-h2 `--lib ferrum_`
pass.

Gateway coverage:

- `tests/unit/gateway_core/frontend_h2_response_write_stall_tests.rs` drives
  the production accept loop over h2c and TLS ALPN `h2` with a raw-frame client
  that never sends `WINDOW_UPDATE`. Each case asserts the stream is reset with
  `CANCEL` within the bound and the backend connection is released. A `0`
  bound control keeps the stream open.
- `tests/functional/functional_client_write_timeout_test.rs` (`--ignored`)
  covers the same client against the real binary:
  `functional_client_write_timeout_releases_backend_of_h2_client_withholding_window_update`,
  the disabled control `functional_client_write_timeout_zero_keeps_h2_client_withholding_window_update`,
  and `functional_client_write_timeout_keeps_h2_client_granting_window_slowly`.

## Filing upstream

Before proposing this to hyper:

- Make the setting independent of Ferrum's h2 patch 003. Against stock h2,
  `capacity_and_assigned()` falls back to `capacity()` twice. The server bound
  then also times a full send buffer, which is correct but stricter.
- Rewrite patch 004's `let ... else` as noted in its README.

## Retirement

Retire together with [patches 002, 004 and 005](../004-h2-body-write-timeout/README.md#retirement)
(co-retirement group `hyper-h2-body-progress-and-timeout`): this patch builds
on patch 004's `WriteTimeout` and patch 002's pending-body state, and changes
patch 005's whole-chunk condition. Retire it when hyper bounds a server response
body that waits for client flow-control window, or when Ferrum stops serving
HTTP/2 through hyper. Retire hyper-util patch 002 in the same change.
Hosted replacement tests must cover a closed window, a slowly opening window,
an idle body and a full send buffer. No compatible replacement release has been
selected or tested.
