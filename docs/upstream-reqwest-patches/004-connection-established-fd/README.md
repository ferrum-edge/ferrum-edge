# Vendored reqwest patch: report an established connection's socket

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/reqwest-0.13.3-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## What this patches

Adds one **additive, defaulted** method to the patch-003 trait:

```rust
pub trait ConnectionAdmission: Send + Sync + 'static {
    fn admit(&self, dst: &Uri) -> Result<ConnectionAdmissionToken, BoxError>;

    #[cfg(unix)]
    fn established(&self, token: &ConnectionAdmissionToken, fd: std::os::fd::RawFd) { /* no-op */ }
}
```

`established` is called at most once per admitted dial, from
`ConnectorService::call`'s `with_admission` wrapper — after the transport (and
any TLS handshake) produced a socket, and **before** the connection object is
handed to hyper, so no request byte has been written yet. `token` is the same
token `admit` returned for that connection, so an implementation can key what it
records on the connection's identity.

Only an HTTP/1.1 connection is reported. A connection that negotiated HTTP/2
over ALPN is multiplexed — its kernel send queue is shared by every stream
hyper opens on it — so no per-request consumer of the descriptor could
attribute that queue to the request that caused the dial; the hook is simply
not called for it (checked via `Connected::is_negotiated_h2()` on the
established connection).

The descriptor is *borrowed* for the duration of the call: the connection owns
it, and an implementation that needs it afterwards must duplicate it (`dup`).
Ferrum does exactly that inside the callback
(`BackendSocketHandle::duplicate_from_raw_fd`), so nothing outside the call ever
holds a bare fd number the connector could close and the kernel could recycle.

Mechanically, the connect path fills a small one-shot cell (`EstablishedFd`, an
`Arc<AtomicI32>` allocated once per **new** physical connection) where the
concrete stream is still visible; `with_admission` — the only place holding the
connection's admission token — reads it once the dial resolves. The descriptor
is taken in `ConnectorService::connect_with_maybe_proxy` for the plain-HTTP
connector and the rustls connector, both of which hand back the
`HttpConnector`'s `TokioIo<TcpStream>` (directly, or under
`hyper_rustls::MaybeHttpsStream` via the accessor chain the module already uses
for `set_nodelay`). Dials that produce no TCP socket the connector can reach —
Unix-domain and named-pipe transports, SOCKS, tunnelled `CONNECT` proxies, and
the `native-tls` connector, which Ferrum does not build — simply leave the cell
empty and the callback is not invoked at all.

Surface area: one defaulted trait method, one new private type, one extra
parameter on two crate-private `async fn`s, and two extra arguments on the
crate-private `with_admission`. Default behavior is unchanged when the hook is
absent, and an existing `ConnectionAdmission` implementation needs no change.

## Why ferrum-edge needs it

Issue [#4411](https://github.com/ferrum-edge/ferrum-edge/issues/4411).
`backend_write_timeout_ms` is documented as bounding transport **write
progress**, including the post-end-of-stream drain of the local send queue. Once
the last request byte has been handed to the kernel, HTTP offers no request-side
receipt that the backend read it; the only remaining evidence is the kernel's
own send-queue depth (`SIOCOUTQ` / `SO_NWRITE`), sampled through
`src/proxy/backend_send_queue.rs`.

Sampling requires the backend socket. Every other Ferrum backend transport
constructs its own `TcpStream` and hands a duplicated handle to the upload pump.
The bundled HTTP client is the exception, and it is the transport in the issue's
own reproduction: its connector returns a sealed `Conn`, `connector_layer` sees
the same sealed type, and no public API exposes the connection's socket. PR
#4615 therefore implemented the bound on the direct HTTP/2 pool, the native gRPC
pool, and HBONE, and left the HTTP/1.1 path explicitly uncovered pending this
patch.

The admission hook is the right seam because patch 003 already owns the single
place a new physical connection is created and already binds a token to that
connection's lifetime; reporting the socket there adds no new concept and no new
lifetime.

## Upstream tracking

- Status: **deliberate fork, unfiled.** It extends the patch-003 trait, which is
  itself an unfiled deliberate fork, so it cannot be filed independently.
- Retirement trigger: retire together with
  [patch 003](../003-connection-admission-hook/README.md) — reqwest exposes a
  connection-lifecycle hook that carries the connection's socket (or un-seals
  the connector connection type so a `connector_layer` can read it).

## Vendored crate

- Path: `vendor/reqwest-0.13.3-ferrum-patched/`
- Base release: reqwest **v0.13.3**
- Wired in via `[patch.crates-io]` in the workspace `Cargo.toml` (unchanged)
- Files touched: `src/connect.rs`

## Behavioral regression coverage

`tests/integration/backend_timeout_enforcement_tests.rs`:

- `vendored_established_hook::established_reports_the_dialed_socket_once_per_physical_connection`
  — the patch's whole contract, asserted directly against a live reqwest client:
  the callback fires **exactly once** per physical connection (so it tracks
  connections, not requests), the descriptor it reports has the dialed backend
  as its peer (so it is that connection's socket and not an arbitrary open fd),
  and it answers a send-queue query. If the callback stops firing, the
  acceptance tests below would silently degrade to `backend_read_timeout_ms`
  instead of failing; this one fails.

  The keep-alive backend answers every request with the client source port that
  carried it, so the test names the physical connection each request actually
  travelled over. That is what makes the assertion deterministic (issue #4888):
  hyper returns a finished HTTP/1.1 connection to the pool from a task it spawns
  after the response body completes, so a request issued straight after the
  previous body can race that return and legitimately dial again. The test keeps
  requesting until the backend reports a source port twice — that request
  provably reused an open connection — then asserts every reported descriptor
  names a distinct source port and the reused connection was reported exactly
  once. The hook itself cannot double-fire: `with_admission` awaits one connect
  attempt and calls `established` at most once on success.
- `in_process_kernel_absorb_write_timeout_maps_to_504` and
  `in_process_h2c_kernel_absorb_write_timeout_maps_to_504` — the issue's
  reproduction end to end: a 2 MiB POST to a backend that `accept()`s and never
  reads is 504 `X-Gateway-Error: backend_timeout` near
  `backend_write_timeout_ms`, over the bundled HTTP client's HTTP/1.1 backend
  path.
- `in_process_progressing_upload_is_not_killed_by_idle_write_timeout` — the
  companion negative: a slow-but-progressing upload over the same path is not
  charged a stall.

`tests/functional/scripted_backend_tests.rs::h1_kernel_absorb_write_timeout_maps_to_504_backend_timeout`
and
`tests/functional/scripted_backend_h2_tests.rs::h2_reqwest_kernel_absorb_write_timeout_maps_to_504`
repeat the acceptance case against the spawned binary and additionally assert
the `error_class=read_write_timeout` access-log attribution.
