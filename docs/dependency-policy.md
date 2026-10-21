# Dependency & Vendored-Crate Governance

This document is the single policy for how Ferrum Edge manages third-party
dependencies and, in particular, the **vendored, patched copies** of upstream
crates it carries in `vendor/**`. It is the human half of the governance; the
machine half is `deny.toml`, [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json),
the scheduled `.github/workflows/dependency-audit.yml` workflow,
`scripts/check_vendored_patch_lifecycle.py`, and the drift guard in
`tests/integration/vendor_integrity_tests.rs`.

> TL;DR — vendored patches must be **auditable** (pinned + drift-tested),
> **tracked** (an upstream PR — or a governed [deliberate-fork record](#deliberate-fork-policy-and-sla)
> — plus a retirement trigger, recorded and polled weekly), and
> **covered** (behavioral regression tests). Security advisories in the
> dependency tree are gated whenever CI selects the dependency-audit lane and re-checked weekly, so a fix landing
> in the reqwest/h3 lineage cannot be missed silently.

## Why we vendor

The HTTP/3, QUIC, and WebSocket stacks are young enough that we occasionally hit
upstream bugs (or need a not-yet-merged API) faster than upstream releases.
Vendoring a patched crate via `[patch.crates-io]` is an accepted, **last-resort**
tool when:

- the fix/feature is required for correctness or a documented Ferrum capability,
  and
- the change has been (or will be) proposed upstream, and
- a written retirement plan exists so the vendor copy does not become orphaned.

Vendoring without a retirement plan is not allowed. Prefer a dependency bump, a
feature flag, or a gateway-side workaround first.

The [Hyper patch stack](upstream-hyper-patches/README.md) is reconstructed in
hosted CI from the checksum-pinned published 1.10.0 crate plus complete ordered
patches 001–006. Every shipped file must match the vendor bytes and integrity
manifest; syntax-only patch parsing does not establish reproducibility.

## Direct pins of otherwise-transitive crates

Some crates are already pulled in transitively but are also listed directly in
`Cargo.toml` when Ferrum calls their API itself (not only through a parent
crate). Keep the version aligned with the transitive copy already in
`Cargo.lock` unless an intentional bump is part of the change.

| Crate | Why pinned directly |
|---|---|
| `crossbeam-utils` | `CachePadded` on hot overload atomics |
| `crossbeam-queue` | lock-free MPMC ring for router-cache eviction samples |
| `crc32fast` | AWS Bedrock event-stream prelude/message CRC32 validation before lengths or usage payloads are trusted |
| `unsafe-libyaml` | API-spec YAML event composition + bounded alias expansion (#3307); already transitive via `serde_yaml` |

## Security floor pins

Security fixes use minimum compatible versions, not permanent exact-version
locks. The required `dependency-audit` job in `.github/workflows/ci.yml` checks
every committed `Cargo.lock` against these floors with
`scripts/verify_dependency_security_chain.py`:

| Crate | Fixed floor | Advisory / purpose |
|---|---:|---|
| `opentelemetry_sdk` | 0.32.1 | GHSA-w9wp-h8wv-79jx |
| `aws-smithy-json` | 0.62.7 | GHSA-8ffr-xgwf-xj56 |
| `xxhash-rust` | 0.8.16 | GHSA-6g2r-675j-hx59 |

The same script also checks every committed lockfile that builds `ferrum-edge`
(today the root, `fuzz/`, and `tests/performance/mesh/` lockfiles). Each must
resolve `hyper`, `reqwest`, `h2`, and `hyper-util` to exactly one copy: the
`[patch.crates-io]` path crate under `vendor/`, at the version its directory
names, with no `source` or `checksum`. A second, registry copy would ship that
crate without Ferrum's patches. The expected versions come from the `vendor/`
directories, so moving a vendored crate needs no change to the checker.

Every committed lockfile must also resolve `aws-smithy-json` to a single copy.
The direct `aws-smithy-json` requirement only constrains the AWS SDK while it
sits on the same 0.x line the SDK crates (`aws-config`,
`aws-sdk-secretsmanager`, and the transitive `aws-sdk-sts`, `aws-sdk-sso`, and
`aws-sdk-ssooidc`) require. A requirement on a newer line, such as the
Dependabot-only bump in #6750, resolves a second copy and constrains nothing
(issue #6755). Move the requirement together with the SDK crates and their
`Cargo.toml` floors (`aws-config` 1.12, `aws-sdk-secretsmanager` 1.120 for
the 0.63 line).

Some optional GCP crates also have exact `=` constraints in `Cargo.toml`. Those constraints selected a published,
compatible dependency generation for the fixes above; they are not a promise to
stay on those releases. To lift them:

1. Confirm the advisory's fixed release and check that newer GCP/OpenTelemetry
   releases remain compatible with the currently patched Hyper/reqwest pair
   and enabled feature sets. Keep direct GCP API dependencies declared when
   Ferrum calls their APIs. The `=` pins on `google-cloud-gax`,
   `google-cloud-gax-internal`, and `google-cloud-wkt` also keep reqwest on the
   patched 0.13 line: newer GAX releases can require reqwest 0.14, which the
   0.13 vendor patch does not cover. The path-patch lockfile check above fails
   if a lift pulls in that registry copy.
2. Replace each security-only `=version` constraint with the fixed minimum
   version (or remove the direct constraint if Ferrum no longer needs that
   crate directly). Keep the `opentelemetry_sdk`, `aws-smithy-json`, and
   `xxhash-rust` requirements at or above their applicable fixed floors.
3. Refresh the root and affected standalone lockfiles from their real manifest
   roots. Inspect Cargo metadata for the root, mesh, and fuzz graphs where they
   consume Ferrum's production dependency path; do not hand-edit lockfile
   package entries or checksums. The AWS SDK and Smithy runtime crates are
   not held back: since issue #6755 the root lockfile carries the Rust 1.94.1
   compiler generation (`aws-config` 1.12, `aws-sdk-secretsmanager` 1.120,
   `aws-smithy-json` 0.63, `aws-smithy-runtime` 1.16.0). `aws-smithy-runtime`
   is held at 1.16.0 with `cargo update --precise` only because 1.16.1 moves to
   `aws-smithy-schema` 1.0 while the SDK crates still require 0.2, which would
   resolve two schema copies; let it move once the SDK crates do. No CI job
   enforces an MSRV; CI builds on stable.
4. If a newer advisory fixes one of these packages, update the corresponding
   floor in the checker and this table together. The required dependency audit
   must keep checking every committed lockfile, including standalone graphs.

GCP and AWS provider features, crypto profiles, and MSRV are separate policy
surfaces. A pin lift must preserve those constraints unless a separately
reviewed change intentionally updates them.

## Vendored crate inventory

Each row is the authoritative human summary. The **Lifecycle ID** column is the
stable identity shared with
[`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json); CI
requires the exact set of IDs (duplicates fail closed). Keep this table, the
machine inventory, the `[patch.crates-io]` block in `Cargo.toml`, the per-patch
docs, and `scripts/check_vendored_patch_lifecycle.py` in sync. CI fails when any
surface drifts.

| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |
|---|---|---|---|---|---|---|---|---|
| `sqlx-core-001-verify-ca-name-context` | `sqlx-core` | 0.8.6 | Exclusive configured root CA, provider-pinned verify-ca verifier, and rustls context-bearing hostname errors | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | PostgreSQL and MySQL verify-ca otherwise reject trusted chains on hostname mismatch (#5534); upstream also UNIONS the configured CA with the bundled public roots, so a name-waived verify-ca would trust any public certificate | A compatible SQLx release treats a configured root CA as exclusive and handles both rustls hostname-error variants while retaining chain and signature verification | [Patch and retirement plan](upstream-sqlx-patches/001-verify-ca-name-context/README.md) |
| `sqlx-core-002-typed-float-null-bindings` | `sqlx-core` | 0.8.6 | Any REAL NULL binds through `Option<f32>`, DOUBLE NULL through `Option<f64>` | Fixed upstream by PR [launchbadge/sqlx#4359](https://github.com/launchbadge/sqlx/pull/4359) (merged 2026-08-19; not yet in a release) | Ferrum Edge maintainers | Upstream 0.8.6 reverses the native parameter types for these typed NULLs (#6010); no stored-value loss is established | A compatible SQLx release preserves native REAL/DOUBLE typed-NULL parameter types and passes the hosted PostgreSQL regression; retain the vendor while patch 001 remains | [Patch and retirement plan](upstream-sqlx-patches/002-typed-float-null-bindings/README.md) |
| `reqwest-001-per-request-connect-timeout` | `reqwest` | 0.13.4 | Per-request `RequestBuilder::connect_timeout` | [seanmonstar/reqwest#3017](https://github.com/seanmonstar/reqwest/pull/3017) (OPEN) | Ferrum Edge maintainers | Pool keys exclude request-only connect/read timeouts, so sibling proxies can share one client; without per-request connect timeout the first proxy's timeout leaks to all | PR #3017 merges and ships in a release we consume | [docs/upstream-reqwest-patches/001-…](upstream-reqwest-patches/001-per-request-connect-timeout/README.md) |
| `reqwest-002-selectable-rustls-provider` | `reqwest` | 0.13.4 | Selectable Ring/AWS-LC rustls fallback | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | Library/test reqwest clients run before binary bootstrap; upstream's only built-in fallback hard-wires AWS-LC and cannot preserve Ferrum's mutually exclusive backend pair | Reqwest ships a provider-neutral selectable fallback, or the vendored crate is retired | [docs/upstream-reqwest-patches/002-…](upstream-reqwest-patches/002-selectable-rustls-provider/README.md) |
| `reqwest-003-connection-admission-hook` | `reqwest` | 0.13.4 | `ClientBuilder::connection_admission` physical-connection admission hook | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | DestinationRule `connectionPool.tcp.maxConnections` is a physical-connection ceiling; reqwest owns its socket pool and exposes no connection-lifetime hook, so no public API can admit a new socket and release on its close | Reqwest exposes a connection-lifecycle/admission hook (or a non-sealed connector connection type a `connector_layer` can wrap), or the vendored crate is retired | [docs/upstream-reqwest-patches/003-…](upstream-reqwest-patches/003-connection-admission-hook/README.md) |
| `reqwest-004-connection-established-fd` | `reqwest` | 0.13.4 | Additive, defaulted `ConnectionAdmission::established(token, fd)` reporting a newly dialed connection's socket | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | `backend_write_timeout_ms` bounds the post-end-of-stream drain of the backend socket's send queue (issue #4411), which needs the socket; reqwest's connector returns a sealed `Conn` and `connector_layer` sees the same sealed type, so no public API exposes the connection's `TcpStream` | Reqwest exposes a connection-lifecycle hook carrying the connection socket (or un-seals the connector connection type); co-retires with `reqwest-003-connection-admission-hook` | [docs/upstream-reqwest-patches/004-…](upstream-reqwest-patches/004-connection-established-fd/README.md) |
| `h3-001-recv-frame-drain-on-quic-close` | `h3` | 0.0.8 | Drain buffered frames before propagating QUIC `CONNECTION_CLOSE` | issue [hyperium/h3#338](https://github.com/hyperium/h3/issues/338), PR [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) | Ferrum Edge maintainers | io_uring batching of `STREAM(FIN)` + `CONNECTION_CLOSE(H3_NO_ERROR)` dropped a buffered HEADERS frame → false 502 on graceful close | Fix ships in an `h3` release **and** patches 002/003/004/005 are also retired | [docs/upstream-h3-patches/001-…](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md) |
| `h3-002-extended-connect-websocket-protocol` | `h3` | 0.0.8 | Add `Protocol::WEB_SOCKET` (RFC 9220 Extended CONNECT) | **Deliberate fork** — unfiled upstream; no published fork ref yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock `h3` 0.0.8 rejects `:protocol=websocket` at the HEADERS layer, making WebSocket-over-HTTP/3 unreachable | Upstream files + merges the variant **and** patches 001/003/004/005 are also retired | [docs/upstream-h3-patches/002-…](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md) |
| `h3-003-peek-buffered-trailers-before-fin` | `h3` | 0.0.8 | Add `RequestStream::peek_recv_trailers()` for already-buffered trailers before FIN | **Deliberate fork** — unfiled upstream; no published fork ref yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `poll_recv_trailers` buffers trailer HEADERS but waits for terminal FIN; gateway trailer-timeout collapse dropped trailers delivered before delayed FIN | Upstream files + merges the API **and** patches 001/002/004/005 are also retired | [docs/upstream-h3-patches/003-…](upstream-h3-patches/003-peek-buffered-trailers-before-fin/README.md) |
| `h3-004-send-stream-stopped-watch` | `h3` | 0.0.8 | Add `SendStreamStopped` so peer `STOP_SENDING` is observable as a `&self` + `'static` return-position `impl Future` without exclusive send-stream access | **Deliberate fork** — unfiled upstream; no published fork ref yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | After request HEADERS the gateway may block on backend headers without polling H3 frames; a client can cancel one multiplexed stream and leave destination `http2MaxRequests` held until the backend answers | Upstream files + merges the API **and** patches 001/002/003/005 are also retired | [docs/upstream-h3-patches/004-…](upstream-h3-patches/004-send-stream-stopped-watch/README.md) |
| `h3-005-max-buffered-frame-len` | `h3` | 0.0.8 | Bound the DECLARED payload length of a buffered non-`DATA` frame and refuse an over-declared frame with `H3_EXCESSIVE_LOAD` before any payload is buffered | **Deliberate fork** — unfiled upstream; no published fork ref yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock `h3` 0.0.8 parks on the declared length of a non-`DATA` frame and accumulates QUIC chunks without bound; QUIC flow control caps only bytes in flight, so one unauthenticated stream declaring 2^62-1 drives the process to OOM (#4261) | Upstream ships a receive-side declared-length bound refusing the frame BEFORE buffering **and** patches 001/002/003/004 are also retired | [docs/upstream-h3-patches/005-…](upstream-h3-patches/005-max-buffered-frame-len/README.md) |
| `h3-quinn-001-stop-sending-during-in-flight-read` | `h3-quinn` | 0.0.10 | Own `quinn::RecvStream` inline so `stop_sending` works while a read is in flight | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `RecvStream` parks its `quinn::RecvStream` in a `ReusableBoxFuture` while a read is pending, so `stop_sending` unwraps a `None` and aborts exactly when a full-duplex H3 server must send `STOP_SENDING(H3_NO_ERROR)` after its response completes | `h3-quinn` ships a release whose `stop_sending` is correct while a read is in flight **and** patch 002 is also retired | [docs/upstream-h3-quinn-patches/001-…](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/README.md) |
| `h3-quinn-002-send-stream-stopped-watch` | `h3-quinn` | 0.0.10 | Implement `h3::quic::SendStreamStopped` via Quinn `&self` + `'static` `stopped()` as a return-position `impl Future` | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock h3-quinn does not forward Quinn's `SendStream::stopped`, so a header wait cannot observe per-stream `STOP_SENDING` without exclusive send-stream access | `h3-quinn` ships a release with an equivalent watch **and** patch 001 is also retired | [docs/upstream-h3-quinn-patches/002-…](upstream-h3-quinn-patches/002-send-stream-stopped-watch/README.md) |
| `tungstenite-001-lossless-takeover` | `tungstenite` | 0.29.0 | `WebSocket::into_inner_with_read_buffer()` (lossless raw takeover) | [snapview/tungstenite-rs#556](https://github.com/snapview/tungstenite-rs/pull/556) | Ferrum Edge maintainers | Tunnel mode lost backend bytes coalesced with the `101` response when dropping to raw relay | **Both** this and tokio-tungstenite#380 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-002-frame-limit-origin` | `tungstenite` | 0.29.0 | Distinct `FrameTooLong` origin for pre-reservation frame policy | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Equal frame/message ceilings otherwise lose which parser boundary rejected input and can emit the wrong configured close reason | Upstream ships equivalent frame-vs-message capacity attribution, or the gateway no longer needs distinct policy reasons | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-003-optional-auto-pong` | `tungstenite` | 0.29.0 | `WebSocketConfig::auto_pong` opt-out for transparent Ping relay | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Stock framer auto-answers Ping while the gateway also forwards it, so one Ping yields two Pongs and a hung backend still looks healthy | Upstream ships equivalent default-true auto-Pong opt-out, or the gateway no longer needs transparent Ping/Pong | [docs/upstream-tungstenite-patches/003-…](upstream-tungstenite-patches/003-optional-auto-pong/README.md) |
| `tungstenite-005-stray-continuation-ordering` | `tungstenite` | 0.29.0 | Reject a stray continuation opcode before frame-size policy | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | A malformed continuation with a valid 63-bit declared length otherwise trips the size ceiling first and is misclassified as policy Close 1009 instead of an RFC 6455 protocol violation | Upstream rejects unexpected continuation state before caller frame-size policy, or the gateway no longer needs distinct protocol-vs-capacity attribution | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tokio-tungstenite-001-lossless-takeover` | `tokio-tungstenite` | 0.29.0 | `WebSocketStream::into_inner_with_read_buffer()` | [snapview/tokio-tungstenite#380](https://github.com/snapview/tokio-tungstenite/pull/380) | Ferrum Edge maintainers | Same lossless-takeover gap on the async wrapper | **Both** this and tungstenite#556 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-004-fragment-accounting` | `tungstenite` | 0.29.0 | `FragmentMeter` + `max_incomplete_message_frames` / `max_incomplete_message_duration` (physical-fragment accounting and bounds) | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | The reader only sees reassembled messages, so fragmented (including zero-length continuation) frames bypass per-message admission policy and are unbounded in count and duration | Upstream ships an equivalent pre-reassembly fragment hook **and** independent incomplete-message count/duration bounds | [docs/upstream-tungstenite-patches/004-…](upstream-tungstenite-patches/004-fragment-accounting/README.md) |
| `tokio-tungstenite-004-fragment-accounting-delegator` | `tokio-tungstenite` | 0.29.0 | `WebSocketStream::set_fragment_accounting()` | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Same accounting gap on the async wrapper, which hides the codec behind `SplitStream` after `split()` | Upstream ships the equivalent delegator alongside the tungstenite hook | [docs/upstream-tungstenite-patches/004-…](upstream-tungstenite-patches/004-fragment-accounting/README.md) |
| `dimpl-001-certificate-chain-and-key-zeroization` | `dimpl` | 0.6.1 | Full leaf-first certificate-chain transport and zeroizing private-key ownership | **Deliberate fork** — unfiled upstream; base commit `37bb0fa83f4167420729de5ea71c61852f82e9ed` ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Published releases expose only one local certificate and retain endpoint/fallback credential bytes in ordinary `Vec<u8>` owners | Upstream ships compatible full-chain DTLS 1.2/1.3 transport, peer-chain output, and drop-time key zeroization on all ownership paths | [docs/upstream-dimpl-patches/001-…](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/README.md) |
| `hyper-util-001-release-h1-sender-on-dispatch-close` | `hyper-util` | 0.1.21 | Legacy client releases an HTTP/1 connection's only request sender once its dispatcher stops reading, so a request stranded by a close during enqueue fails as unsent | **Deliberate fork** — no upstream PR; upstream issue [hyperium/hyper#4202](https://github.com/hyperium/hyper/issues/4202) (hyper-util has issues disabled; filed on hyper, where the stranding dispatcher lives) ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | tokio's unbounded `send` checks for closure and publishes in two steps; a backend RST/FIN on the pooled connection between them strands the request in a channel nobody reads, and hyper-util holds the last sender, so reqwest's `send()` hung until `backend_read_timeout_ms` (504) instead of failing fast (#5714) | A hyper-util release stops holding the only HTTP/1 sender after its dispatcher closes, or a hyper release stops stranding a racing send | [docs/upstream-hyper-util-patches/001-…](upstream-hyper-util-patches/001-release-h1-sender-on-dispatch-close/README.md) |
| `hyper-001-upgraded-h2-connect-error-reset` | `hyper` | 1.10.0 | `Upgraded::reset_with_connect_error()` resets an upgraded HTTP/2 `CONNECT` stream with `RST_STREAM(CONNECT_ERROR)` in place of the clean `END_STREAM` | issue [hyperium/hyper#4209](https://github.com/hyperium/hyper/issues/4209), PR [hyperium/hyper#4210](https://github.com/hyperium/hyper/pull/4210) (filed 2026-09-28) | Ferrum Edge maintainers | hyper's upgraded HTTP/2 stream is private and dropping or shutting it down always sends `END_STREAM`, so an HBONE relay that ended on a socket error looked like a normal close to the peer; RFC 9113 §8.5 names `CONNECT_ERROR` for a failed tunnel (#5781). Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `hyper` advisories against 1.10.0 manually | A hyper release containing PR #4210 (or an equivalent API that resets an upgraded HTTP/2 stream with a chosen error code) is adopted | [docs/upstream-hyper-patches/001-…](upstream-hyper-patches/001-upgraded-h2-connect-error-reset/README.md) |
| `hyper-002-min-data-frame-capacity` | `hyper` | 1.10.0 | A pending HTTP/2 body chunk makes progress with every positive amount of assigned capacity; no fixed minimum is imposed | **Deliberate fork** — current pending-body path unfiled; historical issue [hyperium/hyper#4211](https://github.com/hyperium/hyper/issues/4211), PR [hyperium/hyper#4212](https://github.com/hyperium/hyper/pull/4212) **closed unmerged 2026-10-04** ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | The former 1 KiB minimum could deadlock a legal 512-byte peer stream window; this was reproduced through the Ferrum Edge 0.9.10 release with headers received but zero body bytes. The pending-body path used by patch 004 must preserve Hyper's progress invariant for every legal peer window | Co-retire with patch 004 after adopting an equivalent upstream write-stall bound preserving positive-capacity progress, or moving the HTTP/2 client off Hyper; hosted replacement regressions must pass | [docs/upstream-hyper-patches/002-…](upstream-hyper-patches/002-min-data-frame-capacity/README.md) |
| `hyper-003-greedy-h1-read` | `hyper` | 1.10.0 | HTTP/1 `Buffered::poll_read_from_io` keeps reading into its buffer after a full-TLS-record read while the transport has more ready; the HTTP/1 upgrade handoff (`Rewind`/`Upgraded`) also carries a read error met during that read-ahead into the tunnel, after the buffered bytes | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | tokio-rustls returns one decrypted record per read, so bulk HTTP/1 bodies crossed hyper's dispatcher 16 KiB at a time; the per-chunk path cost Ferrum 14–20% CPU per request on large HTTPS/1.1 responses against Envoy (#5588). A reset met during read-ahead is kept for the next read, so an upgrade must hand it to the tunnel, or a WebSocket or TCP relay sees a clean EOF instead (#5911) | hyper or tokio-rustls hands over every readable record per read, or the vendored hyper is retired | [docs/upstream-hyper-patches/003-…](upstream-hyper-patches/003-greedy-h1-read/README.md) |
| `hyper-004-h2-body-write-timeout` | `hyper` | 1.10.0 | New request extension `hyper::ext::Http2BodyWriteTimeout`: the HTTP/2 client's body pipe runs a timer only while it holds a chunk it cannot yet write (window exhausted or send buffer full), re-arms it on every chunk written, and resets the stream with `CANCEL` when it fires; with the extension the pipe polls the body before waiting for capacity | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | hyper's pipe parks on flow control without polling the body, so `backend_write_timeout_ms` needed a gateway-owned upload pump (a task boundary and channel per frame, about 3.5% gateway CPU on 10 KiB gRPC), and direct-H2 passthrough enforced no write bound at all (#5588). Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `hyper` advisories against 1.10.0 manually | Co-retire with patch 002 after adopting an equivalent upstream write-stall bound preserving positive-capacity progress, or moving the HTTP/2 client off Hyper; hosted replacement regressions must pass | [docs/upstream-hyper-patches/004-…](upstream-hyper-patches/004-h2-body-write-timeout/README.md) |
| `hyper-005-h2-small-window-coalescing` | `hyper` | 1.10.0 | While a ready HTTP/2 body chunk holds positive capacity below `min(chunk remaining, 256)`, the client and server body pipes wait up to 2 ms for more, then hand h2 exactly the assigned capacity (a zero-copy `Bytes` split), so h2 cannot cut a DATA frame from every small window increment; a chunk the stream already holds window for goes to h2 whole even when the send buffer caps `capacity()` (h2 patch 003's `capacity_and_assigned`; stock h2 falls back to splitting), except on a pipe with a patch-004 write-stall bound, which keeps splitting; enabled only on connections with a `Timer` | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | With patch 002's positive-capacity progress, a peer that opens its window a few bytes at a time received one DATA frame per increment, a self-sustaining run that an unpatched h2 0.4.16+ receiver answers with `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")` (#6033). The wait is bounded, so a window that never reaches 256 bytes still progresses. Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `hyper` advisories against 1.10.0 manually | Co-retire with patches 002 and 004, or earlier when hyper or h2 coalesces small window increments while keeping every positive window live; hosted trickling-window and lockstep-window regressions must pass | [docs/upstream-hyper-patches/005-…](upstream-hyper-patches/005-h2-small-window-coalescing/README.md) |
| `hyper-006-h2-stream-termination-origin` | `hyper` | 1.10.0 | New `hyper::ext::take_h2_stream_termination()`: while hyper drops a pending HTTP/2 service future after a stream reset, it reports whether the peer reset the stream, the transport was lost, or hyper's own HTTP/2 stack reset it (`H2StreamTermination`) | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | The dropped future's drop glue cannot tell a client's `RST_STREAM` from a local `PROTOCOL_ERROR` reset, so Ferrum could not record exactly one honest terminal for an admitted request hyper dropped: `499` needs positive evidence of a peer cancellation (#6768). Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `hyper` advisories against 1.10.0 manually | Co-retire with h2 patch 004 when hyper exposes why a server stream ended to the service, or Ferrum stops serving HTTP/2 through hyper | [docs/upstream-hyper-patches/006-…](upstream-hyper-patches/006-h2-stream-termination-origin/README.md) |
| `h2-001-coalesce-data-frame-writes` | `h2` | 0.4.20 | `FramedWrite` copies DATA payloads into its write buffer while it stays within about 64 KiB, instead of chaining one DATA frame at a time, so the frames staged in one `Prioritize` pass leave in one write; a grown buffer is dropped when the connection has nothing more to write | issue [hyperium/h2#902](https://github.com/hyperium/h2/issues/902), PR [hyperium/h2#903](https://github.com/hyperium/h2/pull/903) (third-party, open since 2026-05-05; queues frames instead of copying) | Ferrum Edge maintainers | Every DATA frame cost its own `writev` and peer wakeup, and over TLS a second, 9-byte record for each maximum-size frame; coalesced writes made HTTP/2 through Ferrum 8–24% faster (gRPC 5–7%) on the protocol benchmark (#5588). Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `h2` advisories against 0.4.20 manually | An h2 release containing PR #903 (or another change that batches DATA frames into one write) is adopted, or Ferrum stops using h2; the assigned-send-capacity patch must also retire before dropping the crate | [docs/upstream-h2-patches/001-…](upstream-h2-patches/001-coalesce-data-frame-writes/README.md) |
| `h2-003-assigned-send-capacity` | `h2` | 0.4.20 | New read-only `SendStream::capacity_and_assigned()`: `capacity()` plus the flow-control window already assigned to a stream that buffered data has not claimed (ignoring the send-buffer limit that caps `capacity()`), read under one lock | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Hyper patch 005 must split a body chunk only when the peer's window is short; `capacity()` cannot tell that apart from a full send buffer, so a 1 MiB backend response chunk against the 400 KiB default buffer was split and stalled the frontend response pipe (3–9% at 500 KiB–1 MiB on the HTTP/2 benchmark). Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `h2` advisories against 0.4.20 manually | Retire with Hyper patch 005, or when an h2 release exposes the assigned send window | [docs/upstream-h2-patches/003-…](upstream-h2-patches/003-assigned-send-capacity/README.md) |
| `h2-004-reset-origin` | `h2` | 0.4.20 | New read-only `SendResponse::reset_is_local()`: whether the reset or `GOAWAY` that closed a stream was sent by this endpoint or received from the peer | **Deliberate fork** — no upstream filing yet ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `poll_reset` reports library-generated resets (a `content-length` overrun `PROTOCOL_ERROR`) through the same call as a peer `RST_STREAM`; Hyper patch 006 needs the initiator h2 already records. Path-sourced, so `cargo deny` advisory matching may skip it: check RUSTSEC `h2` advisories against 0.4.20 manually | Retire with Hyper patch 006, or when an h2 release exposes the reset initiator | [docs/upstream-h2-patches/004-…](upstream-h2-patches/004-reset-origin/README.md) |

> Ownership note: `vendor/`, `deny.toml`, this doc, `docs/vendored-patch-lifecycle.json`,
> `docs/upstream-*-patches/`, and the vendored-patch scripts are owned via
> [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`). Upstream `h3`
> work is staged from the `jeremyjpj0916/h3` fork: **h3-001** records a published
> `fork_ref` for its filed upstream PR, while **h3-002** through **h3-005** have
> `fork_ref: null` in `docs/vendored-patch-lifecycle.json` pending maintainer
> handoff. Every patch without an upstream PR is governed by the
> [Deliberate fork policy and SLA](#deliberate-fork-policy-and-sla) below.

### Deliberate fork policy and SLA

As of 2026-10-04, seven patches ride an **open upstream PR** (reqwest #3017,
h3 #339, tungstenite #556 / tokio-tungstenite #380, hyper #4210, and h2 #903 /
#965); the weekly
`scripts/check_vendored_patch_status.sh` (backed by
`docs/vendored-patch-lifecycle.json`) polls those and goes red when one
merges. Every other row in the inventory table is marked **Deliberate fork**
(`upstream.filing: deliberate_fork_unfiled` in the lifecycle JSON), including
sqlx-core, reqwest 002–004, h3 002–005, both h3-quinn patches, the tungstenite /
tokio-tungstenite extensions other than lossless takeover, dimpl,
Hyper 002/003/004, h2 003, and hyper-util (which has upstream issue
[hyperium/hyper#4202](https://github.com/hyperium/hyper/issues/4202) but no
upstream PR). These are not untracked TODOs; they are carried as
**deliberate, time-boxed forks** and are governed as follows:

Hyper #4212 closed **unmerged** on 2026-10-04 at 08:45:54 UTC. Hyper patch
002's current pending-body path is therefore recorded as a deliberate fork,
with the old issue/PR retained as history in its README. It co-retires with
patch 004 after an equivalent progress-preserving timeout implementation is
adopted and tested, or the HTTP/2 client moves off Hyper. No replacement
release or dated owner reaffirmation is recorded for either patch; the owner
must file a current equivalent proposal or record matching dated reaffirmations
before the stable-release checkpoint below. h2 #965 remains an independent
open proposal with its own release-adoption trigger.

- **Owner.** The dependency-governance owner in
  [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`) — the same
  owner for `vendor/`, `deny.toml`, this doc, `docs/upstream-*-patches/`, and
  the vendored-patch scripts.
- **Review cadence (SLA).** Every weekly `dependency-audit` run lists each
  fork-only patch as `NOT YET FILED`. At each run the owner either (a) files the
  upstream issue/PR and records the numbers in the inventory table, the per-patch
  `README.md` Status block, **and**
  [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json), or (b) leaves it as a conscious
  re-affirmation that the fork is still the right call.
- **Hard checkpoint — no unfiled fork ships in a stable release.** A fork-only
  patch (no upstream PR link) may **not** survive the first tagged stable release
  (the schema-freeze milestone in
  [migrations.md → Stability & Upgrade Contract](migrations.md#when-v002-migrations-start-the-schema-freeze))
  without either a filed upstream issue/PR link recorded in the inventory table,
  or an explicit dated re-affirmation
  (`Deliberate fork — re-affirmed YYYY-MM-DD by <owner>: <reason>`) in the
  patch's `README.md`, mirrored into the `reaffirmation` object of the matching
  `docs/vendored-patch-lifecycle.json` entry. A reaffirmation is a
  deliberate-fork record only: CI rejects one on a patch whose `upstream.filing`
  is `filed`, so reaffirming a fork that shares a `README.md` with filed patches
  (as `tungstenite-002-frame-limit-origin` does) does not drag them in. This
  keeps "not yet filed" from silently becoming permanent in a released product.
- **Retirement is unchanged.** Whether upstreamed via PR or carried as a fork,
  each patch retires per its `README.md` retirement plan and the co-vendoring
  rule (all five h3 patches retire together — see the inventory `Removal
  trigger` column).

## Enforcement controls

### 1. Blocking dependency gate (`deny.toml` + CI)

`cargo deny check advisories bans sources licenses` runs whenever CI selects
the full dependency-audit lane (`ci-plan` full mode plus `run_dependency_audit`)
for an eligible pull request, merge group, push to `main`, or manual dispatch
(`dependency-audit` job in `.github/workflows/ci.yml`) and is **blocking**: any
RUSTSEC advisory in the resolved tree that is not explicitly time-boxed in
`deny.toml` fails CI. `unmaintained`/`unsound` are set to `all` (not the 0.19
default of `workspace`) so transitive advisories are blocking too, and
`unused-ignored-advisory = "deny"` forces a stale exception to be deleted once
its advisory is fixed/removed. `bans` (duplicate-version visibility) and
`sources` (crates.io-only) run alongside. The `[licenses]` allowlist and
`confidence-threshold` are **blocking** too: any dependency whose SPDX
expression is outside the allowlist or below the confidence floor fails CI.

The gate runs **twice**, in both the per-PR `dependency-audit` job and the weekly
`.github/workflows/dependency-audit.yml`: once over the root workspace, and once
over `ebpf/Cargo.toml` with `--config deny.toml` so both invocations share one
policy and the allowlists cannot drift. `ebpf/` is a separate `[workspace]` with
its own lockfile, and the root crate path-depends only on `ferrum-ebpf-common` —
so `ferrum-ebpf` (aya-ebpf / aya-log-ebpf and their transitive tree) is invisible
to the root-graph check. That object is nonetheless built by the `ebpf-builder`
stage in `Dockerfile` and shipped in the published `-ebpf` / `-ebpf-tools`
images, where the mesh chart runs it privileged on the host network. Both eBPF
members are `publish = false`, so `[licenses] private = { ignore = true }`
already covers their PolyForm-Noncommercial first-party licenses. Do not add an
`ebpf/deny.toml`: a second config would let the two policies diverge.

Both lanes also run an **advisories-only** pass over every standalone Cargo
workspace (`fuzz/`, `tests/performance/**`, and any crate added later), each of
which resolves its own committed `Cargo.lock` that neither check above can see
(issues #5704, #5708). The manifest list comes from
`.github/scripts/standalone_cargo_manifests.py`, the same inventory the ci.yml
`standalone-cargo` fmt/check gate uses, so a new standalone crate is audited
without editing either workflow. These harnesses never ship, so the license and
ban policy is not applied to them; a vulnerable, unsound, or yanked version in
one of their lockfiles is still blocking. The weekly workflow additionally runs
the informational `cargo audit --file <lockfile>` over each of them. Refresh a
standalone lockfile with a targeted
`cargo update --manifest-path <manifest> -p <crate>@<locked-version>` so the
benchmark inputs stay otherwise stable.

Run locally:

```bash
cargo install --locked cargo-deny
cargo deny check advisories bans sources licenses   # the gate (root workspace)
cargo deny --manifest-path ebpf/Cargo.toml \
    check --allow advisory-not-detected --config deny.toml advisories bans sources licenses          # the gate (eBPF workspace)
for manifest in $(python3 .github/scripts/standalone_cargo_manifests.py); do
  cargo deny --manifest-path "$manifest" \
    check --allow advisory-not-detected --config deny.toml advisories   # standalone workspaces
done
```

### 2. Advisory exceptions are time-boxed

Every `[advisories.ignore]` entry in `deny.toml` carries a rationale and an
`[expires:YYYY-MM-DD]` token **inside its table `reason` string**.
`scripts/check_advisory_expiry.sh` (run by the per-PR gate **and** the weekly
workflow) fails once any date passes — or if an entry uses the string form or a
comment-only token, both of which would dodge the time-box — so an exception
cannot silently become permanent. A maintainer must re-fix the advisory or
consciously extend the window.

Each entry documents the confinement and the upstream it is waiting on. A
re-review checks the latest upstream release of the crate and of every parent
that pulls it in, and either retires the entry (bump, feature change, or
migration) or re-affirms it with dated evidence and a new time box.

#### Advisory exception register

Last full re-evaluation: 2026-09-24 (issue #5721). Latest upstream versions
below were checked against crates.io and the RustSec advisory database on that
date.

| Advisory | Crate | Disposition | Evidence / tracking |
|---|---|---|---|
| RUSTSEC-2023-0071 | `rsa` 0.9.10 (Marvin timing side-channel) | **Re-affirmed** until 2026-12-31 | No fixed release: RustSec `patched = []`; 0.9.10 is the latest stable and 0.10.0-rc.18 (required by sqlx 0.9.0) is still affected. Reached via `sqlx-mysql` (public-key OAEP encryption of the MySQL password only, no private-key operation) and via jsonwebtoken's `rust_crypto` backend in the default `crypto-ring` profile, where RSA *signing* of outbound client assertions (`private_key_jwt` in `oidc_relying_party` / `oauth2_introspection`, `ai_federation` service-account JWTs) runs on the non-constant-time code. For `oidc_relying_party` / `oauth2_introspection`, EC/EdDSA assertion keys or the `fips` profile (`aws_lc_rs`) avoid it. `ai_federation` always signs RS256 (GCP service-account keys are RSA), so only the `fips` profile avoids it there. Retire when `rsa` ships a fix. |
| RUSTSEC-2024-0436 | `paste` 1.0.15 (unmaintained) | **Re-affirmed** until 2026-12-31 | Proc-macro only; no runtime surface. `tikv-jemalloc-ctl` still depends on `paste ^1` in its latest 0.7.0, and the test matrix macro (`tests/scaffolding/matrix.rs`) uses it as a dev-dependency. Retire when `tikv-jemalloc-ctl` drops it. |
| RUSTSEC-2024-0449 | `unsafe-libyaml` 0.2.11 (unmaintained) | **Added** 2026-10-12, until 2026-12-31 | Informational, not a known vulnerability: the repository was archived on 2024-03-25, RustSec lists `patched = []`, and 0.2.11 is the last release. Reached via `serde_yaml` 0.9.34+deprecated (file-mode and mesh file config loaders, config migration, API-spec YAML export) and via the direct pin that drives the libyaml event parser in `src/admin/api_specs/bounded_yaml.rs` and `src/config/yaml_alias_budget.rs` to bound alias expansion (#3307, PR #3843). Present in the root and `fuzz/` lockfiles, not in `ebpf/`. Inputs are operator-controlled (config files, the Kubernetes MeshConfig ConfigMap) or authenticated Admin API spec bodies parsed under size, node, depth, alias, and work budgets; no unauthenticated network input reaches libyaml. Forks such as `serde_yaml_ng` still depend on `unsafe-libyaml`, so retire by migrating `serde_yaml` and both event parsers to a safe-Rust YAML parser (`saphyr` / `serde-saphyr`). |
| RUSTSEC-2026-0118, RUSTSEC-2026-0119 | `hickory-proto` 0.25.2 | **Retired** | Only `mongodb` < 3.7 pulled hickory 0.25. `mongodb` 3.7.0 moved to hickory 0.26. `Cargo.toml` now requires `3.9.1` (the lockfile resolves 3.9.1, also the fix for CVE-2026-88024), so the hickory 0.25 line cannot return. |
| RUSTSEC-2026-0098, RUSTSEC-2026-0099, RUSTSEC-2026-0104 | `rustls-webpki` 0.101.7 | **Retired** | Came only from rustls 0.21 in the AWS SDK's legacy `rustls` connector (`aws-smithy-runtime/tls-rustls`). `aws-sdk-secretsmanager` is now built with `default-features = false` and `default-https-client` + `rt-tokio`, the hyper 1.x / rustls 0.23 client that `aws_config::load_defaults` already selected. |
| RUSTSEC-2026-0258 | `h2` 0.3.27 | **Retired** | Same legacy AWS connector (hyper 0.14). The gateway's own h2 0.4.x stays on the patched release. |
| RUSTSEC-2025-0134 | `rustls-pemfile` 2.2.0 (unmaintained) | **Retired** | PEM parsing uses the `rustls-pki-types` `PemObject` API (`CertificateDer::pem_slice_iter`, `PrivateKeyDer::from_pem_slice`, `CertificateRevocationListDer::pem_slice_iter`), the code `rustls-pemfile` 2.2 already wrapped. `crate::tls::first_pem_private_key` keeps the old `Result<Option<_>>` contract where callers distinguish "no key" from "malformed". The standalone `tests/performance/**` harnesses were migrated the same way and their lockfiles refreshed. |

### 3. License allowlist and exceptions

The `[licenses]` section in `deny.toml` defines the SPDX allowlist and
`confidence-threshold` enforced by the same `cargo deny` gate as advisories.
Vendored path dependencies under `vendor/` are evaluated like any other crate;
their upstream licenses (MIT, Apache-2.0, and similar permissive terms for the
current patches) must fall within the allowlist or carry an explicit exception.

Every `[licenses.exceptions]` entry must document an **owner**, a **rationale**,
and an `[expires:YYYY-MM-DD]` token. The owner and rationale are a review
requirement; the automated checker enforces only the expiry token and its
date: `scripts/check_advisory_expiry.sh` walks the `exceptions` array in
`deny.toml` and fails on a missing token or a passed date, on the per-PR
`dependency-audit` job in `.github/workflows/ci.yml` **and** on the weekly
`.github/workflows/dependency-audit.yml`, so a license exception cannot become
permanent by default.

The token lives in a **comment**, not in the entry value, because cargo-deny's
two schemas differ: an `[advisories.ignore]` table accepts a free-text `reason`
field, while a `[licenses.exceptions]` entry does not — cargo-deny 0.19.9 rejects
every key other than the crate spec plus `allow`
(`error[unexpected-keys]: found 1 unexpected keys, expected: ["allow"]`). The
convention is a `#` comment on the line immediately preceding the entry (a
trailing comment on the entry line is also accepted), and it binds to exactly one
entry:

```toml
exceptions = [
    # owner: platform — vendored root-store data license [expires:2026-12-31]
    { crate = "some-crate", allow = ["Some-License-1.0"] },
]
```

Both the single-line `{ ... }` form and the multi-line `{` / `}` form are parsed.
Run `scripts/check_advisory_expiry.sh --self-test` to exercise the checker
against synthetic fixtures (valid entry, missing token, past date, string-form
advisory ignore, empty/absent `exceptions`); both workflows run that self-test
immediately before the real check, so the rule cannot rot into a no-op.

### 3a. Third-party license inventory

Both the per-PR `dependency-audit` job and the weekly workflow emit a crate →
license listing from the **locked** graph:

```bash
cargo deny list --format json --layout crate > third-party-licenses.json
```

`cargo deny list` reads `cargo metadata` only and compiles nothing, so it needs
no build. The file is uploaded as the `third-party-licenses` artifact
(30-day retention); download it from the Artifacts section of the run summary for
the relevant CI or Dependency Audit run. Producing it next to the gate that
enforces the allowlist is what keeps shipped notices from silently diverging from
what the tree actually resolves to.

The inventory is **not** attached to GitHub Releases. `release.yml`'s
`create-release` job is byte-frozen by the trusted publication boundary
(`.github/scripts/verify_cross_build_policy.py`, see `docs/ci_cd.md` →
"Publish-blocking required checks"), so adding a release asset there is a
direct-to-`main` change no pull request can make.

### 4. Vendor drift guard

`tests/integration/vendor_integrity_tests.rs` hashes every governed file under
`vendor/` and compares it to `vendor/VENDOR_INTEGRITY.sha256`. Known text paths
(allowlisted source/docs/config extensions and basenames) use LF-normalized
SHA-256 (`\r` stripped) so CRLF checkouts stay stable; binary artifacts and any
unrecognized path are hashed byte-for-byte so CR bytes in `.der` / `.bin` (and
similar) cannot change unnoticed. Incidental crate-local `Cargo.lock` files
created by documented standalone vendor tests are ignored by default; intentionally
committed lockfiles that pin a standalone regression graph (currently
`vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock`) are allowlisted in
`GOVERNED_VENDOR_LOCKFILES` and must appear in the manifest. The guard runs in
the normal integration suite (the `protocols-data-plane` shard), so a PR that
changes any governed vendored byte without regenerating the manifest **fails CI**.
This keeps the vendored diff reviewable: an unexpected edit to upstream code
cannot slip in unnoticed.

Regenerate only as part of an intentional, documented patch change:

```bash
scripts/update_vendor_integrity.sh
# i.e. UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity
```

### 5. Scheduled `dependency-audit` workflow

`.github/workflows/dependency-audit.yml` runs weekly (Mon 05:30 UTC) and on
demand:

- **advisories and licenses** — re-runs the `cargo deny` gate (advisories, bans,
  sources, and licenses) against the freshly-fetched advisory DB (catches new
  advisories or license violations with no PR), runs the advisory expiry check,
  and runs `cargo audit` as an independent second opinion.
- **upstream-patch-status** — two steps. *Vendored-patch lifecycle parity* runs
  `scripts/check_vendored_patch_lifecycle.py`, which self-tests its validators
  and then verifies that every patch in `docs/vendored-patch-lifecycle.json`
  matches `Cargo.toml`, `vendor/`, the inventory Lifecycle ID set and upstream
  PR/issue numbers here, the upstream-status wrapper delegation, and per-patch
  READMEs. *Check upstream status* then runs
  `scripts/check_vendored_patch_status.sh`, which delegates to the same checker's
  `--upstream-status` mode and queries each tracked upstream PR. The run goes
  **red when an upstream PR has merged** (a retirement signal — run the
  compatible-release test before deleting vendor copies), unless the patch has a
  reviewed `retirement.merged_release_hold` because a compatible released fix is
  unavailable. That record must name the patch owner, exact upstream merge SHA,
  reviewed latest stable version, evidence, reason, and a review window of at most
  30 days; its compatibility test must remain `blocked`. The README must carry the
  same review. A changed or unknown release, an unconfirmed merge, or expiry fails
  the audit again. Other merged patches still fail by default. The audit reports
  active holds, latest crates.io releases, and deliberate-fork reaffirmation gaps.

The per-PR `dependency-audit` job in `ci.yml` runs the same parity gate. Because
that job is required to stay behind `mode == 'full'`,
`.github/scripts/pr_ci_plan.py` keeps `docs/dependency-policy.md`,
`docs/vendored-patch-lifecycle.json`, and `docs/upstream-*-patches/` on full CI —
a governance-doc-only pull request cannot skip the gate that guards it.

### 6. Behavioral regression tests for the patched behaviors

The patches fix runtime behavior; these tests guard that behavior independently
of the vendor copy and must keep passing after retirement:

- A configured database root CA is the ONLY trust anchor under `verify-ca` and
  `verify-full` — the vendored sqlx-core regressions
  (`net::tls::tls_rustls::tests::root_store_with_configured_ca_replaces_the_default_trust_store`,
  `net::tls::tls_rustls::tests::verify_ca_refuses_a_certificate_from_an_unconfigured_ca`),
  run with
  `cargo test --manifest-path vendor/sqlx-core-0.8.6-ferrum-patched/Cargo.toml --no-default-features --features _rt-tokio,_tls-rustls-ring-webpki --lib tls_rustls::tests`,
  plus `tests/service_integration/db_tls.rs` and the
  `FERRUM_DB_TLS_MODE=verify-ca` without-CA rejection in
  `tests/unit/config/env_config_tests.rs`. Upstream ADDS the configured CA to
  the bundled public roots, which combined with the `verify-ca` hostname waiver
  accepts any publicly-trusted certificate for any name.
- Native REAL/DOUBLE typed-NULL parameter types through SQLx Any —
  `tests/integration/admin_conditional_write_tests.rs`
  (`postgres_conditional_restore_checks_state_and_lease_in_transaction`, via
  `assert_postgres_any_float_null_parameter_types`) in the existing hosted
  **Integration Tests (conditional-live-stores)** gate. `pg_typeof` observes
  uncast parameters and both `IS NULL` witnesses must pass.
- Per-request connect timeout across shared pool keys —
  `tests/integration/connection_pool_tests.rs`
  (`test_connect_timeout_does_not_fragment_pool`,
  `test_pooled_client_exposes_per_request_connect_timeout`).
- HTTP/3 graceful close with a buffered response is not a false 502 —
  `tests/integration/http3_integration_tests.rs`
  (`h3_buffered_response_survives_graceful_close_race`,
  `h3_goaway_after_complete_body_is_treated_as_graceful`,
  `h3_stream_reset_after_partial_body_is_not_treated_as_graceful`), plus
  `tests/functional/scripted_backend_h3_tests.rs`.
- HTTP/3 per-stream `STOP_SENDING` releases destination `http2MaxRequests`
  while the multiplexed QUIC connection stays open —
  `tests/unit/gateway_core/http3_server_dispatch_tests.rs`
  (`h3_plain_header_wait_races_per_stream_stop_sending_not_only_connection_close`,
  `h3_quinn_vendored_send_stream_stopped_is_shared_and_static`) and
  `tests/functional/functional_destination_active_requests_h3_test.rs`
  (same-connection cancellation, including streaming upload).
- The h3 frame-drain unit tests live in the vendored crate
  (`vendor/h3-0.0.8-ferrum-patched/src/frame.rs::tests`) and on upstream PR #339;
  run them with
  `cargo test --manifest-path vendor/h3-0.0.8-ferrum-patched/Cargo.toml --lib frame`.
- The tungstenite pre-reservation frame-origin regression lives in the vendored
  crate (`protocol::frame::tests::size_limit_hit`) and runs alongside the
  raw-takeover regression in the vendored-patch job.
- The tungstenite `auto_pong` opt-out regressions live in the vendored crate
  (`protocol::tests::auto_pong_*`) and in
  `tests/unit/gateway_core/websocket_auto_pong_tests.rs`, with end-to-end
  coverage in `tests/functional/functional_websocket_test.rs`
  (`test_*websocket_ping_*`).
- The tungstenite / tokio-tungstenite fragment-accounting regressions live in
  the vendored crate (`protocol::tests::fragment_*`,
  `protocol::tests::incomplete_message_*`) and in
  `tests/unit/gateway_core/websocket_fragment_metering_tests.rs`.
- The dimpl credential regressions live in
  `vendor/dimpl-0.6.1-ferrum-patched/tests/auto/credential_security.rs`. They
  cover DTLS 1.2 and 1.3 chain transmission plus deterministic clone,
  failed-construction, fallback, and shutdown zeroization observations. The
  Ferrum integration suite separately verifies a root-only client completes a
  handshake because the configured intermediate is transmitted.

- An HTTP/1 request stranded by a connection close during enqueue fails as
  unsent instead of hanging until `backend_read_timeout_ms` (issue #5714) — the
  vendored hyper-util regressions
  (`client::legacy::client::ferrum_release_on_close_tests`), run with
  `cargo test --manifest-path vendor/hyper-util-0.1.21-ferrum-patched/Cargo.toml --features full --lib ferrum_release_on_close_tests`,
  plus hyper-util's own `--test legacy_client` suite for ordinary keep-alive,
  reuse, and close behavior through the patched send path. The race sits
  between two instructions inside tokio's `send`, so the regressions build the
  state it leaves behind rather than scheduling it. The `pooled_http1` tests in
  that module run the step `Client::try_send_request` takes after queuing a
  request (`await_pooled_response`) against a real pooled HTTP/1 connection.
- An HTTP/1 read that returned a full TLS record's worth keeps reading while
  the transport has more ready, a short read never triggers another, and an
  error from an additional read is delivered after the already-buffered bytes,
  including to the tunnel of an upgraded client or server connection
  (issues #5588, #5911) — the vendored hyper regressions
  `proto::h1::io::tests::ferrum_greedy_read_*`, run with
  `cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_greedy_read`.
- HTTP/2 DATA frames staged together leave in one write, byte-exact and in
  order with interleaved control frames, while the write buffer stays within
  about 64 KiB; a larger payload is still chained without a copy, partial
  writes keep the byte stream intact, and a grown buffer is kept across writes
  but dropped once the connection is idle, including end to end on a real
  client connection (issue #5588) — the vendored h2 regressions
  `codec::framed_write::ferrum_coalesce_data_frame_writes_tests`, run with
  `cargo test --manifest-path vendor/h2-0.4.20-ferrum-patched/Cargo.toml --lib ferrum_coalesce_data_frame_writes`.
- An HTTP/2 client request body that stops being written for longer than its
  `Http2BodyWriteTimeout` resets the stream with `CANCEL`, a slow client body
  never trips it, steady progress re-arms it, and a request carrying it on a
  connection without a timer fails (issue #5588) — the vendored hyper
  regressions `proto::h2::ferrum_body_write_timeout_tests`, run with
  `cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_body_write_timeout`.
- An HTTP/2 request body makes progress with a legal 512-byte peer stream
  window and with the final byte of connection capacity
  (hyperium/hyper#4211/#4212) — the vendored Hyper regressions
  `proto::h2::ferrum_h2_flow_control_progress_tests`, run with
  `cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_h2_flow_control_progress`, plus
  `grpc_upload_progresses_with_512_byte_backend_stream_window` in
  `tests/functional/scripted_backend_h2_tests.rs`.
- h2's automatic small-DATA-frame budget follows runtime target-window
  changes, while configured budgets and outstanding charges remain intact
  (hyperium/h2#965, released in h2 0.4.20) — upstream's budget regressions,
  run on the patched vendored crate with
  `cargo test --manifest-path vendor/h2-0.4.20-ferrum-patched/Cargo.toml --lib budget`.
- An HBONE relay that ends on a socket error resets its CONNECT stream with
  `RST_STREAM(CONNECT_ERROR)`, while a normal close still ends it with
  `END_STREAM` (issue #5781) — the vendored hyper regressions
  (`proto::h2::upgrade::ferrum_connect_error_reset_tests`), run with
  `cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_connect_error_reset`,
  plus the gateway tests in `tests/integration/mesh_hbone_tests.rs`
  (`hbone_relay_backend_reset_sends_rst_stream_connect_error`,
  `hbone_relay_backend_close_still_ends_stream_cleanly`,
  `egress_udp_relay_socket_error_sends_rst_stream_connect_error`,
  `egress_udp_relay_tunnel_close_still_ends_stream_cleanly`).

CI gates these vendored-patch contracts in the `Vendored Patch Regressions`
job in `.github/workflows/ci.yml`. Keep that job in sync with this list when
adding, retiring, or changing a vendored patch.

## Procedures

### Adding a vendored patch

1. Confirm a dependency bump / feature flag / gateway workaround can't do it.
2. Copy the locked crates.io source into `vendor/<crate>-<ver>-ferrum-patched/`,
   apply the minimal upstream-proposed diff, and keep the diff reviewable (no
   private Ferrum-only API beyond the proposed surface).
3. Wire it through `[patch.crates-io]` in `Cargo.toml` with a comment block.
4. Add `docs/upstream-<crate>-patches/NNN-…/` with `README.md` (status, upstream
   links, retirement plan), the unified `.patch`, and issue/PR drafts.
5. Add a behavioral regression test for the fixed behavior and wire it into the
   `Vendored Patch Regressions` CI job when it lives outside the normal root
   test matrix.
6. Add a row to the inventory table above (with a unique Lifecycle ID) and a
   matching entry to
   [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json).
7. Regenerate the drift manifest: `scripts/update_vendor_integrity.sh`.
8. File the upstream issue/PR and record the numbers.

### Refreshing a vendored patch (upstream review changes)

1. Re-fetch the upstream diff, re-apply over the pinned base version, copy the
   sources back into the vendor directory.
2. Update the per-patch `.patch` and README notes.
3. **Regenerate the drift manifest** (`scripts/update_vendor_integrity.sh`) and
   review the diff — the manifest change is the audit trail.
4. Run the behavioral regression tests.

### Retiring a vendored patch

Trigger: the upstream PR merges **and** ships in a release we consume (for
co-vendored patches such as `h3`, `h3-quinn`, and tungstenite, *every* patch in
the group must be ready — see the `Removal trigger` column).

1. Bump the registry version in `Cargo.toml` `[dependencies]` to the release
   containing the fix.
2. Remove the crate's line from **every** `[patch.crates-io]` table that
   points at the vendor directory. Standalone workspaces do not inherit the
   root table, so each keeps its own mirror: the root `Cargo.toml`,
   `fuzz/Cargo.toml` and `tests/performance/mesh/Cargo.toml`. Find them all
   with `git grep -n '<crate>-<ver>-ferrum-patched' -- '*Cargo.toml'`.
3. Regenerate every affected lockfile while the vendor directory still exists
   — `Cargo.lock`, `fuzz/Cargo.lock` and `tests/performance/mesh/Cargo.lock`
   (for example `cargo update -p <crate>` and
   `cargo update --manifest-path fuzz/Cargo.toml -p <crate>`). Confirm the root
   and fuzz tables still agree with
   `cargo test --test unit_gateway_core_tests fuzz_workspace_patches_every_vendored_crate_the_root_patches`
   (`tests/unit/gateway_core/fuzz_target_schedule_parity_tests.rs`), which CI
   also runs.
4. `git rm -r vendor/<crate>-<ver>-ferrum-patched/` (and `vendor/` if empty),
   then `git grep '<crate>-<ver>-ferrum-patched'` for remaining references
   (CI steps in `.github/workflows/ci.yml`, `.github/scripts/`, `Dockerfile.test`).
5. Move `docs/upstream-<crate>-patches/NNN-…/` to `…/_retired/NNN-…/` with a
   `STATUS.md` (merge commit + registry version), or delete per that crate's
   README.
6. Remove the inventory row (Lifecycle ID) and the matching `docs/vendored-patch-lifecycle.json`
   entry.
7. Regenerate the drift manifest (now smaller) and keep the gateway call sites —
   they use the upstream API by design.
8. Run the behavioral regression tests; they must still pass.

### Emergency security update for a vendored crate

A vendored crate masks its upstream from a normal `cargo update`, so a CVE in the
reqwest/h3/tungstenite lineage needs an explicit path:

1. **Triage** which version fixes it and whether our patch applies cleanly to
   the fixed source.
2. **If a fixed release exists and we can retire:** follow "Retiring a vendored
   patch" immediately (bump + drop the vendor copy).
3. **If we must keep the patch:** re-vendor on top of the *fixed* upstream
   version — copy the patched-fixed source into a new
   `vendor/<crate>-<fixedver>-ferrum-patched/`, re-apply our minimal diff,
   update `[patch.crates-io]`, the per-patch docs, the inventory row, and
   **regenerate the drift manifest**.
4. **If neither is possible yet (no fix upstream):** add a time-boxed
   `[advisories.ignore]` in `deny.toml` with a rationale documenting the
   confinement and a near-term `[expires:]` date, and open a tracking issue.
5. Land the change on an expedited review per `SECURITY.md` severity timelines.
6. Never silence an advisory without an expiry and a rationale — the expiry
   check will fail the weekly run otherwise (by design).

### Cargo dependency updates

`.github/dependabot.yml` schedules weekly `cargo` version updates for two
directories:

- `/`, the root workspace;
- `/tests/performance/mesh`, the mesh benchmark crate. It path-depends on the
  root crate and mirrors its `[patch.crates-io]` table, and the `Mesh Benchmark
  Lockfile` workflow checks its lockfile.

Minor and patch updates are grouped (`cargo-minor-patch`) into one PR per
directory per week. A semver-major update gets its own PR. The crates replaced
by a vendored `[patch.crates-io]` copy, and the `sqlx*` crates (which pin
`sqlx-core` exactly), are in `ignore`. Moving one of them past its vendored
version would make Cargo pick the crates.io release and drop the Ferrum patch
without failing the build. Cargo only warns that the patch was unused. These
crates move only through "Refreshing a vendored patch", "Retiring a vendored
patch", or the emergency procedure above. Nothing else is ignored: the
`mongodb` driver follows the latest release, and its server floor (MongoDB 4.4
for driver 3.9) is documented in `docs/mongodb.md`.

The Azure SDK crates (`azure_core`, `azure_identity`,
`azure_security_keyvault_secrets`, and their `typespec*` support crates) have
their own `azure-sdk` group, majors included. `azure_identity`'s credentials
and the Key Vault client both implement or consume `azure_core`'s
`TokenCredential`, so a lone `azure_core` bump does not compile (#6559). Upgrade
them as one set. The 1.x line (`azure_core` 1.1, `azure_identity` 1.0,
`azure_security_keyvault_secrets` 1.0.1) also sends bearer tokens only over
TLS, so Key Vault references must be `https://`; see
[`FEATURES.md`](../FEATURES.md#tls-and-trust) for pointing the backend at an
emulator. The azure crates appear only in the root `Cargo.lock`; the mesh and
fuzz graphs do not compile `secrets-azure`.

The other standalone lockfiles get no version updates: `ebpf/` and `fuzz/` pin
nightly toolchains, `tests/performance/multi_protocol/` must keep `# SYNC:`
versions equal to the root, and the remaining benchmark harnesses are not worth
weekly PRs. Dependabot security updates still cover every committed
`Cargo.lock`, and the dependency-audit lanes audit the root, `ebpf/`, and every
standalone workspace in the `standalone_cargo_manifests.py` inventory.

**The repository Cargo config must not name a `rustc-wrapper`.** Every cargo
process under the repository root reads `.cargo/config.toml`, including
Dependabot's cargo updater. The updater runs `rustc -vV` through the configured
wrapper and has no sccache. From PR #821 (2026-05-16) until the wrapper was
removed, every cargo update failed before opening a PR with
`dependency_file_not_resolvable` (`could not execute process 'sccache …/rustc -vV'`).
That covered version and security updates, for the root and for every nested
lockfile. sccache is selected outside the committed file:

- in CI, `.github/actions/setup-sccache` exports `RUSTC_WRAPPER` and
  `CARGO_BUILD_RUSTC_WRAPPER` as the checksum-verified binary, or clears them;
- in cross-rs and container builds, `Cross.toml` and
  `build_linux_gnu_sysroot.sh` pass both as empty values;
- locally, `scripts/install-build-deps.sh` sets `build.rustc-wrapper` in the
  user-level `$CARGO_HOME/config.toml`.

`verify_cross_build_policy.py` (`EXPECTED_CARGO_BUILD`) allowlists exactly
`[build] incremental = false` and rejects any committed `rustc-wrapper`. A
`.cargo/config[.toml]` below the root is rejected outright, so a nested
lockfile cannot get its own wrapper either.

Dependabot cargo PRs use the `deps` commit prefix and the `dependencies` label,
the same as the `docker` ecosystem. They run the ordinary PR CI, including the
blocking dependency audit when `Cargo.lock` changes.

## Base image pinning

Production container images (`Dockerfile`, `Dockerfile.release`, and
`Dockerfile.test`) must pin every external `FROM` base by registry digest, not
by a mutable tag alone. Write the reference as `repo:tag@sha256:…`, the same form
`IPROUTE2_BASE` already uses: the digest decides which bytes are pulled and the
tag stays in the reference as documentation. A Dockerfile comment is a WHOLE line
beginning with `#` — the parser has no inline-comment form — so a resolution note
goes on its own line above the instruction, never after it:

```dockerfile
# Digest resolved YYYY-MM-DD; the tag is kept for readability, the digest is authoritative.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:…
# Digest resolved YYYY-MM-DD; the tag is kept for readability, the digest is authoritative.
FROM rust:latest@sha256:… AS builder
```

`ARG` defaults that feed a `FROM ${VAR}` line follow the same rule. `scratch`
and local stage aliases (`FROM builder`, `FROM runtime-common`, …) are exempt.
Always resolve and pin the **manifest-list** digest (OCI image index), never a
single-platform manifest, so multi-arch builds keep working.

To refresh a base:

1. Resolve the digest for the existing tag with `docker buildx imagetools inspect
   <image>:<tag>` or the registry v2 API; confirm the media type is an image
   index / manifest list.
2. Update the `@sha256:` pin, the tag in the reference when the tag itself
   changes, and the resolution date on the comment line above it.
3. Land via PR and let hosted CI rebuild the Docker targets.

`tests/unit/gateway_core/container_base_pinning_tests.rs` enforces digest pins
and rejects an unpinned floating Rust channel (`latest`, `stable`, `nightly`,
`beta`) on those Dockerfiles. A pin is a reference ending in
`@sha256:<64 lowercase hex>`. Both pin gates read only the complete shapes
`FROM [--flag ...] <image> [AS <alias>]` and `ARG <NAME>[=<value>]`. Any other
`FROM` or `ARG` instruction in a governed Dockerfile, including one with a note
appended after it, fails as an unsupported instruction instead of being read by
its first token or skipped.

### Container build inputs (enforcement and refresh)

Every registry image reference in `Dockerfile`, `Dockerfile.release`,
`Dockerfile.test`, `Dockerfile.ebpf-tools-layer`, and
`Dockerfile.iproute2-layer` — both `FROM <ref>` and the `ARG <NAME>=<ref>`
defaults those `FROM ${VAR}` lines expand — carries an `@sha256:` digest.
`Dockerfile.iproute2-layer`'s default `BASE_IMAGE` matches the source runtime
pin in `Dockerfile` and `Dockerfile.release`; the
[reviewed input record](docker.md#base-image-pinning) distinguishes its
provenance from published-release qualification. An explicit caller override
remains supported. `scratch` is the only
admissible digest-less base, and a `FROM` naming an earlier `AS` alias is an
internal stage edge, not an input.

Two independent gates enforce it, because each covers a hole the other leaves:

- `check_dockerfile_image_pins()` in `.github/scripts/verify_ci_runtime_cache.py`,
  reached from the required `verify_required_ci.py` run. It extracts every
  reference from all five Dockerfiles, requires a digest on each, and separately
  rejects a bare `:latest`. It needs no Rust build, so it fails fast, and it
  binds an `ARG` image default even when no `FROM` consumes it. Its `--self-test`
  cases cover the pinned, unpinned-`FROM`, unpinned-`ARG`, stage-alias,
  `scratch`, and trailing-text (`FROM` tail, image and version `ARG` tail,
  extra `FROM` token) shapes.
- `tests/unit/gateway_core/container_base_pinning_tests.rs`, which additionally
  rejects an unpinned floating Rust channel on the builder image.

Refresh is automated on two tracks, because Dependabot's `docker` ecosystem
parses `FROM` lines only (`dependabot-core`, `docker/lib/dependabot/docker/file_parser.rb`:
`FROM_LINE`); it discovers every file matching `/dockerfile|containerfile/i`, so
all five are in scope, but it cannot see an `ARG` default — which is every input
of `Dockerfile.ebpf-tools-layer` and both runtime bases of `Dockerfile`.

- `.github/dependabot.yml` `docker` ecosystem: weekly, Monday, `deps` prefix,
  label `dependencies`, at most 5 open PRs. Covers the `FROM` references.
- `.github/workflows/base-image-digest-refresh.yml`: weekly plus
  `workflow_dispatch`. It resolves each pinned reference's tag with
  `docker buildx imagetools inspect <image>:<tag> --format '{{json .Manifest.Digest}}'`,
  rewrites the digest in place, re-runs the pin verifier, and opens or updates a
  single pull request on the fixed branch `deps/base-image-digests`. It is
  digest-preserving by construction: it substitutes a digest and never removes
  one, never changes an image or tag, and it moves the `# Digest resolved
  YYYY-MM-DD` comment above each rewritten pin (walking up over adjacent
  `FROM`/`ARG` pin lines) to the run's UTC date. The ordinary required PR checks
  and `Trusted Cross Build Policy` must qualify the latest reviewed PR head
  before merge. Those are path-selected: for Dockerfile changes they include
  the amd64 production Dockerfile smoke build, but multi-architecture image
  builds, FIPS and the GNU ABI scan are not guaranteed to run on the PR.
  Every tracked Dockerfile and YAML file that pins a drifted reference is
  rewritten together; prose such as `CHANGELOG.md` keeps its history. That
  includes the `gcr.io/distroless/cc-debian13` runtime base: its consumers are
  the governed Dockerfiles and
  `tests/performance/multi_protocol/h3_proof/Dockerfile.live`. The protected
  `main-linux-image` job in `.github/workflows/ci.yml` no longer pins a digest:
  it reads `RUNTIME_BASE` from `Dockerfile` and fails unless that is a
  digest-pinned `gcr.io/distroless/cc-debian13:nonroot` reference, so rotating
  the base never edits a workflow or its `WORKFLOW_CONTRACTS` hash.
  `check_distroless_digest_consistency()` still requires every distroless
  reference to match `Dockerfile`.
  The workflow holds no stored credential; it uses its own `GITHUB_TOKEN`
  (`contents: write`, `pull-requests: write`). That token cannot change workflow
  files, so a drifted reference pinned in a workflow, or in the trusted Cross
  policy, fails the run with an instruction to move the pin into a Dockerfile.
  A pull request opened by `GITHUB_TOKEN` does not start its required CI on its
  own: `pull_request` runs, if GitHub creates them, wait for maintainer
  approval, and the `pull_request_target` trusted policy never starts. A
  maintainer therefore closes and reopens the refresh PR (or merges `main` into
  it) to run every required check, including `Trusted Cross Build Policy`,
  verifies each digest
  against its registry, and merges it. Automatic merging was evaluated and
  rejected: see the rationale in PR #6535. `verify_ci_runtime_cache.py` fails if
  the workflow stops rotating every consumer, may rewrite workflow or trusted
  policy files, or stages only the Dockerfiles.
  The shared resolution/staging inventory also includes `Dockerfile.iproute2-layer`,
  so the NodeWaypoint live image uses the same refreshed Debian tooling base. Its
  default `BASE_IMAGE` matches the same source runtime pin; an
  explicit caller override remains supported. The refresh workflow already
  included this Dockerfile and updates its digest-pinned image references.

An action pin rotation needs no admin merge: the trusted policy admits it
(see "Automated action pin rotation" below), and Dependabot PRs auto-merge once
green. A frozen-policy PR that the trusted gates cannot qualify by design, such
as an edit to `verify_cross_build_policy.py` or another frozen executable
surface, may be admin-merged by a maintainer after verification. Before an
admin merge, verify every proposed dependency version and image digest against
its authoritative registry or upstream source. Require all other applicable
required checks to pass on the reviewed head, and record the affected gate and
its frozen contract in the PR body. An admin merge does not waive failed or
missing unrelated required checks.

Emergency procedure (a base-image CVE that cannot wait for Monday): resolve the
fixed tag's manifest-list digest by hand, bump the `@sha256:` value and the
resolution-date comment in a normal pull request, and let required CI gate it.
**Never drop the digest to pick up a fix by tag** — that trades a one-line review
for an unrecorded, unreproducible base and both gates will reject it anyway.

`rust-toolchain.toml` deliberately tracks `channel = "stable"` rather than an
exact version, and records why in the file itself: lint parity with the
`dtolnay/rust-toolchain@stable` CI installs. That is not an unpinned build input.
The compiler identity of a *release* build is fixed by the digest-pinned
`rust:<tag>@sha256:…` builder image, which fixes the rustc inside it.

The one nightly that reaches a published image, the eBPF ELF build in
`Dockerfile`, is pinned by date through the `EBPF_NIGHTLY_TOOLCHAIN` build
argument (currently the fuzz lane's `nightly-2026-09-30`). It is never the
floating `nightly` channel. Move it forward with a normal pull request, which
the production eBPF image smoke gates. The `Dockerfile` builds, the native
release builds in `release.yml`, and the x86_64 GNU sysroot builder all pass
`cargo build --locked`. They compile exactly the committed `Cargo.lock` and
fail instead of re-resolving a dependency (#6574). The ARM64 Cross release job
is byte-frozen by the trusted Cross policy's `WORKFLOW_CONTRACTS` digest, so it
can gain `--locked` only through a reviewed policy migration. It builds the
same tagged commit and lockfile. If that lockfile is stale, the `--locked`
native builds fail, and `create-release` cannot publish without them.

## CI Actions and Kubernetes tooling

GitHub Actions and the kind / kubectl / Helm binaries used by live Kubernetes
jobs are a separate supply-chain surface from Rust crates. Policy:

1. **Pin every external action** to a full 40-character commit SHA, with an
   accurate version comment (for example
   `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`).
   Mutable tags (`@v7`, `@v7.0.1`), branches (`@main`), and short SHAs are
   forbidden. `docker://` action references require an explicit
   `@sha256:<64-hex>` image digest. Local composite actions under
   `./.github/actions/...` and reusable workflows directly under
   `./.github/workflows/` are allowed without a SHA pin; local Docker actions
   must also digest-pin every non-`scratch` `FROM` image.
2. **Install kind, kubectl, and Helm only through**
   [`.github/actions/setup-kubernetes-tools`](../.github/actions/setup-kubernetes-tools/action.yml).
   That composite action downloads from official versioned release URLs, verifies
   each artifact against repository-pinned SHA-256 digests **and** the matching
   official published checksum file for that exact version, then installs into
   the runner PATH. Pinned downloads may be restored from `actions/cache` only
   when the cache key includes every version, checksum, install-subset flag, and
   runner OS/architecture that affect the artifacts; there is no prefix
   restore-key fallback. Restored bytes are hashed again before install, official
   checksum files are always fetched (never restored), and a restore mismatch
   discards the entry and re-downloads. The cache action is pinned to a full
   commit SHA. The installer never pipes remote content to a shell and fails
   closed on download or verification errors.
3. **Do not** use `azure/setup-helm`, `curl … | bash` installers, or
   `raw.githubusercontent.com/helm/helm/main` (or any other mutable-branch
   install script).
4. **Static enforcement.** The `ci-plan` job runs the trusted base branch's
   `.github/scripts/pr_ci_plan.py --self-test` on every CI run (including
   lightweight documentation PRs). Its checker rejects mutable action refs,
   pipe-to-shell installers, mutable-branch install scripts, and direct
   kind/kubectl/Helm downloads outside the composite action. Repository-local
   actions are allowed, but dynamic or matrix-generated `uses` references are
   rejected because the checker cannot prove that every generated value is a
   full immutable SHA. The head-executed required-CI verifier also runs a pull
   request's proposed planner self-tests without consuming planner outputs, so
   new policy code is exercised before merge while the base branch remains the
   sole authority for job gates.

   This is deliberately static enforcement, not a shell interpreter. It catches
   known direct URLs and folded/continued installer commands, but cannot prove
   the destination of a URL assembled indirectly from shell variables or other
   obfuscation. Reviewers must treat such construction as unverified and require
   a literal, versioned URL plus repository-pinned checksum (or the centralized
   installer) before approving it.

### Refreshing GitHub Actions (Dependabot)

`.github/dependabot.yml` schedules weekly `github-actions` updates for
`.github/workflows` and every local composite action (`/.github/actions/*`).
Compatible (minor and patch) updates arrive grouped in one PR; a semver-major
update gets a PR of its own. Every external action is in scope, including the
ones whose exact invocations the trusted Cross build, publication, and CI
runtime-cache contracts freeze. Those used to be on an `ignore` list and needed
a maintainer override to rotate; the trusted policy now admits their pin
rotations itself (next section).

The one remaining `ignore` entry is `dtolnay/rust-toolchain`. It publishes no
release tags (it keeps one force-updated branch per toolchain), so no new pin
for it can pass the release-tag rule below. Rotating it stays a manual,
maintainer-overridden change.

The rules for any action pin, whoever proposes it:

1. Pin a full 40-character commit SHA. Mutable tags, branches, and short SHAs
   are rejected (`pr_ci_plan.py --self-test`, and every frozen surface, which
   only normalizes full-SHA pins).
2. The trailing version comment is informational. Keep it accurate for new
   uses. It is not part of any frozen surface, so Dependabot may rewrite it
   (`# v7.4.0` → `# v7.5.0`) or leave a major-only comment (`# v7`) alone.
   Some guarded checkout sites still carry a historical `# v6` annotation on
   the v7.0.1 SHA; an ordinary PR may now correct it.

### Automated action pin rotation

`verify_cross_build_policy.py` makes every frozen workflow, local-action, and
template comparison over pin-normalized text. A
`uses: owner/repo[/path]@<40-hex SHA>` reference keeps its action path, but its
commit and trailing comment are replaced by a placeholder
(`normalize_action_pins`). A frozen surface therefore still freezes which
action runs, with which inputs, in which job. It no longer freezes which
upstream release commit of that action runs. Changing the action path, adding a
`uses:` step, or replacing a pin with a mutable ref still changes the
normalized text, and the freeze refuses it as before.

The pinned commit is governed by `action_pin_rotation_errors`, which
`Trusted Cross Build Policy` (the required `pull_request_target` gate, run from
the live trusted base) applies to every pull request. It judges the YAML lines
the pull request itself adds, taken from its three-dot diff against the live
trusted tip (`--proposed-changes`). It checks them against the raw YAML of that
tip: workflows, local actions, and YAML under the automation roots. A branch
cut before a rotation therefore does not read as a downgrade of pins it never
touched, because its merge keeps the trusted tip's newer pin. For each upstream
repository that the trusted tip already pins, every new commit on an added line
must pass two checks:

- **Release tag.** The commit must be the target (peeled, for annotated tags)
  of an upstream release tag (`v?N[.N…]`). The tags are read from
  `https://github.com/<owner>/<repo>` itself with `git ls-remote`. A bare
  commit SHA can also resolve through the fork network, but such a commit is
  not an upstream release, so it fails this check.
- **Forward only.** The commit must descend from every commit the trusted base
  pins for that repository. A commit-only `git fetch --filter=tree:0` of that
  release tag must contain each trusted pin. This refuses downgrades and side
  branches.

Upstream lookups use literal-argv `git` with the remote supplied as
configuration, retry transient failures, and fail closed. An unreachable
upstream refuses the rotation until a re-run succeeds. A repository the
trusted base does not pin yet is not a rotation, so this check skips it. The
freeze and ordinary review still apply to it.

The other gates that used to compare exact SHAs now compare pin shape instead
and leave the commit to the check above:

- `cross-build-policy.yml` and the `CI Plan` early guard accept a
  `cross-build-policy.yml` change only when the live trusted verifier reports
  it pin-only (`--pin-normalized-equal`). `verify_cross_build_policy.py` itself
  stays byte-protected.
- `verify_trusted_local_action.py` (Helm Chart) treats a YAML file that differs
  from the trusted bytes only in pins as identical.
- `verify_ci_runtime_cache.py`, `verify_publication_gate.py`,
  `verify_release_image_attestations.py`, `verify_required_ci.py`,
  `test_ci_policy_parallel.py`, `verify_main_latest_image_workflow.py`, and
  `tests/conformance/live_contract.rs` require a full-commit pin of the named
  action instead of one literal commit. `verify_main_latest_image_workflow.py`
  still requires the publisher to use the same pins as `release.yml`.

`CI Policy` runs the trusted verifier against the proposal alone, with no
trusted baseline to compare against, so it cannot judge rotations. The
admission authority for pins is `Trusted Cross Build Policy`. Both are
required.

### Automated dependency merges

`.github/workflows/dependabot-auto-merge.yml` queues GitHub auto-merge, with a
merge commit, on pull requests that Dependabot opened from a branch of this
repository and last pushed to. Queuing is not merging. GitHub merges only
after every required check passes on the PR head, including `Trusted Cross
Build Policy`'s pin rotation check. The rules:

- semver-major updates are left for a maintainer;
- a push to a Dependabot branch by anyone other than Dependabot withdraws the
  queued merge, so a human-edited bump returns to human review;
- the workflow runs from `main` (`pull_request_target`), never checks out or
  executes PR content, and holds only the built-in `GITHUB_TOKEN`. No stored
  credential exists. Both the queuing and the withdrawing job request
  `contents: write` and `pull-requests: write` at job level, because GitHub
  requires both to enable or to disable auto-merge;
- the repository setting **Allow auto-merge** must stay enabled.

A merge that GitHub performs for a `GITHUB_TOKEN`-queued auto-merge does not
start `push`-triggered workflows. A Dependabot merge commit therefore has no
exact-commit push-to-`main` evidence of its own and is not a release candidate
by itself (see `docs/ci_cd.md` → "Publish-blocking required checks"). The next
maintainer merge on top of it produces that evidence for a commit that
contains the bump. `main-latest-image.yml` likewise advances on that next
push.

Cargo PRs follow the same path (see "Cargo dependency updates"). The grouped
`cargo-minor-patch` PRs auto-merge once every required check passes, including
the blocking dependency audit. A semver-major crate update waits for a
maintainer, and the vendored `[patch.crates-io]` crates are never proposed.

#### Scope of the repository-script (automation) freeze

The same verifier also freezes repository scripts, and it does so bluntly: once
a file is judged Cross-sensitive, its surface is a single
`file:<sha256-of-the-whole-file>`, so **no pull request may change a single byte
of it** — not a comment, not whitespace, not a retry loop.

Sensitivity is inferred from text, so it false-positives. A Gateway API lab
harness that never invokes `cross` or `cargo` earned it purely by containing
fixture strings (`/cross` as an HTTPRoute path prefix, `blackbox-cross` as a
backend name), which permanently blocked a CI flake fix in that file.

The freeze is therefore scoped to automation **reachable from the trusted ARM64
cross-build jobs** (`build-arm64-cross`, `build-release-arm64-cross`), which is
the property the policy actually protects: a pull request must not alter
anything that executes with elevated trust inside that build. Reachability is
seeded from those job blocks plus every local composite action — actions are
included wholesale because a protected job may `uses:` any of them, and seeding
a partial set would under-approximate and silently release a file that really
does run in the trusted build.

The narrowing fails closed. If either revision's protected job cannot be located
or parsed, or the reachability walk reports an error, the scope is treated as
unknown and **every** automation file is compared exactly as before. A file
reachable on *either* revision stays in scope, so a pull request cannot drop the
reachability edge and edit the file in the same commit. Newly reaching an
already-Cross-sensitive script from a protected job is still rejected.

#### Temporary generation transitions (`fips-build.yml`, CI jobs, `setup-rust-ci`)

The verifier can admit an exact whole-file SHA-256 source→destination pair for
a frozen surface, so one reviewed rewrite can pass the Cross surface scan. Each
pair is path- or job-bound, one-way, fail-closed, and decided entirely by the
trusted base; anything else is scanned as an ordinary Cross surface change.
Current admissions:

- `fips-build.yml`: one transition for the issue #4018 memory mitigation on the
  `fips-test-build` job (`FIPS_BUILD_ADMITTED_GENERATION_TRANSITION`). The
  earlier #3889 admission was retired by #3943.
- Cross-sensitive `ci.yml` jobs (`CI_JOB_GENERATION_TRANSITIONS`) and local
  composite actions (`LOCAL_ACTION_GENERATION_TRANSITIONS`): both tables are
  currently empty. Their pairs, including the `setup-rust-ci` #3889→#3911
  chain and the issue #6573 BoringCache retirement pairs, are spent and
  retired.

Details and digests: `docs/ci_cd.md` → "Admitted `fips-build.yml` generation
transition", "Admitted CI job SHA-256 generation transitions", and "Admitted
local-action generation transitions".

### Refreshing kind / kubectl / Helm versions and checksums

Versions and digests live as defaults on the
`setup-kubernetes-tools` composite action inputs. To bump a tool:

1. Choose the new official release tag (kind GitHub release, Kubernetes
   `dl.k8s.io` release, or Helm release on `get.helm.sh`).
2. Fetch the **official** published checksum for that exact version and
   architecture (`linux/amd64`):
   - kind:
     `https://github.com/kubernetes-sigs/kind/releases/download/<tag>/kind-linux-amd64.sha256sum`
   - kubectl:
     `https://dl.k8s.io/release/<tag>/bin/linux/amd64/kubectl.sha256`
   - Helm:
     `https://get.helm.sh/helm-<tag>-linux-amd64.tar.gz.sha256sum`
     (optionally cross-check the detached signature assets on the Helm GitHub
     release before trusting a new digest).
3. Update the matching `*-version` and `*-sha256` defaults in
   `.github/actions/setup-kubernetes-tools/action.yml`.
4. Leave workflow jobs calling `uses: ./.github/actions/setup-kubernetes-tools`
   unchanged unless a job must pin an override input for a temporary skew.
5. Land the change via PR; the trusted CI planner policy and the live suites that
   path-filter on the composite action will exercise the new pins.

`Helm Chart` proves `.github/actions/setup-kubernetes-tools` against the trusted
revision before `uses:`, so a pull request that edits that action is rejected
unless `verify_trusted_local_action.py` already admits that exact
source→destination generation pair. Issue #3904's predecessor transition binds
the current `action.yml`
(`6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08`,
non-executable, sole governed file) moving to the PR #3910 cached-installer
generation
(`41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9`, same path
set and mode). Future installer edits need a new frozen pair, or must match the
trusted tree byte for byte. Do not treat a working-tree digest or a mutable
allowlist as admission. After #3910 is the trusted base, retire the predecessor
constants so the old generation cannot remain an admitted source.

Never refresh a checksum by copying a digest from an unpinned adjacent path
without official release provenance, and never pipe a remote install script to
a shell as a shortcut.

## Kafka native TLS build contract

`rdkafka` enables `cmake-build`, `zstd`, and `ssl-vendored` unconditionally
(issue #5212). `ssl-vendored` selects `openssl-sys/vendored` and `openssl-src`;
the native CMake build enables TLS and SCRAM and links OpenSSL statically.
Regenerate the root, fuzz, and mesh benchmark lockfiles with Cargo when changing
these features and run the blocking advisory/license checks. Do not replace this with system `ssl`:
the distroless runtime has no promised shared `libssl` installation.

Build-matrix review for this feature:

| Producer | Build implications |
| --- | --- |
| GNU x86_64 sysroot | The pinned AlmaLinux producer installs Perl, make, GCC, and CMake already; OpenSSL comes from the locked source crate. |
| ARM64 Cross | `Cross.toml` already supplies Perl/make and the target C compiler/archiver. `rdkafka-sys` registers the OpenSSL dependency with CMake, which consumes the target build's root. No Cross command, image, or passthrough change is needed. |
| Native macOS / Linux | Vendored OpenSSL needs Perl, make, and a C compiler, available in the existing native build environments. `rdkafka-sys` also needs `cmake` and curl development headers (`libcurl4-openssl-dev` / `libcurl-devel` / Homebrew `curl`); `scripts/install-build-deps.sh` installs those on apt, dnf, and Homebrew hosts. |
| Windows MSVC | Vendored OpenSSL uses Perl and nmake; the [hosted Windows image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md) supplies Perl and Visual Studio, and the producers already install NASM. Keep the Windows build in the merge-group/release matrix. |
| Docker | The Rust builder includes the native toolchain; only static OpenSSL code goes into the distroless runtime. |
| musl | The locked `openssl-src` supports x86_64/aarch64 musl target configuration. Ferrum currently publishes GNU Linux binaries, not musl gateway binaries; a musl feature-graph resolve is not a claim of a tested release target. |
| FIPS | Audit the locked graph for every claimed FIPS profile. OpenSSL is outside the approved module; the existing FIPS admission policy rejects the entire `kafka_logging` plugin, including plaintext. Enabling its build capability does not extend the FIPS support claim. |

`unit_plugins_b_tests` requires offline TLS/SCRAM admission through librdkafka.
The Service Integration lane runs verified TLS and SCRAM-SHA-256 against a real
Redpanda broker, including gateway-executable validation and HTTP-to-Kafka
delivery, invalid trust, and invalid credentials. TLS capability absence fails
these tests. The ordinary restrictive-egress and FIPS refusal tests remain in
force.

## FIPS build profile

Ferrum ships two mutually exclusive cryptographic-backend cargo features
(issue #3510). Exactly one must be selected; both or neither is a
`compile_error!` in `src/fips/mod.rs`.

| Feature | Backend | Lockfile |
|---|---|---|
| `crypto-ring` (default) | `ring` + `rustls/ring` | the committed `Cargo.lock` |
| `fips` | `aws-lc-fips-sys` via `aws-lc-rs/fips` and `rustls/fips` | the committed `Cargo.lock` |

Rules:

- **The backend is never selected inline on a dependency.** `rustls`,
  `tokio-rustls`, `reqwest`, `sqlx`, `ldap3`, `quinn`, `rcgen`, `x509-parser`,
  `jsonwebtoken`, `hyper-rustls`, and `instant-acme` all take their crypto arm
  from the feature pair. An inline selection would win on both profiles.
  `rustls`, `tokio-rustls`, `quinn`, and `rcgen` carry
  `default-features = false`, because their default sets select a provider;
  reqwest uses `rustls-no-provider` plus vendored `__rustls-ring` /
  `__rustls-aws-lc-rs` fallback arms for the same reason. Because Cargo unifies
  dependency features, Ring takes precedence if a transitive reqwest consumer
  also enables the upstream AWS-LC default in the ordinary profile; the hosted
  resolved-graph audit rejects Ring entirely from the FIPS profile.
- **Additive is not sufficient.** `sqlx-core`, `quinn-proto`, `tonic`, `ldap3`,
  and `hyper-rustls` each gate their aws-lc arm on the *absence* of their ring
  arm, so "also enable aws-lc" produces a build that looks switched and is not.
  This is the whole reason the features are exclusive rather than layered.
- **The declared contract is not the audited one.**
  `.github/scripts/check_fips_feature_policy.py` reads what cargo actually
  resolved (`cargo tree -e normal,build --prefix none -f '{p}|{f}'`) for
  *both* profiles and
  fails on any surviving ring selection in the FIPS graph. It runs in the
  required `FIPS Feature Policy` job of `.github/workflows/fips-build.yml`.
  The `normal,build` edge filter is load-bearing: test fixtures pin `ring` and
  `rustls/ring` as dev-dependencies so the suite can verify both profiles
  without those edges entering a shipped binary. Package-row feature output is
  used because cargo's feature-edge view can retain dev-only root feature
  unification even when the dev dependency edge itself is hidden.
- **Both profiles are pinned in the committed `Cargo.lock`.** A lockfile entry
  does not compile or link the FIPS-only package into an ordinary artifact;
  feature selection still controls the build. Both resolved-graph audits and
  the hosted FIPS build therefore use `--locked`, and a FIPS release retains
  that exact lockfile as deployment evidence — see `docs/fips.md`.
- **`aws-lc-sys` may still be compiled next to `aws-lc-fips-sys`.** `dimpl` and
  rustls's `aws_lc_rs` arm request it unconditionally. `aws-lc-rs` binds
  `aws-lc-fips-sys` whenever its `fips` feature is on, so the validated module
  is what the API reaches; the policy check asserts the `fips` selection rather
  than the absence of the non-FIPS sys crate.
- **A new TLS-consuming dependency must declare its crypto arm in the feature
  pair** and add its ring/aws-lc selections to `REQUIRED_FEATURE_PAIRS` and
  `FORBIDDEN_RESOLVED_FIPS` in the policy script. A dependency whose backend is
  unselectable belongs in `src/fips/inventory.rs` as `rejected` or
  `outside-boundary`, with a matching admission rule in `src/fips/policy.rs`.
- **A new optional cargo feature must be explicitly claimed or explicitly
  refused.** `CLAIMED_FIPS_PROFILES` (supported and audited) and
  `CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME` (builds, refused before use)
  in the policy script are the inventory; `check_claimed_profiles_declared()`
  fails when a declared optional feature appears in neither. An unlisted feature
  would be an implicit FIPS support claim, which is exactly what this gate
  refuses. CI enumerates the same table through `--list-claimed-profiles`, so
  the audited set and the compiled set cannot drift apart.
- `bench-udp-profile` is dependency-free source-site measurement. The claimed
  FIPS inventory includes `fips,bench-udp-profile` and the combined
  `fips,bench-h1-profile,bench-udp-profile`; neither changes provider selection
  or the enforcing runtime boundary. Hosted enumeration audits these graphs.
- **Each feature list must name a dependency's crypto arm exactly once.** A
  duplicate entry, or a `dep:x` beside an `x/<feature>` edge for the same
  optional dependency (the `dep/feature` edge already activates it), breaks the
  position-for-position correspondence the two lists are read under. The
  manifest check rejects both spellings.

`aws-lc-fips-sys` compiles the FIPS build of AWS-LC from source under a fixed
recipe (CMake + Go + Perl). That recipe is part of what the module's validation
covers, so it must not be replaced with a prebuilt artifact.

## See also

- `docs/fips.md` — the FIPS deployment mode, module boundary, and operator
  verification procedure.
- `docs/vendored-patch-lifecycle.json` — machine-readable owner/upstream/retirement
  inventory enforced by `scripts/check_vendored_patch_lifecycle.py`.
- `deny.toml` — the gate configuration and current exceptions.
- `SECURITY.md` — vulnerability reporting and severity timelines.
- `docs/upstream-sqlx-patches/`, `docs/upstream-reqwest-patches/`,
  `docs/upstream-h3-patches/`, `docs/upstream-h3-quinn-patches/`,
  `docs/upstream-tungstenite-patches/`, `docs/upstream-dimpl-patches/`,
  `docs/upstream-hyper-util-patches/`, `docs/upstream-hyper-patches/` —
  per-patch detail and retirement plans.
- `Cargo.toml` `[patch.crates-io]` — the active vendored patches.
