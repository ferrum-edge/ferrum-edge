# Scripted-Backend Test Framework — Implemented / Residual Record

**Status (reconciled against current `main`)**: historical plan converted to an
implemented/residual ledger. Do **not** treat the original "programmable
backends are missing" framing as current work.

**Goal (achieved)**: reusable, deterministic harness for gateway behavior across
protocol + failure-mode combinations — refused connections, mid-stream resets,
ALPN downgrades, QUIC silence, timeouts, trickles, premature closes, and bad
frames — on demand, in-process or via the binary harness.

Closing tracker for the Phase-8 gap-fill continuation: [#2032](https://github.com/ferrum-edge/ferrum-edge/issues/2032) (closed).

## What exists today

| Surface | Location |
|---|---|
| Ports / certs / harness | `tests/scaffolding/{ports,certs,harness,matrix,mod}.rs` |
| Scripted backends | `tests/scaffolding/backends/` (`tcp`, `tls`, `http1`, `http2`, `http3`, `grpc`, `udp`, `dtls`, plus QUIC helpers) |
| Clients | `tests/scaffolding/clients/` |
| Network simulation | `tests/scaffolding/network/` (`latency`, `bandwidth`, `truncate`, `proxy`) |
| Scenario catalog | `tests/scenarios/catalog.rs` |
| Functional coverage | `tests/functional/scripted_backend_*.rs`, plus capability/retry/overload/plugin-network suites that consume the scaffolding |

Current patterns: file-backed child stdout/stderr capture with null stdin;
leased ports from the shared registry (`tests/scaffolding/port_registry.rs`);
3-attempt spawn retries on fresh ports; pre-bound listeners; fresh temp dirs per
retry. See [Functional Testing Guide](../functional_testing.md#subprocess-harness-process-identity).

## Design principles (still normative)

1. **Scripted, not chaotic.** Data-driven sequences; no `rand` in failure paths.
2. **Composable.** Transport independent of script.
3. **Observable.** Backends record received bytes/frames/headers/SNI.
4. **Fast.** In-process by default; binary mode when CLI/SIGHUP/kernel features matter.
5. **One harness for integration and functional.**
6. **Time control.** `tokio::time::pause` where safe; real timers with tolerances otherwise.

## Phase status

| Phase | Intent | Status |
|---|---|---|
| 1 — TCP / TLS / HTTP/1.1 | Scripted backends + certs/ports/harness | **Implemented** (`tests/scaffolding/backends/{tcp,tls,http1}.rs`, `scripted_backend_tests.rs`) |
| 2 — HTTP/2 (+ gRPC framing) | Frame-level H2 control | **Implemented** (`backends/http2.rs`, `backends/grpc.rs`, `scripted_backend_h2_tests.rs`) |
| 3 — HTTP/3 / QUIC | QUIC refuse/close + H3 scripts | **Implemented** (`backends/http3.rs`, QUIC helpers, `scripted_backend_h3_tests.rs`) |
| 4 — UDP / DTLS | Per-datagram scripting | **Implemented** (`backends/udp.rs`, `backends/dtls.rs`, `scripted_backend_udp_tests.rs`) |
| 5 — Network simulation | Latency / bandwidth / truncate wrappers | **Implemented** (`tests/scaffolding/network/`, `scripted_backend_network_sim_tests.rs`) |
| 6 — Cross-protocol matrix macro | `gateway_matrix!` | **Implemented** (`tests/scaffolding/matrix.rs`, `scripted_backend_matrix_tests.rs`) |
| 7 — Scenario catalog | Shared failure scripts | **Implemented** (`tests/scenarios/catalog.rs`) |
| 8 — Capability / retry / overload / plugin-network gap-fill | Close review-flagged scenarios | **Implemented** (continuation closed in #2032; suites under `functional_capability_registry_test`, `functional_retry_test`, `functional_overload_test`, `functional_plugins_network_test`, plus scripted streaming-latency coverage) |

`HarnessMode::InProcess` is live: `tests/scaffolding/harness.rs` calls
`ferrum_edge::modes::file::serve(...)` with pre-bound listeners. Prefer
`mode_in_process()` unless the test needs log capture, CLI parsing, or
kernel-level features (splice/kTLS/io_uring).

## Explicit non-goals (preserved)

- Chaos / property-testing frameworks with randomization in the failure path.
- Docker/k8s deployment-shape tests inside this scaffolding (separate CI pipelines).
- Real-network integration against third-party SaaS endpoints.

## Residual / follow-on (not a reopen of the framework)

- Keep extending the **catalog** with new shared scripts as new failure modes appear — ongoing hygiene, not a missing Phase-1–8 deliverable.
- Mesh HBONE / DNS **performance baseline publication** is separate harness work under [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) (`tests/performance/mesh-hbone-e2e`, `tests/performance/mesh-dns-e2e`), not scripted-backend scaffolding.

## Historical note

Earlier drafts of this document opened with "programmable backends are missing"
and listed directory trees as future deliverables. Those trees and the Phase-6/7
macros now exist in-tree; treat this file as the archive of intent plus the
status table above, not as an active build plan.
