# Vendored reqwest patch: physical-connection admission hook

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/reqwest-0.13.4-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## What this patches

Adds `ClientBuilder::connection_admission(Arc<dyn ConnectionAdmission>)`.

The hook is consulted inside `ConnectorService::call` — the single place
reqwest dials a **new** physical connection — and only there:

- a checkout that reuses an already-open pooled connection never reaches the
  connector;
- an HTTP/2 stream multiplexed onto an existing connection never reaches it
  either.

`ConnectionAdmission::admit(&Uri)` returns a `ConnectionAdmissionToken`, which
the connector moves into the connection object it hands to hyper (a small
delegating `AdmittedConn` wrapper around the connection's IO). The token is
therefore dropped exactly when that physical connection is dropped: handshake
failure, normal close, idle eviction, pool drain, cancellation, and shutdown.
Returning `Err` refuses the dial; the error is surfaced to the caller as that
request's connect error with its source chain intact.

Surface area: three public items (`ConnectionAdmission`,
`ConnectionAdmissionToken`, `ClientBuilder::connection_admission`), one new
private wrapper type, one new field on `Config`/`ConnectorService`, and one
extra parameter on the crate-internal `ConnectorBuilder::build`. Default
behavior is unchanged when the hook is absent (`None`).

## Why ferrum-edge needs it

Istio `DestinationRule.trafficPolicy.connectionPool.tcp.maxConnections` is a
**physical open-connection** ceiling (issue #3290). Ferrum enforces it with one
gateway-wide `BackendConnectionLimiter` (`src/backend_conn_limit.rs`) that every
transport whose socket lifecycle Ferrum owns admits against — raw TCP,
WebSocket, direct H2, gRPC, native H3, HBONE, mesh-mTLS. Those transports can
reserve a slot at connection construction and hand it to the connection's own
driver task, so retirement is exact.

reqwest is the exception: it owns and hides its socket pool, and no public API
can express "this new socket is admitted; release when it closes".

- `ClientBuilder::connector_layer` receives an opaque `Unnameable` request (the
  destination `Uri` is not readable, so a layer cannot even find the
  destination's cap) and returns a sealed `Conn` whose IO cannot be wrapped, so
  a layer cannot own a drop guard for the connection's lifetime.
- `ClientBuilder::dns_resolver` runs per new connection but is bypassed for IP
  literals and carries no connection-lifetime signal.
- Counting *requests* instead is provably wrong in two directions: reqwest keeps
  a socket open and idle after the request that opened it completes (so the
  count reads zero while sockets are still open, and the next dispatch admits
  past the ceiling), and on an ALPN-negotiated h2 dispatch it would count
  streams rather than connections.

The hook also lets a *single* admission object be installed on **every** pooled
`reqwest::Client`, so divergent reqwest pool keys for one destination (TLS
material, the `rcfg` client-behavior suffix, the forced-H1 ALPN discriminator,
`upstream_subset`) share one ceiling instead of each getting their own.

## Upstream tracking

- Status: **deliberate fork, unfiled.** The shape Ferrum needs (an admission
  hook whose token is bound to connection lifetime) is more opinionated than
  anything upstream currently exposes, and upstream has deliberately sealed
  `Conn` to keep the connector's connection type private.
- Retirement trigger: reqwest exposes a connection-lifecycle/admission hook, or
  un-seals the connector connection type so a `connector_layer` can own a drop
  guard for the connection's lifetime.

## Vendored crate

- Path: `vendor/reqwest-0.13.4-ferrum-patched/`
- Base release: reqwest **v0.13.4**
- Wired in via `[patch.crates-io]` in the workspace `Cargo.toml`
- Files touched: `src/connect.rs`, `src/async_impl/client.rs`, `src/lib.rs`

## Behavioral regression coverage

`tests/integration/mesh_destination_rule_connection_pool_audit_tests.rs` — every
assertion is on sockets the **backend** accepted, so a request-counting
implementation cannot pass them:

- `reqwest_client_without_admission_hook_is_socket_unbounded` — the control: the
  ceiling comes from the hook, not from client configuration or pool keys.
- `sequential_requests_never_exceed_the_cap_while_a_socket_sits_idle` — the slot
  is still held while reqwest keeps the socket idle between requests.
- `cap_exhaustion_refuses_the_second_physical_dial` — over-cap refusal happens
  before a second socket is opened, and the slot retires when the connection is
  dropped.
- `distinct_reqwest_pool_keys_share_one_destination_ceiling` — two clients, one
  ceiling.
- `h2_streams_multiplex_without_consuming_extra_slots` — multiplexed streams take
  no additional slot.
- `a_removed_cap_stops_applying_once_its_dispatches_drain` and
  `target_port_remap_counts_on_the_policy_port` — Ferrum-side lane lifecycle and
  policy-port identity.
- `conflicting_reqwest_lanes_resolve_to_the_strictest_in_either_order`,
  `a_newer_config_generation_replaces_a_retired_reqwest_lane_wholesale`,
  `a_retired_generation_cannot_weaken_a_live_reqwest_lane`, and
  `a_reqwest_lane_lives_exactly_as_long_as_its_leases` — the lane a connect
  attempt is admitted against is deterministic under concurrent, conflicting
  policy and across a config reload, and the registry drains rather than
  retaining retired policy.
