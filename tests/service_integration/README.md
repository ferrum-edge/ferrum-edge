# Service Integration Tests

Functional integration tests for Ferrum's **external-middleware integrations** —
the code paths that can only be validated against the **real third-party
software** (a service registry, a directory server, a Kafka broker, an identity
provider, …). Each backend runs as a local container via
[`testcontainers`](https://docs.rs/testcontainers) (Docker) using free,
open-source images. No managed or cloud service is ever involved, and every
fixture seeds its own fully-controlled data so the assertions are deterministic.

This is its own `[[test]]` crate (declared in the root `Cargo.toml`, entry point
`mod.rs`), mirroring `tests/secrets_functional/`. It is **not** part of the
default unit/integration/functional suites; CI runs it as the dedicated
`test-service-integration` job.

## Why this suite exists

These integrations were previously only *config-validated* or only tested on
their *failure* path, leaving the real client logic uncovered:

| Backend | Code under test | Previous coverage | This suite adds |
| --- | --- | --- | --- |
| **Consul** (`src/service_discovery/consul.rs`) | `ConsulDiscoverer::discover()` — health-API JSON parsing | inline unit tests covered only `build_url()` | live Consul: Service-vs-Node address fallback, port/weight/tag extraction, `passing=true` health filter, per-tag filtering, unknown-service empty result |
| **LDAP** (`src/plugins/ldap_auth.rs`) | `ldap3` bind / search-then-bind / group membership, via `create_plugin` → `authenticate` | functional test only pointed the plugin at an *unreachable* server (500 / 401 paths) | live OpenLDAP: valid/invalid direct bind, search-then-bind, group-membership allow (Continue) vs deny (403) |
| **Kafka** (`src/plugins/kafka_logging.rs`) | librdkafka produce, delivery callbacks, consume-back, bounded finalize | deterministic unit tests for admission/CRL/budgets/finalize ownership; ignored optional broker harness | live Redpanda: successful ack + key/record consume, unknown-topic reject after admission, broker oversized reject, paused-broker delivery timeout, producer-queue saturation, successful and stalled finalize, multi-instance generation isolation, Drop/reload disposal with pending records |
| **MySQL** (`src/config/migrations/mod.rs`, `src/config/db_loader.rs`) | custom-plugin DDL plus tracking under MySQL's implicit-commit rules; cross-namespace `config_change_locks` exclusive-lock acquisition; V001 identity-column collation | SQLite covered atomic migration behavior; MySQL SQL was previously inspected only as strings | live MySQL 8.4: failure after committed V1 DDL, exact index reconstruction on retry, V2 index/tracker-gap recovery, SQLx Any text bindings used by `example_audit_plugin`, a bounded cross-namespace writer race proving zero ER_LOCK_DEADLOCK 1213, per-namespace sequence-lock isolation (issue #4130), and NFC/NFD consumer username inserts under `utf8mb4_0900_bin` (#2994) |
| **OIDC** (`src/plugins/oidc_relying_party.rs`) | discovery, authorization-code + PKCE, JWKS/UserInfo/end-session, encrypted sessions, claim headers, idle/absolute expiry, refresh, logout | unit tests with wiremock IdP | live Ory Hydra: full browser challenge → callback session, state/correlation/nonce/issuer/audience/signature negatives (subject proven positively; `azp` multi-aud remains unit-covered), reserved-header protection, idle/absolute expiry with margin sleeps, refresh proven via token-facade `refresh_token` grant counter, RP logout (#3333) |
| **OAuth2 introspection** (`src/plugins/oauth2_introspection.rs`) | RFC 7662 outbound introspect, discovery, cache, scope/role/audience, client auth, failure policy | unit tests with wiremock | live Hydra opaque tokens: active/inactive, scope/role/issuer/audience, `client_secret_basic` + `client_secret_post` request shaping observed on a non-secret facade, discovery facade (same-origin rewrite of admin introspect), cache hit/expiry proven by upstream-call counters without token-key leaks, timeout/malformed/oversized/wiremock-auth/unavailable → 503 (Hydra admin introspect does not enforce client auth) (#3333) |
| **ClickHouse** (`src/plugins/api_chargeback_sink.rs`) | JSONEachRow INSERT of `ChargeEvent` against `migrations/clickhouse/0001_charges.sql` | static DDL/serializer contract in `tests/integration/api_chargeback_sink_tests.rs`; ignored env-URL round trip | live `clickhouse/clickhouse-server:24.8`: apply baseline DDL, plugin HTTP/gRPC/stream/Unicode inserts, max-integer serializer insert, compatible DDL re-apply + durable artifact replay, identity-projection insert (issue #4441) |

## Running locally

```bash
# All backends
cargo test --test service_integration

# One backend (the test-name filter selects the module)
cargo test --test service_integration consul
cargo test --test service_integration ldap
cargo test --test service_integration kafka
cargo test --test service_integration mysql
cargo test --test service_integration oidc
cargo test --test service_integration oauth2_introspection
cargo test --test service_integration clickhouse
```

The MySQL custom-plugin recovery test requires the pedagogical example at
build time (`FERRUM_CUSTOM_PLUGINS=example_plugin,example_audit_plugin`, which
CI sets via `.github/actions/setup-rust-ci`). Without that opt-in the MySQL
test prints `SKIP … example_audit_plugin not compiled in` before starting
Docker.

**With Docker:** the containers start and the assertions run.
**Without Docker:** each test prints `SKIP <test>: <service> unavailable …` and
returns green — the suite stays runnable on a developer machine with no Docker.

The skip/fail decision lives in `common::containers::fail_in_ci_else_skip`: in CI
(`CI` env var set, which GitHub Actions sets automatically) a container that
fails to start is a **hard failure**, so a broken image/setup fails the job
rather than silently passing. Host-port bind collisions are retried with a
fresh port (see below); they are not converted into skips.

## Host port allocation (#3999)

Every testcontainer in this suite that publishes a host port goes through
`common/host_ports.rs`:

| Container | Image ports mapped on the host |
| --- | --- |
| Consul | `8500` |
| OpenLDAP | `389` |
| Redpanda | `9093` (advertised Kafka listener) |
| MySQL | `3306` |
| Hydra | `4444` (public) and `4445` (admin); login/consent URLs also consume unique host ports so they cannot collide with the mapped listeners |
| ClickHouse | `8123` (HTTP interface used by `api_chargeback_sink`) |

Docker auto-assignment and `127.0.0.1:0` both land inside
`/proc/sys/net/ipv4/ip_local_port_range`. The probe socket is then released, an
unrelated ephemeral connection or sibling container can claim the number, and
Docker fails with `port is already allocated` — the same bind-drop-rebind
family as issue #3993.

The allocator therefore:

1. Probes candidate ports **outside** the kernel ephemeral source range (Linux:
   `/proc/sys/net/ipv4/ip_local_port_range`; elsewhere the IANA dynamic range).
2. Retries container start **only** when the error is a host-port bind
   collision (`port is already allocated`, `address already in use`,
   `EADDRINUSE`), with a fresh port each time and a bound attempt budget.
3. Returns every other start failure immediately so an image-pull or wait
   condition failure still hard-fails in CI.

Do not pin a single fixed host port (that trades a race for a hard collision
under parallel jobs) and do not blanket-retry unrelated container errors.

## Container images (free / OSS)

| Backend | Image | Notes |
| --- | --- | --- |
| Consul | `hashicorp/consul:1.19` | `agent -dev`; readiness polled via `/v1/status/leader` |
| OpenLDAP | `osixia/openldap:1.5.0` | base `dc=example,dc=org`; test tree seeded via `ldapadd` exec (readiness handled by retry) |
| Redpanda | `redpandadata/redpanda:v24.2.4` | Kafka API on external listener `127.0.0.1:<mapped-port>`; auto-topic-create disabled; readiness via librdkafka metadata; topics created with `rpk` |
| MySQL | `mysql:8.4` | isolated `ferrum` database; readiness polled with the same SQLx Any driver used by migrations/runtime persistence |
| Hydra | `oryd/hydra:v2.2.0` | `serve all --dev` with `DSN=memory`; host ports allocated outside the ephemeral range for public (4444) and admin (4445); opaque access tokens; clients seeded via admin API; login/consent accepted through admin challenge APIs (no external IdP). Readiness polled via OIDC discovery + admin API |
| ClickHouse | `clickhouse/clickhouse-server:24.8` | HTTP on mapped `8123`; readiness polled via `/ping`; baseline `migrations/clickhouse/0001_charges.sql` applied as one HTTP POST per statement |

Readiness is confirmed by **active polling** (Consul leader endpoint; LDAP
`ldapadd` retry; Redpanda metadata fetch; a MySQL connection; Hydra discovery;
ClickHouse `/ping`),
not by matching a startup log line —
so the helpers do not depend on which stream a given image logs to.

## CI

`.github/workflows/ci.yml` job `test-service-integration` runs on
`ubuntu-latest` (Docker available). Consul, LDAP, Kafka, MySQL, OIDC,
OAuth2 introspection, and ClickHouse run in one nextest `--no-fail-fast`
invocation, which
preserves per-test reporting and continues after one backend fails without
allocating a second runner. It is wired into the `test` aggregation gate, so it
blocks merge on failure. Hydra (or any provider) startup failure is a hard
failure in CI.

## Hydra / OIDC / introspection runbook (#3333)

Both `oidc` and `oauth2_introspection` modules share the Hydra fixture in
`common/hydra.rs` but remain independently filterable.

### Reproduce OIDC relying-party coverage

```bash
cargo test --test service_integration oidc
```

What it drives against live Hydra:

1. Plugin constructed via `create_plugin("oidc_relying_party", …)` with
   `discovery_url` pointed at Hydra's public well-known document.
2. Browser challenge (`authenticate` → 302) after discovery becomes ready;
   authorization URL must carry PKCE `code_challenge` / `S256`.
3. Test process follows Hydra redirects, accepts login/consent via the admin
   API (subject `alice`, email/roles seeded into the token session), and feeds
   `code` + `state` + correlation cookie into `on_request_received`.
4. Encrypted session cookie authenticates subsequent requests; claim headers
   fan out; reserved `Authorization` mapping is rejected at config time;
   client-supplied claim destinations are overwritten only with verified values.
5. Negatives: wrong state, missing correlation cookie, nonce mismatch (Hydra
   signs a different nonce than Ferrum sealed into the pending-flow cookie), wrong issuer via explicit live
   endpoints (signed-token `iss` rejection), wrong audience, and live token
   endpoint + unrelated JWKS (signature failure). Subject is proven positively
   via successful login; multi-audience `azp` enforcement remains unit-covered.
6. Short idle/absolute TTLs observe re-challenge after margin sleeps that do
   not slide the cookie first; a token facade shortens `expires_in` under a
   valid `refresh_skew_secs <= ttl/2` config and asserts a real
   `refresh_token` grant succeeded at Hydra and produced a newly sealed session
   cookie; logout clears the session and targets Hydra's exact discovered
   end-session origin/path.

### Reproduce OAuth2 introspection coverage

```bash
cargo test --test service_integration oauth2_introspection
```

What it drives:

1. Opaque access tokens from Hydra `client_credentials` and authorization-code
   grants (asserted not to decode as a compact JWT; opaque serialization may
   still contain `.` delimiters).
2. Direct admin introspection URL (`/admin/oauth2/introspect`) with
   `client_secret_basic` and `client_secret_post` configs (Hydra admin does
   not enforce client auth; request shaping is observed on the facade).
3. Discovery path through a same-origin facade that rewrites Hydra's discovery
   document so `introspection_endpoint` shares scheme/host/port with discovery
   (Ferrum's discovery origin check) while still proxying to live admin
   introspect. The facade counts upstream calls and Basic vs form-secret
   presence without recording secret values.
4. Active/inactive outcomes, required scopes/roles, issuer/audience denial,
   `ext.*` claim-header mapping from consent session extras, positive-cache
   hit (no second upstream call) then post-TTL upstream refresh, without
   logging raw tokens or client secrets.
5. Failure policy: unavailable endpoint, wiremock timeout / malformed /
   oversized / 401 client-auth responses → HTTP 503 per plugin contract; a
   final live Hydra call proves no cross-test contamination. Wrong secrets
   against Hydra admin introspect are not treated as an auth-failure proof.

### Safety

Never log or assert on raw client secrets, access/refresh tokens, authorization
codes, session cookie values, private keys, or full provider error bodies.
Fixture diagnostics are status/code oriented and length-bounded.

## Kafka acceptance split

Hosted Redpanda covers the broker-dependent acceptance contract from #2548 /
#2551 as fully as practical:

- successful acknowledgement with delivered count, zero failure/rejection, key +
  consume-back of a known path marker
- unknown-topic rejection after local admission
- broker-side oversized-message rejection (`max.message.bytes` on the topic)
- delivery timeout via `acks=all` against a docker-paused broker (Redpanda
  v24.2 does not materialize Kafka's topic `min.insync.replicas`; produce the
  producer while live, then pause so ack cannot complete)
- immediate `queue.buffering.max.messages=1` saturation while a prior record is
  stuck on that paused broker
- successful bounded finalize after delivery
- stalled/failed bounded finalize accounting against a paused broker
- generation isolation across instances and Drop-time old-generation disposal
  while a record is pending on a paused broker (then unpause for the next
  healthy generation)

Deterministic unit coverage remains the home for cases that do not need a
broker (and must stay OpenSSL/librdkafka-host independent):

- unknown root keys / producer_config security aliases
- gateway CRL conflict, match, file-URI normalize, non-file fail-closed,
  `ssl_no_verify` skip
- Ferrum channel / byte-budget / entry-oversize admission
- reserve-before-serialize
- exact-once finalize without pending broker I/O
- docs feature-contract (no undeclared `kafka` Cargo feature)

The optional ignored harness in
`tests/integration/kafka_logging_broker_tests.rs` remains for developers with
an external broker via `FERRUM_TEST_KAFKA_BOOTSTRAP`; hosted CI does **not**
rely on it.

## Adding another external service

Follow `common/containers.rs` (and `tests/secrets_functional/` for the
cloud-SDK variant):

1. Add a `start_<svc>_container()` (+ a small fixture struct) to
   `common/containers.rs` (or a dedicated `common/<svc>.rs` module as with
   Hydra). Pin every published host port with `allocate_host_port()` +
   `with_mapped_port`, and wrap Docker `.start()` in
   `retry_on_host_port_collision` so only bind collisions retry. Prefer
   **active readiness polling** over a log-line wait. Seed
   fixtures via the container's API or an `exec` (see the Consul register
   helper, the LDAP `ldapadd` seeder, the Redpanda `rpk` helper, and the Hydra
   admin client seeder).
2. Add a `<svc>.rs` module and register it in `mod.rs`.
3. Drive the **real** code: construct the plugin via
   `ferrum_edge::plugins::create_plugin(name, &config)` and call the relevant
   `Plugin` hook (`authenticate` / `log` / …), or call the integration type
   directly (as `ConsulDiscoverer` is here).
4. Add the module filter to the `test-service-integration` nextest invocation;
   the existing job row in the `test` gate summary covers the expanded suite.

### Better served by in-process fakes (no container)

The observability sinks send over simple wire protocols, so an in-process fake
is more robust (and runs without Docker) than a full container — these belong in
`tests/integration/`, not here:

- **StatsD** (`statsd_logging`, UDP) — bind a `UdpSocket`, point the plugin at
  it, call `log()`, assert the received datagram's metric line format.
- **Loki / HTTP-style sinks** (`loki_logging`, `http_logging`) — receive the
  push with `wiremock` (already a dev-dependency) and assert the payload.
- **TCP sinks** (`tcp_logging`) — accept on a `TcpListener` and assert the
  framed bytes.
