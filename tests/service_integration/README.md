# Service Integration Tests

Functional integration tests for Ferrum's **external-middleware integrations** —
the code paths that can only be validated against the **real third-party
software** (a service registry, a directory server, a Kafka broker, …). Each
backend runs as a local container via [`testcontainers`](https://docs.rs/testcontainers) (Docker)
using free, open-source images. No managed or cloud service is ever involved,
and every fixture seeds its own fully-controlled data so the assertions are
deterministic.

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
| **MySQL** (`src/config/migrations/mod.rs`, `src/config/db_loader.rs`) | custom-plugin DDL plus tracking under MySQL's implicit-commit rules; config/route lock acquire; identity uniqueness collation; upstream-name admission | SQLite covered atomic migration behavior; MySQL SQL was previously inspected only as strings | live MySQL 8.4: failure after committed V1 DDL, exact index reconstruction on retry, V2 index/tracker-gap recovery, SQLx Any text bindings used by `example_audit_plugin`, cross-namespace config/route writes without deadlock, NFC vs NFD consumer identity under `utf8mb4_bin`, concurrent duplicate Upstream name with exactly one winner |

## Running locally

```bash
# All backends
cargo test --test service_integration

# One backend (the test-name filter selects the module)
cargo test --test service_integration consul
cargo test --test service_integration ldap
cargo test --test service_integration kafka
cargo test --test service_integration mysql
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
rather than silently passing.

## Container images (free / OSS)

| Backend | Image | Notes |
| --- | --- | --- |
| Consul | `hashicorp/consul:1.19` | `agent -dev`; readiness polled via `/v1/status/leader` |
| OpenLDAP | `osixia/openldap:1.5.0` | base `dc=example,dc=org`; test tree seeded via `ldapadd` exec (readiness handled by retry) |
| Redpanda | `redpandadata/redpanda:v24.2.4` | Kafka API on external listener `127.0.0.1:<mapped-port>`; auto-topic-create disabled; readiness via librdkafka metadata; topics created with `rpk` |
| MySQL | `mysql:8.4` | isolated `ferrum` database; readiness polled with the same SQLx Any driver used by migrations/runtime persistence |

Readiness is confirmed by **active polling** (Consul leader endpoint; LDAP
`ldapadd` retry; Redpanda metadata fetch; a MySQL connection), not by matching a
startup log line —
so the helpers do not depend on which stream a given image logs to.

## CI

`.github/workflows/ci.yml` job `test-service-integration` runs on
`ubuntu-latest` (Docker available). Consul, LDAP, Kafka, and MySQL run in one nextest
`--no-fail-fast` invocation, which preserves per-test reporting and continues
after one backend fails without allocating a second runner. It is wired into
the `test` aggregation gate, so it blocks merge on failure.

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
   `common/containers.rs`. Prefer **active readiness polling** over a log-line
   wait. Seed fixtures via the container's API or an `exec` (see the Consul
   register helper, the LDAP `ldapadd` seeder, and the Redpanda `rpk` helper).
2. Add a `<svc>.rs` module and register it in `mod.rs`.
3. Drive the **real** code: construct the plugin via
   `ferrum_edge::plugins::create_plugin(name, &config)` and call the relevant
   `Plugin` hook (`authenticate` / `log` / …), or call the integration type
   directly (as `ConsulDiscoverer` is here).
4. Add the module filter to the `test-service-integration` nextest invocation;
   the existing job row in the `test` gate summary covers the expanded suite.

### Candidates / roadmap

- **OIDC relying party / OAuth2 introspection** — login/session/introspection
  flows. Use `ory/hydra` or `keycloak`.

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
