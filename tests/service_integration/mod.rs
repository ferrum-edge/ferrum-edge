//! Functional integration tests for Ferrum's external-middleware integrations
//! that can only be validated against the REAL third-party software — a
//! service registry, a directory server, a Kafka-compatible broker, a SQL
//! database, and an OIDC/OAuth2 identity provider — imitated locally with free
//! OSS containers (`testcontainers`/Docker). No managed or cloud service is
//! ever used.
//!
//! These exercise the REAL integration code paths against locally-run servers:
//!
//!   - **consul** — HashiCorp Consul dev agent. Drives
//!     [`ferrum_edge::service_discovery::consul::ConsulDiscoverer::discover`]
//!     against live Consul health-API output (Service-vs-Node address
//!     fallback, weights, tags, the `passing=true` filter, blocking-query
//!     cursor commit after snapshot admission). Only `build_url` was previously covered.
//!   - **ldap** — OpenLDAP seeded via a controlled LDIF. Drives the real
//!     `ldap_auth` plugin through `create_plugin` → `authenticate`, covering
//!     direct bind, search-then-bind, and group-membership — the `ldap3`
//!     bind/search paths that the existing functional test (unreachable
//!     server) never reaches.
//!   - **kafka** — Redpanda (Kafka API). Drives `kafka_logging` produce,
//!     delivery-callback accounting, consume-back verification, and bounded
//!     finalize against a real broker.
//!   - **mysql** — MySQL 8.4. Exercises custom-plugin migration recovery
//!     across implicit-commit DDL boundaries, the example audit schema's
//!     SQLx Any text bindings, a cross-namespace `config_change_locks`
//!     concurrency regression against ER_LOCK_DEADLOCK 1213, and byte-exact
//!     NFC/NFD consumer identity uniqueness under `utf8mb4_0900_bin` (#2994).
//!   - **oidc** — Ory Hydra. Drives `oidc_relying_party` through live discovery,
//!     authorization-code + PKCE, JWKS/UserInfo/end-session, encrypted sessions,
//!     claim headers, idle/absolute expiry, refresh, and logout (#3333).
//!   - **oauth2_introspection** — same Hydra fixture. Drives
//!     `oauth2_introspection` against opaque tokens: active/inactive, scope /
//!     role / issuer / audience, client auth methods, discovery facade, cache,
//!     and failure policy (#3333).
//!
//! Container-backed tests self-skip (with a printed notice) when Docker is
//! unavailable, so the suite is safe to run locally without Docker. In CI the
//! `test-service-integration` job runs all backends with `--no-fail-fast` on a
//! Docker-enabled runner where a
//! container that fails to start is a HARD failure (see
//! `common::containers::fail_in_ci_else_skip`).
//!
//! Run per backend (see also the consolidated CI job):
//!   cargo test --test service_integration consul
//!   cargo test --test service_integration ldap
//!   cargo test --test service_integration kafka
//!   cargo test --test service_integration mysql
//!   cargo test --test service_integration oidc
//!   cargo test --test service_integration oauth2_introspection

mod common;

mod consul;
mod kafka;
mod ldap;
mod mysql;
mod oauth2_introspection;
mod oidc;
