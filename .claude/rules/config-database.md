---
paths:
  - "src/config/**"
  - "src/config_sources/**"
  - "src/modes/database.rs"
  - "src/modes/file.rs"
  - "src/modes/control_plane.rs"
  - "src/modes/data_plane.rs"
  - "src/modes/migrate.rs"
  - "src/grpc/cp_server.rs"
  - "src/grpc/dp_client.rs"
  - "src/grpc/auth.rs"
  - "src/service_discovery/**"
  - "ferrum.conf"
  - "proto/ferrum.proto"
  - "docs/configuration.md"
  - "docs/mongodb.md"
  - "docs/database_tls.md"
  - "docs/migrations.md"
  - "docs/cp_dp_mode.md"
  - "docs/cp_namespace_tenancy.md"
  - "docs/upgrade_guide.md"
  - "tests/unit/config/**"
  - "tests/unit/gateway_core/*{cp_server,dp_client,config_delta,service_discovery}*"
  - "tests/integration/*{db,cp,config,incremental,offline}*"
  - "tests/functional/*{database,mongodb,db,cp_dp,file,migrate,namespace}*"
---

# Config And Database Rules

## Domain Model

- `GatewayConfig` contains `Proxy`, `Consumer`, `Upstream`, and `PluginConfig`. Each has `namespace`, defaulting to `ferrum`.
- `ApiSpec` is intentionally not in `GatewayConfig`; it is admin-only metadata.
- `Proxy`, `Upstream`, and `PluginConfig` carry optional `api_spec_id` ownership tags. Do not strip or repurpose them.
- `FERRUM_NAMESPACE` controls what a gateway loads. DB queries filter by namespace. File mode filters after deserialize. Admin API uses `X-Ferrum-Namespace`.
- Uniqueness is per namespace for listen path, proxy name, consumer identity, upstream name, and listen port. Same listen port across namespaces is allowed at config level; OS bind catches real conflicts.
- Consumer ids are per-namespace (SQL PK `(namespace, id)`; Mongo consumer `_id` is `"{namespace}:{id}"`). Consumer id, username, and custom_id share ONE identity keyspace per namespace, enforced in persistence by the `consumer_identity_index` table/collection written transactionally with every consumer write (cross-field collisions are 409s; self-collisions within one consumer are allowed). Full config loads quarantine pre-existing colliding consumers fail-closed via `GatewayConfig::quarantine_colliding_consumer_identities()` — do not revert to warn-and-overwrite.
- ID-only `DatabaseBackend` reads/deletes/updates are namespace-predicated at the query level (`get_/delete_/update_*` carry the namespace in the WHERE clause / filter document); update methods return `Ok(false)` on zero matched rows and must not emit a config-change record for phantom updates.
- Hostname normalization is ASCII-lowercase at admission through `normalize_fields()` for `Proxy.hosts`, `Proxy.backend_host`, and `UpstreamTarget.host`.
- Apply normalization at admin API, loaders, DP gRPC, and restore entrypoints. Do not re-lowercase in DNS, pool, health, or LB keys.

## Multi-Namespace CP/DP

- `FERRUM_CP_NAMESPACES` controls CP scope. Empty or unset is back-compatible `Single(FERRUM_NAMESPACE)`, `*` is cluster-wide, CSV is an explicit set.
- `src/grpc/cp_server.rs::NamespaceBroadcasts` partitions broadcasts by namespace so DPs receive only their namespace slice.
- DP still runs `dp_client::filter_config_to_namespace` as defense in depth.
- `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true` requires DP `ConfigSync.Subscribe` JWTs to carry an `ns` claim, string or array, authorizing the subscribe namespace.
- xDS ADS, MeshConfigSync, and the K8s controller broadcast hook still use the back-compatible single-namespace sender. Do not claim multi-namespace support on those surfaces until implemented.

## Config Admission And Schemas

- New config fields go in `src/config/types.rs` with `#[serde(default)]` when optional.
- Env-driven fields also update `src/config/env_config.rs`, `docs/configuration.md`, and `ferrum.conf`.
- SQL storage changes are folded into `src/config/migrations/v001_initial_schema.rs` during build-out, with parsing in `db_loader.rs`.
- MongoDB persists through serde BSON unless a queried field needs an index in
  `src/config/mongo_index_plan.rs` (consumed by `MongoStore::run_migrations()`,
  migrate dry-run, and migrate status).
- Add unit tests under `tests/unit/config/` and update `openapi.yaml` when admin-exposed.
- Required new fields need a migration/versioning plan even in build-out; do not silently make old config deserialize differently unless intended.
- Check parent structs for `#[serde(deny_unknown_fields)]` before adding fields.

## Database Backends

- Supported stores are PostgreSQL, MySQL, SQLite through sqlx, and MongoDB.
- SQLite must keep `PRAGMA journal_mode=WAL`, `busy_timeout=5000`, and `foreign_keys=ON` through `after_connect`.
- `DatabaseBackend` in `src/config/db_backend.rs` is the shared trait. `DatabaseStore` and `MongoStore` both implement it. Admin and modes use `Arc<dyn DatabaseBackend>`.
- SQL wraps multi-step CRUD in `sqlx::Transaction`.
- MongoDB single-doc writes are atomic. Multi-doc atomicity requires `FERRUM_MONGO_REPLICA_SET`; otherwise flows must be idempotent with poll-cycle cleanup.
- `FERRUM_DB_FAILOVER_URLS` uses the same `FERRUM_DB_TYPE`.
- Runtime config polling is authoritative and primary-consistent: startup full loads, incremental change-log reads, relationship reads, cursor advancement, and accepted association state must not use SQL read replicas or MongoDB secondary read preferences.
- `FERRUM_DB_READ_REPLICA_URL` is SQL-only and may offload eligible admin-only reads; writes and runtime polling always use primary. Replica query failure must mark the replica unavailable and retry the admin read on primary.
- MongoDB replica-set failover comes from listing members in `FERRUM_DB_URL`; Ferrum's config store forces primary reads and ignores URL read preferences.
- MongoDB pool sizing comes from driver URL options such as `maxPoolSize` and `minPoolSize`; `FERRUM_DB_POOL_*` is ignored.

## Incremental Polling And Broadcast

- `FERRUM_DB_POLL_INTERVAL` defaults to 30s.
- Startup performs a full load and seeds the accepted durable change sequence. Subsequent SQL and MongoDB polls read `config_changes` after that sequence, collapse each resource to its final operation in the batch, and point-load changed IDs only.
- Poll results are validated before apply; on reject, the accepted sequence remains unchanged.
- Poll failure or an expired retained sequence auto-falls back to full reload.
- CP broadcasts deltas through a tokio broadcast channel sized by `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`.
- Lagging DPs automatically receive a full snapshot.
- If config source is unavailable, keep serving the last cached config.

## Database TLS

- Canonical envs are `FERRUM_DB_TLS_MODE`, `FERRUM_DB_TLS_CA_CERT_PATH`, `FERRUM_DB_TLS_CLIENT_CERT_PATH`, and `FERRUM_DB_TLS_CLIENT_KEY_PATH`.
- SQL modes support `disable`, `allow`, `prefer`, `require`, `verify-ca`, and `verify-full` subject to backend limits.
- MySQL rejects `allow`.
- MongoDB supports only `disable`, `require`, and `verify-full`.
- SQLite accepts only `disable` and rejects cert paths and other TLS modes.
- Keep `docs/database_tls.md`, `docs/configuration.md`, and env parsing synchronized.

## File Mode And Validation

- File mode is read-only admin plus proxy. It loads YAML/JSON and reloads on SIGHUP on Unix.
- Config validators must behave by mode: file mode should fail startup for invalid local config, DB mode should warn for bad existing data when appropriate, DP should reject bad updates and keep cached config.
- Backend TLS cert paths are validated by `validate_all_fields_with_ip_policy()`: file mode is fatal, DB/CP admin warns, and DP rejects the update while keeping old config. Frontend TLS cert failure is always fatal; no silent fallback.
- Plugin file dependencies such as MaxMind `.mmdb` are validated separately by `validate_plugin_file_dependencies()`: file mode is fatal; DB warns for absent/unreadable files; CP admin validates structure but skips node-local files because it does not construct proxy plugins; DP full snapshots and affected incremental rebuilds validate/refresh the DP node's local files off the runtime worker. Constructors apply the configured request-time fallback for absent/unreadable files on DB/DP nodes, while readable invalid files reject the candidate and preserve the last published generation. On a DP forced node-local refresh the load session substitutes the live generation's last-known-good snapshot for a temporarily unavailable path (keyed on `db_path`), so a transient outage cannot downgrade an enforcing geo gate; the instance is still rebuilt from the incoming config so policy changes are never stale.

## Proto And gRPC Config Sync

- `proto/ferrum.proto` compiles through `build.rs` and `tonic_build`.
- `ConfigSync` exposes streaming `Subscribe` and unary `GetFullConfig`.
- `FERRUM_REAL_IP_HEADER` is an enforced CP/DP cluster ownership setting. DPs
  advertise an explicitly present effective value (empty means unset) on both
  ConfigSync requests; CP rejects missing or mismatched values before config
  distribution so CP admission and serving-DP correlation ownership cannot diverge.
- CP/DP auth is HS256 JWT in `authorization` metadata. The channel carries that JWT plus the full gateway config, so the transport is secure-by-default: `EnvConfig::validate_cp_dp_grpc_transport_security()` refuses a non-loopback plaintext CP bind and a non-loopback `http://` DP URL unless `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true`. Loopback (`127.0.0.1`/`::1`/`localhost`) plaintext is always allowed; permitted plaintext still logs a high-severity warning on CP and DP. mTLS (`FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH`) is the only DP auth factor beyond the bearer JWT — warn when CP TLS is configured without it.
- `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` is rejected at startup: tonic's `ClientTlsConfig` exposes no public verifier-skip hook, so the flag never disabled verification (CRL is likewise not applied to the tonic-managed CP/DP client). Pin the CP CA via `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` for self-signed test certs. Do not re-add a no-verify path by hand-rolling a tonic connector.
- Production CP server uses `CpGrpcServer::with_channel_capacity(env_config.cp_broadcast_channel_capacity)`. `new()` default capacity 128 is for tests.
- DP reconnects priority-ordered CP URLs with exponential backoff from 1s to 30s and plus/minus 25% jitter.
- On fallback CP, DP races the stream against primary-retry timer `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.

## Dependency Version Sync

- `tests/performance/multi_protocol/` is a standalone crate with its own `Cargo.toml` and `Cargo.lock`.
- Protocol-level dependencies shared with the root crate must stay version-aligned. Cross-version wire incompatibilities can silently fail.
- When bumping shared deps in the root `Cargo.toml`, update `tests/performance/multi_protocol/Cargo.toml` and run `cd tests/performance/multi_protocol && cargo update -p <crate>`.
- Look for `# SYNC:` comments in both manifests.
