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
- MongoDB persists through serde BSON unless a queried field needs an index in `MongoStore::run_migrations()`.
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
- Plugin file dependencies such as MaxMind `.mmdb` are validated separately by `validate_plugin_file_dependencies()`: file mode is fatal, DB warns, and CP admin plus DP skip the check because files live on DP nodes. Constructors must tolerate missing plugin dependency files and apply request-time fallback policy.

## Proto And gRPC Config Sync

- `proto/ferrum.proto` compiles through `build.rs` and `tonic_build`.
- `ConfigSync` exposes streaming `Subscribe` and unary `GetFullConfig`.
- CP/DP auth is HS256 JWT in `authorization` metadata.
- Production CP server uses `CpGrpcServer::with_channel_capacity(env_config.cp_broadcast_channel_capacity)`. `new()` default capacity 128 is for tests.
- DP reconnects priority-ordered CP URLs with exponential backoff from 1s to 30s and plus/minus 25% jitter.
- On fallback CP, DP races the stream against primary-retry timer `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.

## Dependency Version Sync

- `tests/performance/multi_protocol/` is a standalone crate with its own `Cargo.toml` and `Cargo.lock`.
- Protocol-level dependencies shared with the root crate must stay version-aligned. Cross-version wire incompatibilities can silently fail.
- When bumping shared deps in the root `Cargo.toml`, update `tests/performance/multi_protocol/Cargo.toml` and run `cd tests/performance/multi_protocol && cargo update -p <crate>`.
- Look for `# SYNC:` comments in both manifests.
