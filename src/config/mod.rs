//! Configuration subsystem — loading, parsing, validation, and migration.
//!
//! - `types` — Core domain model (Proxy, Consumer, Upstream, PluginConfig, etc.)
//! - `env_config` — Environment variable parsing (90+ vars) + conf file overlay
//! - `conf_file` — `ferrum.conf` parser (env vars take precedence over conf values)
//! - `batch_atomicity` — Graph-level all-or-nothing vocabulary for `POST /batch`
//! - `db_loader` — Database config loader with incremental polling
//! - `file_loader` — YAML/JSON file loader with version migration
//! - `config_backup` — On-disk JSON backup for DB-unreachable startup failover
//! - `config_change_watch` — Coalesced wake-up signal for backend-native
//!   config-change watchers (MongoDB replica-set change streams)
//! - `config_migration` — Config format version migrations (chain-of-responsibility)
//! - `migrations` — SQL schema migrations for database mode
//! - `pool_config` — Connection pool configuration (global defaults + per-proxy overrides)

// The fault-injection seam is driven by external tests through the lib target's
// `_test_support` shim; the bin target recompiles this module without those
// callers, so its installers would otherwise read as dead code there.
#[allow(dead_code)]
pub mod batch_atomicity;
pub mod conf_file;
pub mod config_backup;
// Wake-up plumbing for backend-native config-change watchers. Some accessors
// are consumed only through external tests, which the bin target cannot see.
#[allow(dead_code)]
pub mod config_change_watch;
pub mod config_migration;
pub mod db_backend;
pub mod db_loader;
pub mod env_config;
pub mod file_loader;
pub(crate) mod incremental_apply;
pub mod migrations;
pub mod mongo_index_plan;
pub mod mongo_store;
pub mod pool_config;
#[allow(dead_code)] // Public DOC-03 inventory is consumed by external tests, not the binary crate.
pub mod public_env_inventory;
pub mod types;
pub(crate) mod validation_pipeline;

#[allow(unused_imports)] // AutoBool is used by unit tests but not directly by the binary
pub use env_config::AutoBool;
#[allow(unused_imports)] // DbTlsMode is used by unit tests and public config consumers
pub use env_config::{
    AdminHttpExposure, BackendAllowIps, BackendEgressPolicy, DbTlsMode, EffectiveSqlBackend,
    EnvConfig, OperatingMode, check_backend_ip_allowed,
};
#[allow(unused_imports)] // Used by unit tests
pub use env_config::{is_always_blocked_range, is_private_ip};
pub use pool_config::PoolConfig;
