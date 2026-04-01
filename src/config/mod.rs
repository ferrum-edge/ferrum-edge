//! Configuration subsystem — loading, parsing, validation, and migration.
//!
//! - `types` — Core domain model (Proxy, Consumer, Upstream, PluginConfig, etc.)
//! - `env_config` — Environment variable parsing (90+ vars) + conf file overlay
//! - `conf_file` — `ferrum.conf` parser (env vars take precedence over conf values)
//! - `db_loader` — Database config loader with incremental polling
//! - `file_loader` — YAML/JSON file loader with version migration
//! - `config_backup` — On-disk JSON backup for DB-unreachable startup failover
//! - `config_migration` — Config format version migrations (chain-of-responsibility)
//! - `migrations` — SQL schema migrations for database mode
//! - `pool_config` — Connection pool configuration (global defaults + per-proxy overrides)

pub mod conf_file;
pub mod config_backup;
pub mod config_migration;
pub mod db_loader;
pub mod env_config;
pub mod file_loader;
pub mod migrations;
pub mod pool_config;
pub mod types;

pub use env_config::{EnvConfig, OperatingMode};
pub use pool_config::PoolConfig;
