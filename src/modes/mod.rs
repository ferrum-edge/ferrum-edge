//! Operating mode entry points for the Ferrum Edge gateway.
//!
//! The gateway binary runs in exactly one mode, selected by `FERRUM_MODE`:
//!
//! | Mode       | Proxy | Admin API   | Config Source                    |
//! |------------|-------|-------------|----------------------------------|
//! | `database` | Yes   | Read/Write  | PostgreSQL/MySQL/SQLite polling   |
//! | `file`     | Yes   | Read-only   | YAML/JSON file, SIGHUP reload    |
//! | `cp`       | No    | Read/Write  | DB polling + gRPC broadcast to DPs |
//! | `dp`       | Yes   | Read-only   | gRPC stream from CP              |
//! | `migrate`  | No    | No          | Runs DB migrations then exits    |
//!
//! All modes share the same `ProxyState` and atomic config swap mechanism.
//! Config changes (from any source) are validated, then swapped atomically
//! via `ArcSwap` — in-flight requests see old or new config, never partial.

pub mod control_plane;
pub mod data_plane;
pub mod database;
pub mod file;
pub mod migrate;
