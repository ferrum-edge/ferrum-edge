//! Small cross-cutting utilities. Modules here have no direct dependency on
//! the proxy/admin/config layers — they expose pure helpers that those
//! layers compose from.

pub mod accept_backoff;
pub mod atomic_log_rate_limiter;
pub mod backoff;
pub mod body_limit;
pub mod cidr;
pub mod client_identity;
pub mod conn_limit;
pub mod http_headers;
pub mod json_dup_keys;
pub mod media_type;
pub mod sharding;
pub mod unix_socket;
pub mod unknown_keys;
