//! Small cross-cutting utilities. Modules here have no direct dependency on
//! the proxy/admin/config layers — they expose pure helpers that those
//! layers compose from.

pub mod accept_backoff;
pub mod backoff;
pub mod body_limit;
pub mod http_headers;
pub mod sharding;
