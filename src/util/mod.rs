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
pub mod deserialization;
pub mod endpointslice;
pub mod http_headers;
pub mod json_dup_keys;
pub mod json_object;
pub mod media_type;
pub mod mesh_enrollment;
pub mod sharding;
pub mod unix_socket;
pub mod unknown_keys;

/// Value of one ASCII hexadecimal digit, or `None` when `byte` is not one.
///
/// Shared by the admin percent-decoders (backup `resources` filters and API
/// spec `$ref` fragments) so both accept exactly the same escapes.
pub(crate) const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
