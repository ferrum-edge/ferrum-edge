//! Per-field value transforms (`schema.transforms`).
//!
//! A schema can rename, omit, reorder, and stamp fields; `transforms` adds a
//! small, bounded set of value-minimization operators for the string fields
//! compliance programs most often need shaped rather than dropped:
//!
//! * `truncate` — keep at most `max_bytes` bytes (cut on a UTF-8 boundary).
//! * `ip_prefix` — zero the host part of an IP address (`ipv4_bits` /
//!   `ipv6_bits` network bits are kept; IPv4-mapped IPv6 is canonicalized to
//!   IPv4 first). A value that is not an IP address is emitted as `null`,
//!   never raw.
//! * `hash` — keyed HMAC-SHA-256 pseudonym, lowercase hex. The key is a
//!   `${FERRUM_PLUGIN_SECRET_<NAME>}` reference resolved once at compile time;
//!   literal keys are refused so the secret never lands in stored config.
//!
//! Everything is parsed and keyed once at schema compile time. The emit path
//! performs no allocation, no regex, and no registry access: a transform is a
//! byte-boundary scan, an address parse + mask, or one HMAC over the value.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use serde::ser::SerializeMap;
use serde_json::Value;

use super::fields::{self, SchemaCapabilities};
use super::{SummaryType, unknown_field_error};
use crate::fips::approved::HmacSha256Key;
use crate::plugins::utils::plugin_secret_env::resolve_plugin_secret_env;

/// Native string fields a transform may target. Every entry is a string (or
/// optional string) on each summary entry kind that carries it, and every
/// entry kind exposes it through `SchemaSerializable::native_text`.
pub const TRANSFORMABLE_FIELDS: &[&str] = &[
    "client_ip",
    "consumer_username",
    "request_path",
    "request_user_agent",
    "backend_target",
    "backend_resolved_ip",
    "sni_hostname",
];

/// Fields that carry an IP address and therefore admit `ip_prefix`.
pub const IP_TRANSFORMABLE_FIELDS: &[&str] = &["client_ip", "backend_resolved_ip"];

/// Accepted `type` tokens.
pub const TRANSFORM_TYPES: &[&str] = &["truncate", "ip_prefix", "hash"];

/// Fixed-shape keys of a `truncate` transform.
pub const TRUNCATE_TRANSFORM_KEYS: &[&str] = &["type", "max_bytes"];

/// Fixed-shape keys of an `ip_prefix` transform.
pub const IP_PREFIX_TRANSFORM_KEYS: &[&str] = &["type", "ipv4_bits", "ipv6_bits"];

/// Fixed-shape keys of a `hash` transform.
pub const HASH_TRANSFORM_KEYS: &[&str] = &["type", "secret_ref"];

/// Upper bound on `truncate.max_bytes`.
pub const MAX_TRUNCATE_BYTES: u64 = 65_536;

/// Minimum length of the resolved `hash` secret, matching the gateway-wide
/// HMAC key floor.
pub const MIN_HASH_SECRET_BYTES: usize = 32;

/// Default network bits kept by `ip_prefix` for IPv4 (`/24`).
pub const DEFAULT_IPV4_PREFIX_BITS: u8 = 24;

/// Default network bits kept by `ip_prefix` for IPv6 (`/48`).
pub const DEFAULT_IPV6_PREFIX_BITS: u8 = 48;

/// A compiled value transform for one native field.
///
/// The HMAC key lives behind an `Arc`: the backend key schedule is large (over
/// a kilobyte on the FIPS module), and `Option<ValueTransform>` is embedded in
/// every native `FieldSpec`, so an inline key would inflate every compiled
/// field — transformed or not. The `Arc` is created once at compile time and
/// only borrowed on the emit path.
#[derive(Debug, Clone)]
pub enum ValueTransform {
    Truncate { max_bytes: usize },
    IpPrefix { ipv4_bits: u8, ipv6_bits: u8 },
    Hash(Arc<HashTransformKey>),
}

/// Keyed HMAC-SHA-256 state for the `hash` transform. Never printed.
#[derive(Clone)]
pub struct HashTransformKey(HmacSha256Key);

impl fmt::Debug for HashTransformKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashTransformKey(<redacted>)")
    }
}

impl HashTransformKey {
    fn from_reference(reference: &str, field_label: &str) -> Result<Self, String> {
        let name = reference
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
            .ok_or_else(|| {
                format!(
                    "{field_label} must be a `${{FERRUM_PLUGIN_SECRET_<NAME>}}` reference; \
                     literal secrets are not accepted in a log schema"
                )
            })?;
        let secret = resolve_plugin_secret_env(field_label, name)?;
        if secret.len() < MIN_HASH_SECRET_BYTES {
            return Err(format!(
                "{field_label} resolves to a secret shorter than {MIN_HASH_SECRET_BYTES} bytes"
            ));
        }
        let key = HmacSha256Key::new_from_slice(secret.as_bytes())
            .map_err(|_| format!("{field_label} could not be used as an HMAC-SHA-256 key"))?;
        Ok(Self(key))
    }

    /// Lowercase-hex HMAC-SHA-256 of `value`, written into a stack buffer.
    /// `None` only if hex encoding into the fixed 64-byte buffer failed,
    /// which a 32-byte tag cannot cause.
    fn hex_digest(&self, value: &str) -> Option<[u8; 64]> {
        let mut mac = self.0.begin();
        mac.update(value.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 64];
        hex::encode_to_slice(tag, &mut out).ok()?;
        Some(out)
    }
}

/// How a summary entry exposes a transformable native field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeText<'a> {
    /// The entry carries the field and it has a string value.
    Text(&'a str),
    /// The entry carries the field but it has no value (`None`); native
    /// serialization (null or skip) is used, since there is nothing to leak.
    Absent,
    /// The entry does not expose this field as text. A transformed field is
    /// then dropped from the record rather than emitted untransformed.
    NotTransformable,
}

impl<'a> NativeText<'a> {
    /// `Text` for `Some`, `Absent` for `None`.
    pub fn from_option(value: Option<&'a str>) -> Self {
        match value {
            Some(value) => Self::Text(value),
            None => Self::Absent,
        }
    }
}

impl ValueTransform {
    /// Emit `out_key` with the transformed form of `value`.
    pub(crate) fn serialize_entry<S: SerializeMap>(
        &self,
        out_key: &str,
        value: &str,
        map: &mut S,
    ) -> Result<(), S::Error> {
        match self {
            Self::Truncate { max_bytes } => {
                map.serialize_entry(out_key, truncate_on_char_boundary(value, *max_bytes))
            }
            Self::IpPrefix {
                ipv4_bits,
                ipv6_bits,
            } => match mask_ip(value, *ipv4_bits, *ipv6_bits) {
                Some(masked) => map.serialize_entry(out_key, &DisplayStr(masked)),
                // Not an address: fail closed to `null`, never the raw value.
                None => map.serialize_entry(out_key, &()),
            },
            Self::Hash(key) => {
                let digest = key.hex_digest(value);
                match digest
                    .as_ref()
                    .and_then(|digest| std::str::from_utf8(digest).ok())
                {
                    Some(hex) => map.serialize_entry(out_key, hex),
                    // Unreachable (the buffer is ASCII hex); fail closed.
                    None => map.serialize_entry(out_key, &()),
                }
            }
        }
    }
}

/// Serialize a `Display` value as a JSON string without an intermediate
/// `String` for serializers that write `collect_str` directly.
struct DisplayStr<T>(T);

impl<T: fmt::Display> serde::Serialize for DisplayStr<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// The longest prefix of `value` that is at most `max_bytes` long and ends on
/// a UTF-8 character boundary.
pub fn truncate_on_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or("")
}

/// Parse `value` as an IP address (or `ip:port` socket address) and keep only
/// its network prefix. IPv4-mapped IPv6 addresses are canonicalized to IPv4
/// first so they are masked with `ipv4_bits`.
pub fn mask_ip(value: &str, ipv4_bits: u8, ipv6_bits: u8) -> Option<IpAddr> {
    let ip = value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))?;
    Some(match ip.to_canonical() {
        IpAddr::V4(addr) => {
            let bits = u32::from(ipv4_bits.min(32));
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
        }
        IpAddr::V6(addr) => {
            let bits = u32::from(ipv6_bits.min(128));
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
        }
    })
}

/// Parse and validate the `transforms` map. Keys are native source field
/// names (before `rename`).
pub(super) fn parse_transforms(
    value: Option<&Value>,
    plugin_name: &str,
    summary_type: SummaryType,
    caps: SchemaCapabilities,
    omit: &[String],
) -> Result<HashMap<String, ValueTransform>, String> {
    let Some(value) = value else {
        return Ok(HashMap::new());
    };
    if !caps.family.supports_transforms() {
        return Err(format!(
            "{plugin_name}: schema `transforms` is not supported for this plugin (a {} is not a \
             transaction summary); remove the key",
            caps.family.label()
        ));
    }
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema `transforms` must be an object"))?;
    let mut out = HashMap::with_capacity(obj.len());
    for (field, spec) in obj {
        if fields::lookup(summary_type, caps, field).is_none() {
            return Err(unknown_field_error(
                plugin_name,
                "transforms",
                field,
                summary_type,
                caps,
            ));
        }
        // `field` is a known native field name from here on, so it is safe to
        // echo in diagnostics.
        let Some(field_name) = TRANSFORMABLE_FIELDS
            .iter()
            .copied()
            .find(|name| *name == field.as_str())
        else {
            return Err(format!(
                "{plugin_name}: schema `transforms` cannot transform field `{field}` \
                 (transformable string fields: `{}`)",
                TRANSFORMABLE_FIELDS.join("`, `")
            ));
        };
        if omit.iter().any(|omitted| omitted == field_name) {
            return Err(format!(
                "{plugin_name}: schema field `{field_name}` is both omitted and transformed"
            ));
        }
        let transform = parse_value_transform(spec, plugin_name, field_name)?;
        out.insert(field_name.to_string(), transform);
    }
    Ok(out)
}

fn parse_value_transform(
    spec: &Value,
    plugin_name: &str,
    field: &'static str,
) -> Result<ValueTransform, String> {
    let path = format!("`transforms.{field}`");
    let obj = spec
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema {path} must be an object"))?;
    let kind = match obj.get("type") {
        Some(Value::String(kind)) => kind.as_str(),
        Some(_) => {
            return Err(format!(
                "{plugin_name}: schema {path}.type must be a string"
            ));
        }
        None => {
            return Err(format!(
                "{plugin_name}: schema {path} is missing `type` (one of `{}`)",
                TRANSFORM_TYPES.join("`, `")
            ));
        }
    };
    let allowed_keys: &[&str] = match kind {
        "truncate" => TRUNCATE_TRANSFORM_KEYS,
        "ip_prefix" => IP_PREFIX_TRANSFORM_KEYS,
        "hash" => HASH_TRANSFORM_KEYS,
        other => {
            return Err(format!(
                "{plugin_name}: schema {path}.type must be `truncate`, `ip_prefix`, or `hash` (got {other:?})"
            ));
        }
    };
    for key in obj.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(format!(
                "{plugin_name}: unknown schema key {key:?} at {path} (valid keys for type `{kind}`: `{}`)",
                allowed_keys.join("`, `")
            ));
        }
    }
    match kind {
        "truncate" => {
            let max_bytes = obj
                .get("max_bytes")
                .and_then(Value::as_u64)
                .filter(|max| (1..=MAX_TRUNCATE_BYTES).contains(max))
                .and_then(|max| usize::try_from(max).ok())
                .ok_or_else(|| {
                    format!(
                        "{plugin_name}: schema {path}.max_bytes must be an integer between 1 and \
                         {MAX_TRUNCATE_BYTES}"
                    )
                })?;
            Ok(ValueTransform::Truncate { max_bytes })
        }
        "ip_prefix" => {
            if !IP_TRANSFORMABLE_FIELDS.contains(&field) {
                return Err(format!(
                    "{plugin_name}: schema {path}: `ip_prefix` applies only to IP address fields \
                     (`{}`)",
                    IP_TRANSFORMABLE_FIELDS.join("`, `")
                ));
            }
            let ipv4_bits = parse_prefix_bits(
                obj.get("ipv4_bits"),
                DEFAULT_IPV4_PREFIX_BITS,
                32,
                plugin_name,
                &path,
                "ipv4_bits",
            )?;
            let ipv6_bits = parse_prefix_bits(
                obj.get("ipv6_bits"),
                DEFAULT_IPV6_PREFIX_BITS,
                128,
                plugin_name,
                &path,
                "ipv6_bits",
            )?;
            Ok(ValueTransform::IpPrefix {
                ipv4_bits,
                ipv6_bits,
            })
        }
        // `hash` — the only remaining admitted type after the check above.
        _ => {
            let field_label = format!("{plugin_name}: schema {path}.secret_ref");
            let reference = obj.get("secret_ref").and_then(Value::as_str).ok_or_else(|| {
                format!(
                    "{field_label} is required and must be a `${{FERRUM_PLUGIN_SECRET_<NAME>}}` \
                     reference"
                )
            })?;
            Ok(ValueTransform::Hash(Arc::new(
                HashTransformKey::from_reference(reference, &field_label)?,
            )))
        }
    }
}

fn parse_prefix_bits(
    value: Option<&Value>,
    default: u8,
    max: u8,
    plugin_name: &str,
    path: &str,
    key: &str,
) -> Result<u8, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .as_u64()
        .filter(|bits| *bits <= u64::from(max))
        .and_then(|bits| u8::try_from(bits).ok())
        .ok_or_else(|| {
            format!("{plugin_name}: schema {path}.{key} must be an integer between 0 and {max}")
        })
}
