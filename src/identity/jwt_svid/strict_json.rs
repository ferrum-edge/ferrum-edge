//! Duplicate-key-rejecting JSON parsing for JOSE segments.
//!
//! `serde_json`'s default object handling silently keeps the *last* value for
//! a repeated key. For a security token that is an ambiguity an attacker can
//! steer: `{"aud":"attacker","aud":"victim"}` may be read one way by the
//! validator and another way by a downstream consumer that re-parses the same
//! bytes. Both the JOSE header and the claims set are therefore parsed
//! through [`StrictValue`], which fails closed on any repeated object key at
//! any nesting depth.
//!
//! `serde_json`'s own recursion limit bounds nesting depth, and callers bound
//! the segment size before handing bytes here, so a hostile document cannot
//! exhaust the stack or the heap.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::JwtSvidError;

/// A [`serde_json::Value`] that rejects duplicate object keys at any depth.
pub(crate) struct StrictValue(pub(crate) Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with no repeated object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element::<StrictValue>()? {
            items.push(item);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let StrictValue(value) = map.next_value::<StrictValue>()?;
            if object.insert(key, value).is_some() {
                return Err(de::Error::custom("repeated JSON object key"));
            }
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

/// Parse `bytes` as a JSON object, failing closed on malformed input, on a
/// non-object top level, and on any repeated key.
///
/// The error is a fixed string: the caller-supplied bytes are hostile input
/// and must never be reflected back.
pub(crate) fn parse_strict_json_object(bytes: &[u8]) -> Result<Map<String, Value>, JwtSvidError> {
    let StrictValue(value) = serde_json::from_slice::<StrictValue>(bytes).map_err(|_| {
        JwtSvidError::InvalidToken("segment is not well-formed JSON or repeats an object key")
    })?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(JwtSvidError::InvalidToken("segment is not a JSON object")),
    }
}
