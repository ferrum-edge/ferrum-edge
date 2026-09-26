//! JSON claims → `google.protobuf.Struct` for `ValidateJWTSVID`.
//!
//! The SPIFFE Workload API returns a validated JWT-SVID's claims as a
//! `google.protobuf.Struct`. The conversion follows the proto3 JSON mapping of
//! `Struct` / `Value`, which is also what SPIRE produces:
//!
//! | JSON            | `google.protobuf.Value` kind          |
//! |-----------------|---------------------------------------|
//! | `null`          | `null_value` (`NULL_VALUE`)           |
//! | `true`/`false`  | `bool_value`                          |
//! | number          | `number_value` (IEEE-754 double)      |
//! | string          | `string_value`                        |
//! | object          | `struct_value`                        |
//! | array           | `list_value` (element order preserved)|
//!
//! Numbers are carried as doubles, as in SPIRE: an integer claim beyond 2^53
//! loses precision, which is inherent to `google.protobuf.Value`. A number
//! that has no finite double form is refused rather than approximated.
//!
//! Nesting is bounded by [`MAX_JWT_CLAIMS_NESTING_DEPTH`]: every JSON
//! container becomes up to three nested protobuf messages, and protobuf
//! decoders cap message recursion (prost at 100), so an unbounded claim tree
//! would produce a response a conformant client cannot decode.

use std::collections::BTreeMap;

use prost_types::value::Kind;
use prost_types::{ListValue, NullValue, Struct};
use serde_json::{Map, Number, Value};

use super::{JwtSvidError, MAX_JWT_CLAIMS_NESTING_DEPTH};

/// Convert a JWT claims object to a `google.protobuf.Struct`.
///
/// The claims object itself is nesting depth 1; each nested object or array
/// adds one. A claim tree deeper than [`MAX_JWT_CLAIMS_NESTING_DEPTH`] is
/// refused with [`JwtSvidError::InvalidToken`].
pub fn claims_to_struct(claims: &Map<String, Value>) -> Result<Struct, JwtSvidError> {
    object_to_struct(claims, 1)
}

fn object_to_struct(object: &Map<String, Value>, depth: usize) -> Result<Struct, JwtSvidError> {
    check_depth(depth)?;
    let mut fields = BTreeMap::new();
    for (key, value) in object {
        fields.insert(key.clone(), json_to_value(value, depth)?);
    }
    Ok(Struct { fields })
}

fn array_to_list(array: &[Value], depth: usize) -> Result<ListValue, JwtSvidError> {
    check_depth(depth)?;
    let values = array
        .iter()
        .map(|value| json_to_value(value, depth))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ListValue { values })
}

/// Convert one JSON value held by a container at `depth`.
fn json_to_value(value: &Value, depth: usize) -> Result<prost_types::Value, JwtSvidError> {
    let kind = match value {
        Value::Null => Kind::NullValue(NullValue::NullValue as i32),
        Value::Bool(flag) => Kind::BoolValue(*flag),
        Value::Number(number) => Kind::NumberValue(number_to_double(number)?),
        Value::String(text) => Kind::StringValue(text.clone()),
        Value::Object(object) => Kind::StructValue(object_to_struct(object, depth + 1)?),
        Value::Array(array) => Kind::ListValue(array_to_list(array, depth + 1)?),
    };
    Ok(prost_types::Value { kind: Some(kind) })
}

fn number_to_double(number: &Number) -> Result<f64, JwtSvidError> {
    number
        .as_f64()
        .filter(|double| double.is_finite())
        .ok_or(JwtSvidError::InvalidToken(
            "claims contain a number with no finite double representation",
        ))
}

fn check_depth(depth: usize) -> Result<(), JwtSvidError> {
    if depth > MAX_JWT_CLAIMS_NESTING_DEPTH {
        return Err(JwtSvidError::InvalidToken("claims are nested too deeply"));
    }
    Ok(())
}
