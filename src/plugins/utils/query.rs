//! Ordered, duplicate-aware query-string helpers.
//!
//! Backend-visible query identity must not round-trip through the single-value
//! [`std::collections::HashMap`] used for plugin `query_params`. This module
//! parses a raw query into an ordered pair list, applies
//! `request_transformer` mutations with defined duplicate-key semantics, and
//! serializes an exact outbound query string while preserving unmodified
//! encodings byte-for-byte.

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::collections::{HashMap, HashSet};

/// Characters that must be percent-encoded in query names/values we author.
/// Unreserved characters (RFC 3986) stay literal; space becomes `%20` (never
/// `+`) so authored pairs do not introduce form-urlencoded plus ambiguity.
const QUERY_COMPONENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Decode one query name or value for WAF HPP comparison.
///
/// `application/x-www-form-urlencoded` treats literal `+` as space, but `%2B`
/// is an unambiguous encoded plus. Normalize only raw `+` before percent-
/// decoding so `%2B` stays literal plus.
fn decode_form_urlencoded_component_for_hpp(raw: &str) -> String {
    let normalized;
    let component = if raw.as_bytes().contains(&b'+') {
        normalized = raw.replace('+', " ");
        normalized.as_str()
    } else {
        raw
    };
    percent_decode_str(component)
        .decode_utf8_lossy()
        .into_owned()
}

/// Whether one decoded query name appears with conflicting decoded values.
///
/// The WAF parameter-pollution rule deliberately keeps this narrower
/// predicate: it reports the concrete first/last-value differential, while an
/// identical repeated value does not trigger that rule. Security-sensitive
/// routing and delegated policy must use [`CanonicalQuery`] instead, because
/// they also fail closed on identical duplicates, encoded aliases, literal
/// plus, and invalid encodings.
pub fn has_conflicting_duplicate_query_key(raw_query: &str) -> bool {
    let mut seen: HashMap<String, String> = HashMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_form_urlencoded_component_for_hpp(raw_key);
        let value = decode_form_urlencoded_component_for_hpp(raw_value);
        match seen.get(&key) {
            Some(previous) if previous != &value => return true,
            Some(_) => {}
            None => {
                seen.insert(key, value);
            }
        }
    }
    false
}

/// A reason the client's query cannot be reduced to one unambiguous decoded
/// name→value view that Ferrum policy and the backend are guaranteed to read
/// identically.
///
/// Every variant is a fixed-cardinality classification. Reason strings never
/// echo query bytes, which are attacker-controlled and may carry credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryAmbiguity {
    /// A literal `+` in a name or value. RFC 3986 reads `+` as a plus sign,
    /// while the `application/x-www-form-urlencoded` decoders most application
    /// frameworks apply read it as a space. Ferrum forwards the byte
    /// unchanged, so a policy decision made on either reading can differ from
    /// what the backend executes (advisory `GHSA-gr4p-3qw3-87r5`).
    LiteralPlus,
    /// A `%` that does not begin a complete `%HH` triplet. Decoders disagree
    /// on whether to pass it through, drop it, or reject the request.
    MalformedPercentEncoding,
    /// A percent-decoded name that is not valid UTF-8.
    NonUtf8Name,
    /// A percent-decoded value that is not valid UTF-8.
    NonUtf8Value,
    /// The same decoded name occurs more than once — through repetition, a
    /// percent-encoded alias (`a` vs `%61`), or a bare/valued pair of the same
    /// name. Backends variously take the first value, the last value, all
    /// values, or reject, so no single value is the one the backend executes
    /// (advisory `GHSA-j2j6-f9c7-hh85`).
    DuplicateName,
}

impl QueryAmbiguity {
    /// Stable, fixed-cardinality reason token for logs, metadata, and
    /// policy-visible input. Safe to emit: it never contains request bytes.
    pub fn reason(self) -> &'static str {
        match self {
            Self::LiteralPlus => "literal_plus",
            Self::MalformedPercentEncoding => "malformed_percent_encoding",
            Self::NonUtf8Name => "non_utf8_name",
            Self::NonUtf8Value => "non_utf8_value",
            Self::DuplicateName => "duplicate_name",
        }
    }
}

/// One canonical query parameter, decoded exactly once from the bytes Ferrum
/// forwards to the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalQueryParam {
    /// Percent-decoded name. Lossy only when the pair was flagged
    /// [`QueryAmbiguity::NonUtf8Name`].
    pub name: String,
    /// Percent-decoded value. Empty for a bare parameter. Lossy only when the
    /// pair was flagged [`QueryAmbiguity::NonUtf8Value`].
    pub value: String,
    /// `true` for `?flag` (no `=`), `false` for `?flag=` (explicit empty
    /// value). Both decode to an empty `value`; this bit is what keeps the two
    /// distinguishable in a lossless representation.
    pub bare: bool,
}

/// Ordered, occurrence-complete, explicitly ambiguity-classified view of a
/// request query.
///
/// Valid UTF-8 components are decoded exactly once. A component that decodes to
/// non-UTF-8 is represented with replacement characters and explicitly marked
/// `non_utf8_name` / `non_utf8_value`; consumers must not mistake that decoded
/// value for an exact byte representation.
///
/// # The forwarding-parity contract
///
/// [`canonical_query_for_policy`] builds this from
/// [`crate::proxy::effective_backend_query_string`] — the backend-bound query
/// representation in the request context at the consumer's hook. That includes
/// authentication-owned strips and any query transform that has already run,
/// rather than a separate parse of the lossy shared map. A deliberately later
/// transformer may still replace the query in its own ordered phase; consumers
/// that run after it observe the replacement.
///
/// # Ambiguity is recorded, never silently resolved
///
/// Parsing is infallible so a consumer can always obtain the lossless pair
/// list. Whatever could make Ferrum and the backend disagree is recorded in
/// [`Self::ambiguities`]; fail-closed consumers check
/// [`Self::first_ambiguity`] and reject before acting, and consumers that
/// delegate the decision hand the pairs and the ambiguity list to the policy
/// engine. Nothing here picks a first/last/all-value convention on the
/// operator's behalf.
///
/// # Bounds and ordering
///
/// Wire order is preserved. Work is linear in the query length, and the pair
/// count is already bounded upstream by `FERRUM_MAX_QUERY_PARAMS` on every
/// frontend protocol (`count_query_params`), so no additional cap is imposed
/// here. Do not cache this on the request context: the effective backend query
/// changes when `request_transformer` publishes an outbound query or an
/// authentication plugin marks a credential for stripping, and a stale
/// canonical view would reintroduce exactly the policy/forwarding differential
/// this type exists to close.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalQuery {
    params: Vec<CanonicalQueryParam>,
    ambiguities: Vec<QueryAmbiguity>,
}

impl CanonicalQuery {
    /// Decode an effective backend-visible query string into the canonical
    /// view. Never panics and never fails; see the type docs.
    pub fn parse(effective_query: &str) -> Self {
        if effective_query.is_empty() {
            return Self::default();
        }
        // Ordered, deduplicated: at most one entry per variant, in the order
        // first encountered, so `first_ambiguity` is deterministic.
        fn record(into: &mut Vec<QueryAmbiguity>, ambiguity: QueryAmbiguity) {
            if !into.contains(&ambiguity) {
                into.push(ambiguity);
            }
        }

        let mut params: Vec<CanonicalQueryParam> = Vec::new();
        let mut ambiguities: Vec<QueryAmbiguity> = Vec::new();

        for pair in effective_query.split('&') {
            // Empty `&` segments are separators, not parameters — the same
            // rule `count_query_params` applies, so H1/H2/H3 agree.
            if pair.is_empty() {
                continue;
            }
            let (raw_name, raw_value, bare) = match pair.split_once('=') {
                Some((name, value)) => (name, value, false),
                None => (pair, "", true),
            };
            if raw_name.contains('+') || raw_value.contains('+') {
                record(&mut ambiguities, QueryAmbiguity::LiteralPlus);
            }
            if !has_valid_percent_triplets(raw_name) || !has_valid_percent_triplets(raw_value) {
                record(&mut ambiguities, QueryAmbiguity::MalformedPercentEncoding);
            }
            let name = match percent_decode_str(raw_name).decode_utf8() {
                Ok(name) => name.into_owned(),
                Err(_) => {
                    record(&mut ambiguities, QueryAmbiguity::NonUtf8Name);
                    percent_decode_str(raw_name)
                        .decode_utf8_lossy()
                        .into_owned()
                }
            };
            let value = match percent_decode_str(raw_value).decode_utf8() {
                Ok(value) => value.into_owned(),
                Err(_) => {
                    record(&mut ambiguities, QueryAmbiguity::NonUtf8Value);
                    percent_decode_str(raw_value)
                        .decode_utf8_lossy()
                        .into_owned()
                }
            };
            params.push(CanonicalQueryParam { name, value, bare });
        }

        // Duplicate detection runs on decoded names, so `a=1&%61=2` is one
        // duplicate rather than two distinct parameters.
        let has_duplicate = {
            let mut seen: HashSet<&str> = HashSet::with_capacity(params.len());
            params.iter().any(|param| !seen.insert(param.name.as_str()))
        };
        if has_duplicate {
            record(&mut ambiguities, QueryAmbiguity::DuplicateName);
        }

        Self {
            params,
            ambiguities,
        }
    }

    /// Ordered, deduplicated ambiguity classifications for this query. Empty
    /// means the decoded view is the one the backend must also see.
    pub fn ambiguities(&self) -> &[QueryAmbiguity] {
        &self.ambiguities
    }

    /// First recorded ambiguity, in the order encountered. Fail-closed
    /// consumers reject on `Some(_)`.
    pub fn first_ambiguity(&self) -> Option<QueryAmbiguity> {
        self.ambiguities.first().copied()
    }

    /// Whether this query can be reduced to one decoded view both Ferrum and
    /// the backend are guaranteed to read the same way.
    pub fn is_unambiguous(&self) -> bool {
        self.ambiguities.is_empty()
    }

    /// Ordered pairs, exactly as they appear in the forwarded query.
    pub fn params(&self) -> &[CanonicalQueryParam] {
        &self.params
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Look up a decoded parameter value.
    ///
    /// Returns the first occurrence. On an unambiguous query there is at most
    /// one occurrence, so "first" is not a convention choice — callers that
    /// could act on a duplicated name must reject via [`Self::first_ambiguity`]
    /// before consulting this. The scan is linear over a query-count-bounded
    /// slice, which beats allocating a map for the handful of predicates a
    /// route rule declares.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|param| param.name == name)
            .map(|param| param.value.as_str())
    }
}

/// Build the canonical policy view from the request's current backend-bound
/// query representation.
///
/// This is the single entry point every security-sensitive query consumer must
/// use — OPA authorization input, `mesh_route_dispatch` predicates, and
/// `serverless_function` delegated-policy payloads. Reading
/// `ctx.query_params` instead reintroduces the collapse and the literal-plus
/// differential both advisories describe, and reading `raw_query_string()`
/// instead ignores transformer mutations and credential strips that change
/// what the backend actually receives.
pub fn canonical_query_for_policy(ctx: &crate::plugins::RequestContext) -> CanonicalQuery {
    CanonicalQuery::parse(&crate::proxy::effective_backend_query_string(ctx))
}

/// Whether every `%` in `value` begins a complete `%HH` triplet.
pub fn has_valid_percent_triplets(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len()
                || !bytes[idx + 1].is_ascii_hexdigit()
                || !bytes[idx + 2].is_ascii_hexdigit()
            {
                return false;
            }
            idx += 3;
        } else {
            idx += 1;
        }
    }
    true
}

/// One query pair, retaining wire encoding for names/values that were not
/// rewritten by a transform rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPair {
    /// Encoded name as it should appear on the wire.
    pub raw_name: String,
    /// Percent-decoded name used for rule matching (lossy UTF-8).
    pub decoded_name: String,
    /// `None` preserves a key-without-equals flag (`?flag`). `Some("")` is an
    /// explicit empty value (`?flag=`).
    pub raw_value: Option<String>,
    /// Percent-decoded value used for map materialization (lossy UTF-8).
    pub decoded_value: String,
}

impl QueryPair {
    fn from_raw_segment(pair: &str) -> Self {
        match pair.split_once('=') {
            Some((raw_name, raw_value)) => Self {
                decoded_name: percent_decode_str(raw_name)
                    .decode_utf8_lossy()
                    .into_owned(),
                decoded_value: percent_decode_str(raw_value)
                    .decode_utf8_lossy()
                    .into_owned(),
                raw_name: raw_name.to_string(),
                raw_value: Some(raw_value.to_string()),
            },
            None => Self {
                decoded_name: percent_decode_str(pair).decode_utf8_lossy().into_owned(),
                decoded_value: String::new(),
                raw_name: pair.to_string(),
                raw_value: None,
            },
        }
    }

    fn authored(name: &str, value: &str) -> Self {
        Self {
            raw_name: encode_query_component(name),
            decoded_name: name.to_string(),
            raw_value: Some(encode_query_component(value)),
            decoded_value: value.to_string(),
        }
    }

    fn write_to(&self, out: &mut String) {
        out.push_str(&self.raw_name);
        if let Some(ref value) = self.raw_value {
            out.push('=');
            out.push_str(value);
        }
    }
}

/// Ordered, duplicate-aware query representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrderedQuery {
    pairs: Vec<QueryPair>,
}

impl OrderedQuery {
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Parse a raw query string. Empty `&` segments are skipped (they are not
    /// parameters). Invalid percent-encoding is retained on the wire form and
    /// decoded lossily for matching — never panics.
    pub fn parse(raw_query: &str) -> Self {
        if raw_query.is_empty() {
            return Self::new();
        }
        let mut pairs = Vec::new();
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            pairs.push(QueryPair::from_raw_segment(pair));
        }
        Self { pairs }
    }

    /// Build from a already-materialized single-value map (synthetic / test
    /// contexts with no retained raw query). Order follows the map iterator.
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        let mut pairs = Vec::with_capacity(map.len());
        for (name, value) in map {
            pairs.push(QueryPair::authored(name, value));
        }
        Self { pairs }
    }

    pub fn contains_decoded_name(&self, name: &str) -> bool {
        self.pairs.iter().any(|pair| pair.decoded_name == name)
    }

    /// Serialize to a query string. Unmodified pairs keep their original
    /// encoding; authored pairs use RFC 3986 percent-encoding (`%20`, never `+`).
    pub fn serialize(&self) -> String {
        if self.pairs.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (idx, pair) in self.pairs.iter().enumerate() {
            if idx > 0 {
                out.push('&');
            }
            pair.write_to(&mut out);
        }
        out
    }

    /// Collapse to the plugin-visible single-value map (last occurrence wins),
    /// matching [`crate::plugins::RequestContext::materialize_query_params`].
    pub fn to_single_value_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(self.pairs.len());
        for pair in &self.pairs {
            map.insert(pair.decoded_name.clone(), pair.decoded_value.clone());
        }
        map
    }

    /// `add`: append `name=value` only when no existing pair has that decoded
    /// name. Duplicate existing names are left untouched.
    pub fn add(&mut self, name: &str, value: &str) -> bool {
        if self.contains_decoded_name(name) {
            return false;
        }
        self.pairs.push(QueryPair::authored(name, value));
        true
    }

    /// `update`: replace the value of every pair whose decoded name matches.
    /// If none match, append one authored pair (HashMap `insert` create).
    /// Always writes an `=` form (including empty values).
    pub fn update(&mut self, name: &str, value: &str) -> bool {
        let encoded_value = encode_query_component(value);
        let mut found = false;
        for pair in &mut self.pairs {
            if pair.decoded_name == name {
                pair.raw_value = Some(encoded_value.clone());
                pair.decoded_value = value.to_string();
                found = true;
            }
        }
        if found {
            return true;
        }
        self.pairs.push(QueryPair::authored(name, value));
        true
    }

    /// `remove`: drop every pair whose decoded name matches.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.pairs.len();
        self.pairs.retain(|pair| pair.decoded_name != name);
        self.pairs.len() != before
    }

    /// Drop every pair whose raw or decoded name is in `names`.
    ///
    /// Used to remove authentication-owned credential pairs before ordered
    /// query mutations so a later rename/update/add cannot relocate or
    /// re-encode an authenticated secret onto the outbound query. Matches the
    /// same raw-or-decoded name contract as
    /// [`crate::proxy::query_string_after_plugin_strips`].
    pub fn remove_matching_names(&mut self, names: &HashSet<&str>) -> bool {
        if names.is_empty() {
            return false;
        }
        let before = self.pairs.len();
        self.pairs.retain(|pair| {
            !names.contains(pair.raw_name.as_str()) && !names.contains(pair.decoded_name.as_str())
        });
        self.pairs.len() != before
    }

    /// `rename`: rename every matching pair to `new_name`, preserving each
    /// pair's value encoding and key-without-equals shape. Existing pairs
    /// already named `new_name` are left in place (duplicates of `new_name`
    /// may result). No-op when `name` is absent.
    pub fn rename(&mut self, name: &str, new_name: &str) -> bool {
        if name == new_name {
            return false;
        }
        let encoded_new = encode_query_component(new_name);
        let mut changed = false;
        for pair in &mut self.pairs {
            if pair.decoded_name == name {
                pair.raw_name = encoded_new.clone();
                pair.decoded_name = new_name.to_string();
                changed = true;
            }
        }
        changed
    }
}

/// Percent-encode a query component we author. Never panics.
pub fn encode_query_component(input: &str) -> String {
    utf8_percent_encode(input, QUERY_COMPONENT_ENCODE_SET).to_string()
}
