//! Shared chargeback helpers used by in-memory and durable charge exporters.

use std::borrow::Cow;
use std::cell::RefCell;

use crate::fips::approved::Sha256;
use crate::plugins::utils::principal::{EXTERNAL_KEY_PREFIX, Principal, PrincipalOrigin};

use super::TransactionSummary;

/// Domain separator for the billing-identity digest. Keeps the digest from
/// colliding with any other SHA-256 use in the process and pins the encoding
/// version so a future change is a visibly different representation.
const BILLING_IDENTITY_DIGEST_DOMAIN: &[u8] = b"ferrum-edge/chargeback-billing-identity/v1\0";

/// Domain separator for the digest form of an unmapped external principal's
/// billing identity (GHSA-q9vj-rf66-3j58). Distinct from
/// [`BILLING_IDENTITY_DIGEST_DOMAIN`], so an external digest form never equals
/// a Consumer's even when the two hashed strings are the same bytes.
const EXTERNAL_BILLING_IDENTITY_DIGEST_DOMAIN: &[u8] =
    b"ferrum-edge/chargeback-billing-identity/external/v1\0";

/// Initial capacity of the per-thread external billing key buffer: the
/// longest fixed part of an external key (prefix, mechanism, 64-hex authority,
/// separators) plus a typical subject.
const EXTERNAL_KEY_BUF_INITIAL_CAPACITY: usize = 160;

/// Capacity above which the per-thread external billing key buffer is released
/// after use instead of being retained for the next record.
const EXTERNAL_KEY_BUF_MAX_RETAINED_CAPACITY: usize = 4096;

/// Marker separating the human-readable prefix from the digest.
const BILLING_IDENTITY_DIGEST_MARKER: &str = "~sha256:";

/// Hex length of a SHA-256 digest.
const BILLING_IDENTITY_DIGEST_HEX_LEN: usize = 64;

/// Total bytes a digest suffix adds: marker plus hex digest.
pub const BILLING_IDENTITY_DIGEST_SUFFIX_BYTES: usize =
    BILLING_IDENTITY_DIGEST_MARKER.len() + BILLING_IDENTITY_DIGEST_HEX_LEN;

/// Longest UTF-8-safe prefix of `value` that fits in `max_len` bytes.
///
/// Shared by every chargeback field bound so the char-boundary walk has one
/// implementation. This is a *display* bound only: never use its output as an
/// aggregation, snapshot, or export key for an identity — use
/// [`bounded_billing_identity`] there.
pub fn bounded_display(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }
    let mut end = max_len;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Bound an authenticated billing identity to `max_len` bytes **without**
/// merging distinct principals.
///
/// A plain prefix truncation is not usable as a billing key: two verified
/// identities that share the first `max_len` bytes would become one exported
/// `consumer_id` and, in snapshot mode, one accumulator entry combining both
/// principals' calls, bytes, and charges (GHSA-m28c-f3v5-26qg).
///
/// Values within the bound are returned byte-for-byte, so the common case is
/// allocation-free and fully reversible. An oversized value is replaced by a
/// domain-separated, collision-resistant representation:
/// `<utf8-safe prefix>~sha256:<hex digest of the complete identity>`. The
/// digest covers the whole original value, so two identities differing
/// anywhere still produce different representations, while the retained prefix
/// keeps the row recognizable during reconciliation. Operators who need the
/// original value must resolve it at the identity provider — the gateway
/// deliberately does not retain oversized credential-derived identities.
///
/// The mapping is injective, which is what makes it safe as a key: a value
/// returned verbatim never contains the digest marker, and a digest form always
/// does, so the two classes are disjoint and two digest forms collide only on a
/// SHA-256 collision. A within-bound identity that itself contains the marker is
/// therefore *also* replaced by its digest form — otherwise an actor who knows a
/// victim's long identity could present its representation as a short identity
/// and be billed into the victim's row. Internal registry sentinels that need to
/// stay unreachable from real principals (for example the api_chargeback
/// cardinality-overflow row) must likewise live in the digest-form class, with a
/// non-hex suffix so they cannot equal a genuine digest representation either.
///
/// `max_len` below `BILLING_IDENTITY_DIGEST_SUFFIX_BYTES` leaves no room for a
/// prefix; the representation is then the leading bytes of the digest alone.
pub fn bounded_billing_identity(value: &str, max_len: usize) -> Cow<'_, str> {
    if value.len() <= max_len && !value.contains(BILLING_IDENTITY_DIGEST_MARKER) {
        return Cow::Borrowed(value);
    }
    Cow::Owned(digest_billing_identity(
        BILLING_IDENTITY_DIGEST_DOMAIN,
        value,
        max_len,
    ))
}

/// Lowercase hex alphabet for digest suffixes written in place.
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 of `domain || value`.
fn billing_identity_digest(domain: &[u8], value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value.as_bytes());
    hasher.finalize()
}

/// Append the first `hex_len` lowercase hex digits of `digest` to `out` (the
/// same text as a prefix of `hex::encode(digest)`), without allocating beyond
/// `out`'s own growth.
fn push_digest_hex(out: &mut String, digest: &[u8; 32], hex_len: usize) {
    let mut remaining = hex_len.min(BILLING_IDENTITY_DIGEST_HEX_LEN);
    for &byte in digest {
        for nibble in [byte >> 4, byte & 0x0f] {
            if remaining == 0 {
                return;
            }
            out.push(char::from(LOWER_HEX[usize::from(nibble)]));
            remaining -= 1;
        }
    }
}

/// The digest form `<utf8-safe prefix>~sha256:<hex of SHA-256(domain || value)>`
/// bounded to `max_len` (see [`bounded_billing_identity`]).
fn digest_billing_identity(domain: &[u8], value: &str, max_len: usize) -> String {
    let digest = billing_identity_digest(domain, value);
    if max_len < BILLING_IDENTITY_DIGEST_SUFFIX_BYTES {
        // No prefix budget: emit as much of the digest as fits.
        let mut out = String::with_capacity(max_len.min(BILLING_IDENTITY_DIGEST_HEX_LEN));
        push_digest_hex(&mut out, &digest, max_len);
        return out;
    }
    let prefix_budget = max_len - BILLING_IDENTITY_DIGEST_SUFFIX_BYTES;
    let prefix = bounded_display(value, prefix_budget);
    let mut out = String::with_capacity(prefix.len() + BILLING_IDENTITY_DIGEST_SUFFIX_BYTES);
    out.push_str(prefix);
    out.push_str(BILLING_IDENTITY_DIGEST_MARKER);
    push_digest_hex(&mut out, &digest, BILLING_IDENTITY_DIGEST_HEX_LEN);
    out
}

/// Replace the complete value held in `buf` with its digest form, in place:
/// byte-for-byte what [`digest_billing_identity`] returns for the same value,
/// but reusing `buf` (hash the whole value, truncate at the UTF-8-safe prefix
/// boundary, append marker and hex) so a warm buffer allocates nothing.
fn digest_billing_identity_in_place(domain: &[u8], buf: &mut String, max_len: usize) {
    let digest = billing_identity_digest(domain, buf.as_str());
    if max_len < BILLING_IDENTITY_DIGEST_SUFFIX_BYTES {
        buf.clear();
        push_digest_hex(buf, &digest, max_len);
        return;
    }
    let prefix_budget = max_len - BILLING_IDENTITY_DIGEST_SUFFIX_BYTES;
    let prefix_len = bounded_display(buf.as_str(), prefix_budget).len();
    buf.truncate(prefix_len);
    buf.push_str(BILLING_IDENTITY_DIGEST_MARKER);
    push_digest_hex(buf, &digest, BILLING_IDENTITY_DIGEST_HEX_LEN);
}

/// The billable principal behind a summary's display identity, or `None` when
/// the summary carries no (or an empty) identity and is therefore not billed.
///
/// `origin` is the summary's recorded [`PrincipalOrigin`]; a missing origin
/// fails closed to an external principal (see [`Principal::with_origin`]).
pub fn billing_principal(
    identity: Option<&str>,
    origin: Option<PrincipalOrigin>,
) -> Option<Principal<'_>> {
    identity
        .filter(|identity| !identity.is_empty())
        .map(|identity| Principal::with_origin(identity, origin))
}

/// The billing identity (`/charges` consumer key, `consumer` label, and
/// `api_chargeback_sink` `consumer_id`) of an authenticated principal, bounded
/// to `max_len` bytes (GHSA-q9vj-rf66-3j58).
///
/// The display string `effective_identity()` puts in a summary's
/// `consumer_username` is shared by a mapped Consumer and by unmapped external
/// principals of every mechanism and authority, so it cannot be the billing
/// key. Each principal gets one of these disjoint forms instead:
///
/// - **Consumer** `alice`: the username, exactly as [`bounded_billing_identity`]
///   represents it, so Consumer rows are unchanged. The one exception is a
///   username that begins with `external:`, which is always given its digest
///   form so it can never spell an external principal's row.
/// - **External principal**: its namespaced
///   [`Principal::push_key`](crate::plugins::utils::principal::Principal::push_key)
///   form `external:<mechanism|->:<authority-hex|->:<identity>`, the same
///   key per-caller limiters use. Two authorities (or mechanisms) that issue
///   the same subject therefore bill separate rows, and neither shares the
///   Consumer's.
/// - **Digest form** `<prefix>~sha256:<64 hex>`: any value that is oversized or
///   contains the digest marker. External keys hash under a separate domain
///   from Consumer usernames, so the two digest forms never coincide.
///
/// The verbatim Consumer class never starts with `external:` and the verbatim
/// external class always does; neither contains the digest marker, which every
/// digest form does; and the internal `api_chargeback` overflow sentinel is a
/// marker-bearing value whose suffix is not 64 hex, so no real principal can
/// share its row either. `max_len` must be at least
/// [`BILLING_IDENTITY_DIGEST_SUFFIX_BYTES`] for these guarantees (both
/// chargeback plugins use 512).
///
/// Allocates only for an external principal or a digest form; the
/// allocation-free [`with_principal_billing_identity`] serves the request path.
pub fn principal_billing_identity(principal: Principal<'_>, max_len: usize) -> Cow<'_, str> {
    match principal {
        Principal::Consumer(username) => consumer_billing_identity(username, max_len),
        Principal::External { .. } => {
            let mut key = String::new();
            principal.push_key(&mut key);
            Cow::Owned(external_billing_identity_from_key(key, max_len))
        }
    }
}

/// [`principal_billing_identity`] as an owned `String` built with exactly one
/// allocation, for a value that is moved into an exported event: a verbatim
/// Consumer username is copied once, a verbatim external key is built directly
/// at its exact length, and any digest form is encoded in the per-thread
/// buffer and copied once. The bytes are identical to
/// [`principal_billing_identity`].
pub fn owned_principal_billing_identity(principal: Principal<'_>, max_len: usize) -> String {
    match principal {
        Principal::Consumer(username) if !consumer_needs_digest(username, max_len) => {
            username.to_owned()
        }
        // The fixed key components (prefix, compiled-in mechanism, hex or `-`
        // authority, separators) cannot form the digest marker, so the
        // identity alone decides whether the marker appears.
        Principal::External { identity, .. }
            if principal.key_len() <= max_len
                && !identity.contains(BILLING_IDENTITY_DIGEST_MARKER) =>
        {
            let mut key = String::new();
            principal.push_key(&mut key);
            key
        }
        _ => with_principal_billing_identity(principal, max_len, str::to_owned),
    }
}

/// [`principal_billing_identity`] handed to `f` without allocating once the
/// per-thread buffer is warm: an in-bound Consumer borrows its username, and
/// every other form (an external principal's key, and any digest form) is
/// built in that buffer. The bytes are identical to
/// [`principal_billing_identity`].
pub fn with_principal_billing_identity<R>(
    principal: Principal<'_>,
    max_len: usize,
    f: impl FnOnce(&str) -> R,
) -> R {
    if let Principal::Consumer(username) = principal
        && !consumer_needs_digest(username, max_len)
    {
        return f(username);
    }
    thread_local! {
        static EXTERNAL_KEY_BUF: RefCell<String> =
            RefCell::new(String::with_capacity(EXTERNAL_KEY_BUF_INITIAL_CAPACITY));
    }
    EXTERNAL_KEY_BUF.with(move |buf| match buf.try_borrow_mut() {
        Ok(mut key) => {
            key.clear();
            match principal {
                // Only a digest-form Consumer reaches the buffer.
                Principal::Consumer(username) => {
                    key.push_str(username);
                    digest_billing_identity_in_place(
                        BILLING_IDENTITY_DIGEST_DOMAIN,
                        &mut key,
                        max_len,
                    );
                }
                Principal::External { .. } => {
                    principal.push_key(&mut key);
                    if !external_key_is_verbatim(key.as_str(), max_len) {
                        digest_billing_identity_in_place(
                            EXTERNAL_BILLING_IDENTITY_DIGEST_DOMAIN,
                            &mut key,
                            max_len,
                        );
                    }
                }
            }
            let result = f(key.as_str());
            if key.capacity() > EXTERNAL_KEY_BUF_MAX_RETAINED_CAPACITY {
                *key = String::with_capacity(EXTERNAL_KEY_BUF_INITIAL_CAPACITY);
            }
            result
        }
        // Re-entered from inside `f`: build an owned key rather than share
        // the buffer that is still lent out.
        Err(_) => f(principal_billing_identity(principal, max_len).as_ref()),
    })
}

/// Whether a Consumer username needs its digest form: oversized,
/// marker-bearing (as for [`bounded_billing_identity`]), or spelling the
/// reserved external-key prefix.
fn consumer_needs_digest(username: &str, max_len: usize) -> bool {
    username.len() > max_len
        || username.contains(BILLING_IDENTITY_DIGEST_MARKER)
        || username.starts_with(EXTERNAL_KEY_PREFIX)
}

/// Consumer arm of [`principal_billing_identity`]: the username exactly as
/// [`bounded_billing_identity`] represents it, except that a reserved-prefix
/// username is always digested.
fn consumer_billing_identity(username: &str, max_len: usize) -> Cow<'_, str> {
    if consumer_needs_digest(username, max_len) {
        return Cow::Owned(digest_billing_identity(
            BILLING_IDENTITY_DIGEST_DOMAIN,
            username,
            max_len,
        ));
    }
    Cow::Borrowed(username)
}

/// Whether an external key is its own billing identity (in bound and free of
/// the digest marker) rather than needing its digest form.
fn external_key_is_verbatim(key: &str, max_len: usize) -> bool {
    key.len() <= max_len && !key.contains(BILLING_IDENTITY_DIGEST_MARKER)
}

/// External arm of [`principal_billing_identity`] for an already built key.
fn external_billing_identity_from_key(key: String, max_len: usize) -> String {
    if external_key_is_verbatim(&key, max_len) {
        return key;
    }
    digest_billing_identity(EXTERNAL_BILLING_IDENTITY_DIGEST_DOMAIN, &key, max_len)
}

/// Final status dimensions used by both chargeback implementations.
///
/// `status_code` is the billable/output dimension. Ordinary HTTP retains its
/// wire status; native gRPC and translated gRPC-Web use the canonical effective
/// HTTP mapping of the final normalized application status. The raw transport
/// and application values remain available separately for durable exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpBillingOutcome {
    pub status_code: u16,
    pub http_status_code: u16,
    pub grpc_status: Option<u32>,
}

/// Billable status for a gRPC exchange whose terminal status is present on the
/// wire but unreadable by the gateway (for example a compressed gRPC-Web
/// trailer frame). The documented mapping sends unknown terminal codes to
/// `500`; billing the wire `200` would price a possibly failed call as success.
const UNREADABLE_GRPC_STATUS_BILLING_CODE: u16 = 500;

pub fn http_billing_outcome(summary: &TransactionSummary) -> HttpBillingOutcome {
    let grpc_status = summary.grpc_status();
    let status_code = grpc_status
        .map(crate::proxy::grpc_proxy::grpc_status_to_http_status)
        .unwrap_or_else(|| {
            // `grpc_status` stays `None` for an unreadable status so logs never
            // report an UNKNOWN the client did not receive; only the billable
            // dimension is mapped.
            if summary
                .metadata
                .contains_key(crate::proxy::grpc_proxy::GRPC_STATUS_UNREADABLE_METADATA_KEY)
            {
                UNREADABLE_GRPC_STATUS_BILLING_CODE
            } else if is_websocket_handshake(summary) {
                101
            } else {
                summary.response_status_code
            }
        });
    HttpBillingOutcome {
        status_code,
        http_status_code: summary.response_status_code,
        grpc_status,
    }
}

/// Successful WebSocket handshakes share one billing tier across HTTP transports.
/// Rejected Extended CONNECT requests retain their ordinary error status.
pub fn is_websocket_handshake(summary: &TransactionSummary) -> bool {
    summary.response_status_code == 101
        || ((200..300).contains(&summary.response_status_code)
            && summary
                .metadata
                .get("request_protocol")
                .is_some_and(|protocol| protocol == "ws"))
}

pub mod pricing {
    use serde_json::Value;
    use std::collections::HashMap;

    use crate::util::unknown_keys::reject_unknown_keys;

    /// Closed key set for each `pricing_tiers[]` object.
    const PRICING_TIER_KEYS: &[&str] = &["status_codes", "price_per_call"];

    /// Maximum accepted unit price for every chargeback pricing dimension
    /// (`price_per_call`, `price_per_byte_*`, `price_per_connection`).
    ///
    /// Bound is chosen so multiplying any accepted price by the largest
    /// supported counter (`u64::MAX`) still yields a finite IEEE-754 binary64
    /// value, with headroom to sum the three per-entry charge dimensions
    /// (call + bytes_sent + bytes_received). Aggregation across many series can
    /// still overflow; exporters must fail closed on non-finite totals rather
    /// than emit JSON `null` or Prometheus `inf`.
    ///
    /// Arithmetic semantics: the stored `u64` counter is converted to binary64
    /// and multiplied by the binary64 unit price at export (or per event for
    /// the durable sink). Counters above 2^53 therefore follow normal IEEE-754
    /// rounding. There is no decimal/currency-subunit rounding; Prometheus
    /// samples format with 10 fractional digits (`{:.10}`).
    pub const MAX_UNIT_PRICE: f64 = 1.0e288;

    /// Resolved pricing configuration for chargeback plugins.
    #[derive(Debug, Clone, Default)]
    pub struct PricingConfig {
        /// Per-call pricing keyed by billable status code.
        pub price_by_status: HashMap<u16, f64>,
        /// Per-byte bandwidth charge for client->backend bytes.
        pub bandwidth_price_sent: f64,
        /// Per-byte bandwidth charge for backend->client bytes.
        pub bandwidth_price_received: f64,
        /// Per-connection charge for stream sessions (TCP/UDP/DTLS).
        pub stream_connection_price: f64,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq)]
    pub struct ChargeComputation {
        pub call_count: u32,
        pub charge_call: f64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub charge_bytes_sent: f64,
        pub charge_bytes_received: f64,
        pub charge_total: f64,
    }

    /// Multiply an exact `u64` quantity by a unit price, rejecting non-finite
    /// results (including overflow to ±infinity).
    pub fn checked_mul_quantity(quantity: u64, unit_price: f64) -> Result<f64, String> {
        if !unit_price.is_finite() || unit_price < 0.0 {
            return Err(format!(
                "chargeback unit price must be a finite non-negative number, got \"{unit_price}\""
            ));
        }
        let product = quantity as f64 * unit_price;
        if !product.is_finite() {
            return Err(format!(
                "chargeback quantity×price overflowed to a non-finite value \
                 (quantity={quantity}, unit_price={unit_price})"
            ));
        }
        Ok(product)
    }

    /// Add two monetary values, rejecting non-finite sums.
    pub fn checked_add_charge(lhs: f64, rhs: f64) -> Result<f64, String> {
        if !lhs.is_finite() || !rhs.is_finite() {
            return Err("chargeback cannot add a non-finite monetary value".to_string());
        }
        let sum = lhs + rhs;
        if !sum.is_finite() {
            return Err(
                "chargeback monetary aggregate overflowed to a non-finite value".to_string(),
            );
        }
        Ok(sum)
    }

    /// Require a monetary sample to be finite before export.
    pub fn require_finite_charge(value: f64, ctx: &str) -> Result<f64, String> {
        if !value.is_finite() {
            return Err(format!(
                "chargeback {ctx} is non-finite and cannot be exported as a number"
            ));
        }
        Ok(value)
    }

    impl PricingConfig {
        pub fn from_config(config: &Value, plugin_name: &str) -> Result<Self, String> {
            let mut pricing = PricingConfig::default();
            if let Some(tiers) = config.get("pricing_tiers") {
                pricing.price_by_status = parse_pricing_tiers(tiers, plugin_name)?;
            }
            if let Some(bw) = config.get("bandwidth_pricing") {
                let (sent, received) = parse_bandwidth_pricing(bw, plugin_name)?;
                pricing.bandwidth_price_sent = sent;
                pricing.bandwidth_price_received = received;
            }
            if let Some(stream) = config.get("stream_connection_pricing") {
                pricing.stream_connection_price =
                    parse_stream_connection_pricing(stream, plugin_name)?;
            }
            Ok(pricing)
        }

        pub fn has_any_pricing(&self) -> bool {
            !self.price_by_status.is_empty()
                || self.bandwidth_price_sent > 0.0
                || self.bandwidth_price_received > 0.0
                || self.stream_connection_price > 0.0
        }

        pub fn compute_http(
            &self,
            status_code: u16,
            bytes_sent: u64,
            bytes_received: u64,
        ) -> Option<ChargeComputation> {
            let call_price = self.price_by_status.get(&status_code).copied();
            let has_bandwidth =
                self.bandwidth_price_sent > 0.0 || self.bandwidth_price_received > 0.0;
            if call_price.is_none() && !has_bandwidth {
                return None;
            }
            Some(self.compute_amounts(1, call_price.unwrap_or(0.0), bytes_sent, bytes_received))
        }

        pub fn compute_stream(
            &self,
            bytes_sent: u64,
            bytes_received: u64,
        ) -> Option<ChargeComputation> {
            let has_bandwidth =
                self.bandwidth_price_sent > 0.0 || self.bandwidth_price_received > 0.0;
            if self.stream_connection_price == 0.0 && !has_bandwidth {
                return None;
            }
            Some(self.compute_amounts(1, self.stream_connection_price, bytes_sent, bytes_received))
        }

        pub fn compute_websocket_bandwidth(
            &self,
            bytes_sent: u64,
            bytes_received: u64,
        ) -> Option<ChargeComputation> {
            if self.bandwidth_price_sent == 0.0 && self.bandwidth_price_received == 0.0 {
                return None;
            }
            Some(self.compute_amounts(0, 0.0, bytes_sent, bytes_received))
        }

        fn compute_amounts(
            &self,
            call_count: u32,
            charge_call: f64,
            bytes_sent: u64,
            bytes_received: u64,
        ) -> ChargeComputation {
            // Admission bounds every unit price so each u64 multiplication and
            // the three-way per-event sum remain finite. Keep the sink's
            // existing infallible accounting contract: silently dropping a
            // billable event would be worse than the export failure this issue
            // is fixing.
            let charge_bytes_sent = bytes_sent as f64 * self.bandwidth_price_sent;
            let charge_bytes_received = bytes_received as f64 * self.bandwidth_price_received;
            ChargeComputation {
                call_count,
                charge_call,
                bytes_sent,
                bytes_received,
                charge_bytes_sent,
                charge_bytes_received,
                charge_total: charge_call + charge_bytes_sent + charge_bytes_received,
            }
        }
    }

    pub fn optional_non_negative_f64(
        value: &Value,
        ctx: &str,
        plugin_name: &str,
    ) -> Result<f64, String> {
        let number = value
            .as_f64()
            .ok_or_else(|| format!("{plugin_name}: `{ctx}` must be a number"))?;
        if !number.is_finite() || number < 0.0 {
            return Err(format!(
                "{plugin_name}: `{ctx}` must be a finite non-negative number \
                 no greater than {MAX_UNIT_PRICE}"
            ));
        }
        if number > MAX_UNIT_PRICE {
            return Err(format!(
                "{plugin_name}: `{ctx}` must be a finite non-negative number \
                 no greater than {MAX_UNIT_PRICE}, got \"{number}\""
            ));
        }
        // Reject rates whose product with the largest supported counter cannot
        // stay finite even though the rate itself is below MAX_UNIT_PRICE
        // (defensive against future bound tweaks / unusual float quirks).
        let _ = checked_mul_quantity(u64::MAX, number).map_err(|_| {
            format!(
                "{plugin_name}: `{ctx}`=\"{number}\" overflows when multiplied by \
                 the maximum supported counter (u64::MAX)"
            )
        })?;
        Ok(number)
    }

    fn parse_pricing_tiers(value: &Value, plugin_name: &str) -> Result<HashMap<u16, f64>, String> {
        let tiers = value
            .as_array()
            .ok_or_else(|| format!("{plugin_name}: `pricing_tiers` must be an array"))?;

        if tiers.is_empty() {
            return Err(format!(
                "{plugin_name}: `pricing_tiers` must contain at least one pricing tier"
            ));
        }

        let mut price_by_status: HashMap<u16, f64> = HashMap::new();
        for (i, tier) in tiers.iter().enumerate() {
            let tier_obj = tier
                .as_object()
                .ok_or_else(|| format!("{plugin_name}: `pricing_tiers[{i}]` must be an object"))?;
            reject_unknown_keys(
                tier_obj,
                &format!("pricing_tiers[{i}]"),
                PRICING_TIER_KEYS,
                &format!("{plugin_name}: `pricing_tiers[{i}]`: "),
            )?;

            let status_codes = tier
                .get("status_codes")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    format!(
                        "{plugin_name}: `pricing_tiers[{i}].status_codes` is required and must be an array"
                    )
                })?;

            if status_codes.is_empty() {
                return Err(format!(
                    "{plugin_name}: `pricing_tiers[{i}].status_codes` must not be empty"
                ));
            }

            let price_value = tier.get("price_per_call").ok_or_else(|| {
                format!(
                    "{plugin_name}: `pricing_tiers[{i}].price_per_call` is required and must be a number"
                )
            })?;
            let price = optional_non_negative_f64(
                price_value,
                &format!("pricing_tiers[{i}].price_per_call"),
                plugin_name,
            )?;

            for code_val in status_codes {
                let code_u64 = code_val.as_u64().ok_or_else(|| {
                    format!(
                        "{plugin_name}: `pricing_tiers[{i}].status_codes` contains non-integer value"
                    )
                })?;

                if !(100..=599).contains(&code_u64) {
                    return Err(format!(
                        "{plugin_name}: `pricing_tiers[{i}].status_codes` contains invalid HTTP status code \"{code_u64}\""
                    ));
                }
                let code = code_u64 as u16;

                if price_by_status.contains_key(&code) {
                    return Err(format!(
                        "{plugin_name}: `pricing_tiers[{i}].status_codes` status code \"{code}\" appears in multiple pricing tiers"
                    ));
                }

                price_by_status.insert(code, price);
            }
        }
        Ok(price_by_status)
    }

    fn parse_bandwidth_pricing(value: &Value, plugin_name: &str) -> Result<(f64, f64), String> {
        if !value.is_object() {
            return Err(format!(
                "{plugin_name}: `bandwidth_pricing` must be an object"
            ));
        }
        if let Some(obj) = value.as_object() {
            crate::util::unknown_keys::reject_unknown_keys(
                obj,
                "bandwidth_pricing",
                &["price_per_byte_sent", "price_per_byte_received"],
                &format!("{plugin_name}: `bandwidth_pricing`: "),
            )?;
        }
        let price_sent = match value.get("price_per_byte_sent") {
            Some(v) => {
                optional_non_negative_f64(v, "bandwidth_pricing.price_per_byte_sent", plugin_name)?
            }
            None => 0.0,
        };
        let price_received = match value.get("price_per_byte_received") {
            Some(v) => optional_non_negative_f64(
                v,
                "bandwidth_pricing.price_per_byte_received",
                plugin_name,
            )?,
            None => 0.0,
        };
        Ok((price_sent, price_received))
    }

    fn parse_stream_connection_pricing(value: &Value, plugin_name: &str) -> Result<f64, String> {
        if !value.is_object() {
            return Err(format!(
                "{plugin_name}: `stream_connection_pricing` must be an object"
            ));
        }
        if let Some(obj) = value.as_object() {
            crate::util::unknown_keys::reject_unknown_keys(
                obj,
                "stream_connection_pricing",
                &["price_per_connection"],
                &format!("{plugin_name}: `stream_connection_pricing`: "),
            )?;
        }
        match value.get("price_per_connection") {
            Some(v) => optional_non_negative_f64(
                v,
                "stream_connection_pricing.price_per_connection",
                plugin_name,
            ),
            None => Err(format!(
                "{plugin_name}: `stream_connection_pricing.price_per_connection` is required"
            )),
        }
    }
}
