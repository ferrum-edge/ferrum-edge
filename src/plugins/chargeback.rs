//! Shared chargeback helpers used by in-memory and durable charge exporters.

use std::borrow::Cow;

use crate::fips::approved::Sha256;

use super::TransactionSummary;

/// Domain separator for the billing-identity digest. Keeps the digest from
/// colliding with any other SHA-256 use in the process and pins the encoding
/// version so a future change is a visibly different representation.
const BILLING_IDENTITY_DIGEST_DOMAIN: &[u8] = b"ferrum-edge/chargeback-billing-identity/v1\0";

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
    let mut hasher = Sha256::new();
    hasher.update(BILLING_IDENTITY_DIGEST_DOMAIN);
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    if max_len < BILLING_IDENTITY_DIGEST_SUFFIX_BYTES {
        // No prefix budget: emit as much of the digest as fits. `digest` is
        // ASCII hex, so byte slicing is always on a char boundary.
        return Cow::Owned(digest[..max_len.min(BILLING_IDENTITY_DIGEST_HEX_LEN)].to_string());
    }
    let prefix_budget = max_len - BILLING_IDENTITY_DIGEST_SUFFIX_BYTES;
    let prefix = bounded_display(value, prefix_budget);
    Cow::Owned(format!("{prefix}{BILLING_IDENTITY_DIGEST_MARKER}{digest}"))
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

pub fn http_billing_outcome(summary: &TransactionSummary) -> HttpBillingOutcome {
    let grpc_status = summary.grpc_status();
    let status_code = grpc_status
        .map(crate::proxy::grpc_proxy::grpc_status_to_http_status)
        .unwrap_or_else(|| {
            if is_websocket_handshake(summary) {
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
                "chargeback unit price must be a finite non-negative number, got {unit_price}"
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
            .ok_or_else(|| format!("{plugin_name}: '{ctx}' must be a number"))?;
        if !number.is_finite() || number < 0.0 {
            return Err(format!(
                "{plugin_name}: '{ctx}' must be a finite non-negative number \
                 no greater than {MAX_UNIT_PRICE}"
            ));
        }
        if number > MAX_UNIT_PRICE {
            return Err(format!(
                "{plugin_name}: '{ctx}' must be a finite non-negative number \
                 no greater than {MAX_UNIT_PRICE}, got {number}"
            ));
        }
        // Reject rates whose product with the largest supported counter cannot
        // stay finite even though the rate itself is below MAX_UNIT_PRICE
        // (defensive against future bound tweaks / unusual float quirks).
        let _ = checked_mul_quantity(u64::MAX, number).map_err(|_| {
            format!(
                "{plugin_name}: '{ctx}'={number} overflows when multiplied by \
                 the maximum supported counter (u64::MAX)"
            )
        })?;
        Ok(number)
    }

    fn parse_pricing_tiers(value: &Value, plugin_name: &str) -> Result<HashMap<u16, f64>, String> {
        let tiers = value
            .as_array()
            .ok_or_else(|| format!("{plugin_name}: 'pricing_tiers' must be an array"))?;

        if tiers.is_empty() {
            return Err(format!(
                "{plugin_name}: 'pricing_tiers' must contain at least one pricing tier"
            ));
        }

        let mut price_by_status: HashMap<u16, f64> = HashMap::new();
        for (i, tier) in tiers.iter().enumerate() {
            let tier_obj = tier
                .as_object()
                .ok_or_else(|| format!("{plugin_name}: pricing_tiers[{i}] must be an object"))?;
            reject_unknown_keys(
                tier_obj,
                &format!("pricing_tiers[{i}]"),
                PRICING_TIER_KEYS,
                &format!("{plugin_name}: "),
            )?;

            let status_codes = tier
                .get("status_codes")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    format!(
                        "{plugin_name}: pricing_tiers[{i}].status_codes is required and must be an array"
                    )
                })?;

            if status_codes.is_empty() {
                return Err(format!(
                    "{plugin_name}: pricing_tiers[{i}].status_codes must not be empty"
                ));
            }

            let price_value = tier.get("price_per_call").ok_or_else(|| {
                format!(
                    "{plugin_name}: pricing_tiers[{i}].price_per_call is required and must be a number"
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
                        "{plugin_name}: pricing_tiers[{i}].status_codes contains non-integer value"
                    )
                })?;

                if !(100..=599).contains(&code_u64) {
                    return Err(format!(
                        "{plugin_name}: pricing_tiers[{i}].status_codes contains invalid HTTP status code {code_u64}"
                    ));
                }
                let code = code_u64 as u16;

                if price_by_status.contains_key(&code) {
                    return Err(format!(
                        "{plugin_name}: status code {code} appears in multiple pricing tiers"
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
                "{plugin_name}: 'bandwidth_pricing' must be an object"
            ));
        }
        let allowed = ["price_per_byte_sent", "price_per_byte_received"];
        if let Some(obj) = value.as_object() {
            for key in obj.keys() {
                if !allowed.contains(&key.as_str()) {
                    return Err(format!(
                        "{plugin_name}: unknown key '{key}' in bandwidth_pricing (allowed: {})",
                        allowed.join(", ")
                    ));
                }
            }
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
                "{plugin_name}: 'stream_connection_pricing' must be an object"
            ));
        }
        let allowed = ["price_per_connection"];
        if let Some(obj) = value.as_object() {
            for key in obj.keys() {
                if !allowed.contains(&key.as_str()) {
                    return Err(format!(
                        "{plugin_name}: unknown key '{key}' in stream_connection_pricing (allowed: {})",
                        allowed.join(", ")
                    ));
                }
            }
        }
        match value.get("price_per_connection") {
            Some(v) => optional_non_negative_f64(
                v,
                "stream_connection_pricing.price_per_connection",
                plugin_name,
            ),
            None => Err(format!(
                "{plugin_name}: 'stream_connection_pricing.price_per_connection' is required"
            )),
        }
    }
}
