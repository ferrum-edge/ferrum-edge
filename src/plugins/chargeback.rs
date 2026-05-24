//! Shared chargeback helpers used by in-memory and durable charge exporters.

pub mod pricing {
    use serde_json::Value;
    use std::collections::HashMap;

    /// Resolved pricing configuration for chargeback plugins.
    #[derive(Debug, Clone, Default)]
    pub struct PricingConfig {
        /// Per-call pricing keyed by HTTP status code.
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
            let call_price = self
                .price_by_status
                .get(&status_code)
                .copied()
                .unwrap_or(0.0);
            let has_bandwidth =
                self.bandwidth_price_sent > 0.0 || self.bandwidth_price_received > 0.0;
            if call_price == 0.0 && !has_bandwidth {
                return None;
            }
            Some(self.compute_amounts(1, call_price, bytes_sent, bytes_received))
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
                "{plugin_name}: '{ctx}' must be a finite non-negative number"
            ));
        }
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
            if !tier.is_object() {
                return Err(format!(
                    "{plugin_name}: pricing_tiers[{i}] must be an object"
                ));
            }

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
