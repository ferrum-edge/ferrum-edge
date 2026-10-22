//! Explicit, bounded synthetic headers for a diagnostic workload ladder.
//!
//! This changes only opted-in tool traffic. The backend verifies the entire
//! synthetic set independently; the fixed-width response receipt proves which
//! configured profile accepted an exchange, without a per-request checksum.

use anyhow::{Context, Result};
use clap::Args;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;

pub const REQUEST_HEADER_PREFIX: &str = "x-mesh-bench-";
pub const RECEIPT_HEADER: &str = "x-mesh-bench-receipt";
pub const MAX_HEADER_COUNT: u16 = 32;
pub const MAX_HEADER_VALUE_BYTES: u16 = 256;

#[derive(Args, Clone, Debug, Default)]
pub struct HeaderDiagnosticArgs {
    /// Explicit diagnostic synthetic-header count; requires the value size.
    #[arg(
        long,
        requires = "diagnostic_header_value_bytes",
        value_parser = clap::value_parser!(u16).range(0..=32)
    )]
    pub diagnostic_header_count: Option<u16>,
    /// Bytes of ASCII h in each diagnostic header; requires the header count.
    #[arg(
        long,
        requires = "diagnostic_header_count",
        value_parser = clap::value_parser!(u16).range(0..=256)
    )]
    pub diagnostic_header_value_bytes: Option<u16>,
}

impl HeaderDiagnosticArgs {
    pub fn profile(&self) -> Result<Option<HeaderDiagnostic>> {
        HeaderDiagnostic::from_options(
            self.diagnostic_header_count,
            self.diagnostic_header_value_bytes,
        )
    }
}

#[derive(Clone, Debug)]
pub struct HeaderDiagnostic {
    count: u16,
    value_bytes: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    receipt: HeaderValue,
    receipt_text: String,
    added_request_wire_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct HeaderDiagnosticMetadata {
    pub count: u16,
    pub value_bytes: u16,
    /// HTTP/1 field lines only: name + colon/space + value + CRLF. This is
    /// not TLS, HPACK, packet or aggregate network accounting.
    pub added_request_wire_bytes: usize,
    pub expected_receipt: String,
    /// None when no full echo passed receipt and body validation. Every
    /// successful warmup, measured or drained exchange validates the receipt.
    pub validated_receipt: Option<String>,
    pub validated_exchanges: u64,
}

impl HeaderDiagnostic {
    pub fn from_options(count: Option<u16>, value_bytes: Option<u16>) -> Result<Option<Self>> {
        match (count, value_bytes) {
            (None, None) => Ok(None),
            (Some(count), Some(value_bytes)) => Self::new(count, value_bytes).map(Some),
            _ => anyhow::bail!("both diagnostic header flags must be supplied together"),
        }
    }

    pub fn new(count: u16, value_bytes: u16) -> Result<Self> {
        anyhow::ensure!(
            count <= MAX_HEADER_COUNT,
            "diagnostic header count exceeds 32"
        );
        anyhow::ensure!(
            value_bytes <= MAX_HEADER_VALUE_BYTES,
            "diagnostic header value size exceeds 256"
        );
        let value = HeaderValue::from_bytes(&vec![b'h'; usize::from(value_bytes)])
            .context("invalid fixed diagnostic header value")?;
        let mut headers = Vec::with_capacity(usize::from(count));
        let mut added_request_wire_bytes = 0;
        for index in 0..count {
            let name = format!("{REQUEST_HEADER_PREFIX}{index:03}");
            added_request_wire_bytes += name.len() + 2 + usize::from(value_bytes) + 2;
            headers.push((
                HeaderName::from_bytes(name.as_bytes()).context("invalid fixed diagnostic name")?,
                value.clone(),
            ));
        }
        let receipt_text = format!("{count:02x}-{value_bytes:04x}");
        let receipt = HeaderValue::from_str(&receipt_text)
            .context("invalid fixed diagnostic response receipt")?;
        Ok(Self {
            count,
            value_bytes,
            headers,
            receipt,
            receipt_text,
            added_request_wire_bytes,
        })
    }

    pub fn append_request_headers(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.headers {
            headers.append(name.clone(), value.clone());
        }
    }

    pub fn validate_request_headers(&self, headers: &HeaderMap) -> bool {
        // HeaderMap normalizes names. Each expected name must occur exactly
        // once, including for empty values; coalesced duplicates fail equality.
        for (name, expected) in &self.headers {
            let mut values = headers.get_all(name).iter();
            if values.next() != Some(expected) || values.next().is_some() {
                return false;
            }
        }
        // Check every synthetic name, including the zero-header arm. Reject
        // malformed indices, gaps, out-of-range names and receipt spoofing.
        for name in headers.keys() {
            let Some(index) = name.as_str().strip_prefix(REQUEST_HEADER_PREFIX) else {
                continue;
            };
            if index.len() != 3 || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            let Ok(index) = index.parse::<usize>() else {
                return false;
            };
            if self.headers.get(index).map(|(expected, _)| expected) != Some(name) {
                return false;
            }
        }
        true
    }

    pub fn receipt(&self) -> &HeaderValue {
        &self.receipt
    }

    pub fn validate_response_headers(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(RECEIPT_HEADER).iter();
        values.next() == Some(&self.receipt) && values.next().is_none()
    }

    pub fn metadata(&self, validated_exchanges: u64) -> HeaderDiagnosticMetadata {
        HeaderDiagnosticMetadata {
            count: self.count,
            value_bytes: self.value_bytes,
            added_request_wire_bytes: self.added_request_wire_bytes,
            expected_receipt: self.receipt_text.clone(),
            validated_receipt: (validated_exchanges > 0).then(|| self.receipt_text.clone()),
            validated_exchanges,
        }
    }
}
