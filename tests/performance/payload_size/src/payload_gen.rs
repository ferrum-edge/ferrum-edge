//! Payload generators for realistic content-type-specific test data.
//!
//! Each generator creates a payload of approximately the requested size with
//! structurally valid content for the given content type.

use rand::Rng;

/// Supported content types for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    Json,
    Xml,
    FormUrlEncoded,
    MultipartFormData,
    OctetStream,
    Grpc,
    Sse,
    Ndjson,
    SoapXml,
    Graphql,
    WsBinary,
    TcpBinary,
    UdpBinary,
}

impl ContentType {
    /// Parse from CLI argument string.
    pub fn from_arg(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "xml" => Some(Self::Xml),
            "form-urlencoded" => Some(Self::FormUrlEncoded),
            "multipart" => Some(Self::MultipartFormData),
            "octet-stream" => Some(Self::OctetStream),
            "grpc" => Some(Self::Grpc),
            "sse" => Some(Self::Sse),
            "ndjson" => Some(Self::Ndjson),
            "soap-xml" => Some(Self::SoapXml),
            "graphql" => Some(Self::Graphql),
            "ws-binary" => Some(Self::WsBinary),
            "tcp" => Some(Self::TcpBinary),
            "udp" => Some(Self::UdpBinary),
            _ => None,
        }
    }

    /// The HTTP Content-Type header value for this type.
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::FormUrlEncoded => "application/x-www-form-urlencoded",
            Self::MultipartFormData => {
                "multipart/form-data; boundary=----PayloadBenchBoundary7MA4YWxkTrZu0gW"
            }
            Self::OctetStream => "application/octet-stream",
            Self::Grpc => "application/grpc",
            Self::Sse => "text/event-stream",
            Self::Ndjson => "application/x-ndjson",
            Self::SoapXml => "application/soap+xml; charset=utf-8",
            Self::Graphql => "application/json", // GraphQL uses JSON encoding
            Self::WsBinary | Self::TcpBinary | Self::UdpBinary => "application/octet-stream",
        }
    }

    /// The display name for reports.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::FormUrlEncoded => "application/x-www-form-urlencoded",
            Self::MultipartFormData => "multipart/form-data",
            Self::OctetStream => "application/octet-stream",
            Self::Grpc => "application/grpc",
            Self::Sse => "text/event-stream",
            Self::Ndjson => "application/x-ndjson",
            Self::SoapXml => "application/soap+xml",
            Self::Graphql => "application/graphql",
            Self::WsBinary => "ws-binary",
            Self::TcpBinary => "tcp-binary",
            Self::UdpBinary => "udp-binary",
        }
    }

    /// The transport protocol this content type uses.
    pub fn transport(&self) -> Transport {
        match self {
            Self::Grpc => Transport::Grpc,
            Self::WsBinary => Transport::WebSocket,
            Self::TcpBinary => Transport::Tcp,
            Self::UdpBinary => Transport::Udp,
            _ => Transport::Http,
        }
    }

    /// The tier for this content type (1, 2, or 3).
    pub fn tier(&self) -> u8 {
        match self {
            Self::Json | Self::Sse | Self::Grpc | Self::OctetStream => 1,
            Self::MultipartFormData | Self::FormUrlEncoded => 2,
            Self::Xml | Self::SoapXml | Self::Graphql => 3,
            Self::Ndjson | Self::WsBinary | Self::TcpBinary | Self::UdpBinary => 1,
        }
    }

    /// All content types in tier order.
    pub fn all() -> &'static [Self] {
        &[
            // Tier 1
            Self::Json,
            Self::OctetStream,
            Self::Ndjson,
            Self::Grpc,
            Self::WsBinary,
            Self::TcpBinary,
            Self::UdpBinary,
            // Tier 2
            Self::MultipartFormData,
            Self::FormUrlEncoded,
            // Tier 3
            Self::Xml,
            Self::SoapXml,
            Self::Graphql,
        ]
    }

    /// Content types for a given tier.
    pub fn for_tier(tier: u8) -> Vec<Self> {
        Self::all()
            .iter()
            .filter(|ct| ct.tier() == tier)
            .copied()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Http3,
    Grpc,
    WebSocket,
    Tcp,
    Udp,
}

/// Parse a human-readable size string into bytes.
pub fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim().to_lowercase();
    if let Some(n) = s.strip_suffix("mb") {
        n.trim().parse::<usize>().ok().map(|n| n * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("kb") {
        n.trim().parse::<usize>().ok().map(|n| n * 1024)
    } else {
        s.parse::<usize>().ok()
    }
}

/// Format bytes as a human-readable size string.
pub fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{}MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

/// All benchmark sizes in bytes.
pub const SIZES: &[usize] = &[
    10 * 1024,       // 10 KB
    50 * 1024,       // 50 KB
    100 * 1024,      // 100 KB
    1024 * 1024,     // 1 MB
    5 * 1024 * 1024, // 5 MB
    9 * 1024 * 1024, // 9 MB
];

/// Generate a payload of approximately `target_size` bytes for the given content type.
pub fn generate_payload(content_type: ContentType, target_size: usize) -> Vec<u8> {
    match content_type {
        ContentType::Json => generate_json(target_size),
        ContentType::Xml => generate_xml(target_size),
        ContentType::FormUrlEncoded => generate_form_urlencoded(target_size),
        ContentType::MultipartFormData => generate_multipart(target_size),
        ContentType::OctetStream
        | ContentType::WsBinary
        | ContentType::TcpBinary
        | ContentType::UdpBinary => generate_binary(target_size),
        ContentType::Grpc => generate_binary(target_size), // raw bytes, protobuf wrapping done by tonic
        ContentType::Sse => generate_sse(target_size),
        ContentType::Ndjson => generate_ndjson(target_size),
        ContentType::SoapXml => generate_soap_xml(target_size),
        ContentType::Graphql => generate_graphql(target_size),
    }
}

/// Measure the exact serialized length of `count` empty-padding records.
///
/// Record IDs widen as they grow (1, 2, … digits), so a fixed per-record
/// estimate based on record 0 drifts and previously forced a final
/// `truncate` that cut closing syntax. Measuring the real empty records
/// lets the caller distribute the remaining bytes as in-field padding and
/// hit the target size exactly without truncating serialized syntax.
fn empty_records_len(count: usize, mut format_record: impl FnMut(usize, &str) -> String) -> usize {
    (0..count).map(|i| format_record(i, "").len()).sum()
}

/// Generate a realistic JSON payload.
/// Uses a metadata wrapper + padding data fields sized to hit the exact target.
fn generate_json(target_size: usize) -> Vec<u8> {
    // Template: {"metadata":{...},"records":[<RECORD>,...]}
    // The overhead of the wrapper is fixed; we fill the "data" fields to hit target_size.
    let prefix = r#"{"metadata":{"type":"benchmark","version":"1.0","timestamp":"2024-01-01T00:00:00Z","tags":["perf","test","payload-size"]},"records":["#;
    let suffix = "]}";
    let format_record = |i: usize, padding: &str| {
        format!(
            r#"{{"id":{i},"name":"user_{i}","email":"user{i}@bench.example.com","role":"senior_engineer","active":true,"score":98.5,"department":"platform","data":"{padding}"}}"#
        )
    };

    let fixed_overhead = prefix.len() + suffix.len();
    let available = target_size.saturating_sub(fixed_overhead);
    let mut num_records = (available / 512).clamp(1, 5000);
    // Shrink the record count until the empty records (plus commas) fit.
    let mut base_len = fixed_overhead
        + empty_records_len(num_records, &format_record)
        + num_records.saturating_sub(1);
    while base_len > target_size && num_records > 1 {
        num_records -= 1;
        base_len = fixed_overhead
            + empty_records_len(num_records, &format_record)
            + num_records.saturating_sub(1);
    }

    let total_padding = target_size.saturating_sub(base_len);
    let padding_per_record = total_padding / num_records;
    let padding_remainder = total_padding % num_records;

    let mut buf = String::with_capacity(target_size + 512);
    buf.push_str(prefix);
    for i in 0..num_records {
        if i > 0 {
            buf.push(',');
        }
        let extra = usize::from(i < padding_remainder);
        buf.push_str(&format_record(i, &"A".repeat(padding_per_record + extra)));
    }
    buf.push_str(suffix);
    buf.into_bytes()
}

/// Generate a realistic XML payload.
fn generate_xml(target_size: usize) -> Vec<u8> {
    let header = r#"<?xml version="1.0" encoding="UTF-8"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#;
    let footer = "</root>";
    let overhead = header.len() + footer.len();
    let available = target_size.saturating_sub(overhead);
    let format_record = |i: usize, padding: &str| {
        format!(
            r#"<record id="{i}"><name>user_{i}</name><email>user{i}@example.com</email><role>engineer</role><active>true</active><score>98.5</score><data>{padding}</data></record>"#
        )
    };

    let mut records_count = (available / 512).clamp(1, 10000);
    let mut base_len = overhead + empty_records_len(records_count, &format_record);
    while base_len > target_size && records_count > 1 {
        records_count -= 1;
        base_len = overhead + empty_records_len(records_count, &format_record);
    }
    let total_padding = target_size.saturating_sub(base_len);
    let padding_per_record = total_padding / records_count;
    let padding_remainder = total_padding % records_count;

    let mut buf = String::with_capacity(target_size + 1024);
    buf.push_str(header);
    for i in 0..records_count {
        let extra = usize::from(i < padding_remainder);
        buf.push_str(&format_record(i, &"A".repeat(padding_per_record + extra)));
    }
    buf.push_str(footer);
    buf.into_bytes()
}

/// Generate a form-urlencoded payload.
fn generate_form_urlencoded(target_size: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_size + 128);
    buf.push_str("username=testuser&email=test%40example.com&action=submit");

    // Add a large data field
    let remaining = target_size.saturating_sub(buf.len() + 6); // &data=
    if remaining > 0 {
        buf.push_str("&data=");
        // URL-safe characters that don't need encoding
        let chunk = "abcdefghijklmnopqrstuvwxyz0123456789";
        let full_chunks = remaining / chunk.len();
        let remainder = remaining % chunk.len();
        for _ in 0..full_chunks {
            buf.push_str(chunk);
        }
        buf.push_str(&chunk[..remainder]);
    }

    // Exact by construction for targets above the fixed prefix; never
    // truncate, which could cut a %XX escape in the fixed pairs.
    buf.into_bytes()
}

/// Generate a multipart/form-data payload.
fn generate_multipart(target_size: usize) -> Vec<u8> {
    let boundary = "----PayloadBenchBoundary7MA4YWxkTrZu0gW";
    let header_part = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{{\"type\":\"benchmark\",\"version\":\"1.0\"}}\r\n"
    );
    let file_header = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    let footer = format!("\r\n--{boundary}--\r\n");

    let overhead = header_part.len() + file_header.len() + footer.len();
    let file_size = target_size.saturating_sub(overhead);

    let mut buf = Vec::with_capacity(target_size + 128);
    buf.extend_from_slice(header_part.as_bytes());
    buf.extend_from_slice(file_header.as_bytes());

    // Binary file content
    let mut rng = rand::thread_rng();
    let mut file_data = vec![0u8; file_size];
    rng.fill(&mut file_data[..]);
    buf.extend_from_slice(&file_data);

    buf.extend_from_slice(footer.as_bytes());
    // Exact by construction when target_size >= overhead; for smaller
    // targets return the smallest valid multipart body rather than
    // truncating the closing boundary.
    buf
}

/// Generate random binary data.
fn generate_binary(target_size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; target_size];
    rng.fill(&mut data[..]);
    data
}

/// Generate SSE-formatted events.
///
/// Only whole events are emitted: the final event's `payload` padding is
/// sized to fill the remaining budget, and generation stops short of the
/// target when fewer bytes remain than one empty event needs. The result
/// is therefore approximate in size (the module contract) but never cuts
/// an event or its terminating blank line.
fn generate_sse(target_size: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_size + 1024);
    let mut id = 0u64;
    loop {
        let empty_event =
            format!("id: {id}\nevent: message\ndata: {{\"seq\":{id},\"payload\":\"\"}}\n\n");
        let remaining = target_size.saturating_sub(buf.len());
        if remaining < empty_event.len() {
            break;
        }
        let padding_len = remaining.min(4096).saturating_sub(empty_event.len());
        let padding = "A".repeat(padding_len);
        buf.push_str(&format!(
            "id: {id}\nevent: message\ndata: {{\"seq\":{id},\"payload\":\"{padding}\"}}\n\n"
        ));
        id += 1;
    }
    buf.into_bytes()
}

/// Generate newline-delimited JSON.
///
/// Only whole records are emitted, each terminated by `\n`: the final
/// record's `data` padding is sized to fill the remaining budget, and
/// generation stops short of the target when fewer bytes remain than one
/// empty record (plus its newline) needs.
fn generate_ndjson(target_size: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_size + 1024);
    let mut id = 0u64;
    loop {
        let empty_record = format!(
            r#"{{"id":{id},"timestamp":"2024-01-01T00:00:00Z","event":"benchmark","data":""}}"#
        );
        let min_record_len = empty_record.len() + 1; // + '\n'
        let remaining = target_size.saturating_sub(buf.len());
        if remaining < min_record_len {
            break;
        }
        let padding_len = remaining.min(1024).saturating_sub(min_record_len);
        let padding = "A".repeat(padding_len);
        buf.push_str(&format!(
            r#"{{"id":{id},"timestamp":"2024-01-01T00:00:00Z","event":"benchmark","data":"{padding}"}}"#
        ));
        buf.push('\n');
        id += 1;
    }
    buf.into_bytes()
}

/// Generate a SOAP+XML envelope.
fn generate_soap_xml(target_size: usize) -> Vec<u8> {
    let header = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ws="http://example.com/ws">
  <soap:Header>
    <ws:AuthToken>benchmark-token-12345</ws:AuthToken>
    <ws:RequestId>req-payload-bench-001</ws:RequestId>
  </soap:Header>
  <soap:Body>
    <ws:ProcessDataRequest>"#;
    let footer = r#"
    </ws:ProcessDataRequest>
  </soap:Body>
</soap:Envelope>"#;

    let overhead = header.len() + footer.len();
    let available = target_size.saturating_sub(overhead);
    let format_record = |i: usize, padding: &str| {
        format!(r#"<ws:DataItem id="{i}"><ws:Value>{padding}</ws:Value></ws:DataItem>"#)
    };

    let mut records_count = (available / 256).clamp(1, 10000);
    let mut base_len = overhead + empty_records_len(records_count, &format_record);
    while base_len > target_size && records_count > 1 {
        records_count -= 1;
        base_len = overhead + empty_records_len(records_count, &format_record);
    }
    let total_padding = target_size.saturating_sub(base_len);
    let padding_per_record = total_padding / records_count;
    let padding_remainder = total_padding % records_count;

    let mut buf = String::with_capacity(target_size + 1024);
    buf.push_str(header);
    for i in 0..records_count {
        let extra = usize::from(i < padding_remainder);
        buf.push_str(&format_record(i, &"A".repeat(padding_per_record + extra)));
    }
    buf.push_str(footer);
    buf.into_bytes()
}

/// Generate a GraphQL request payload (JSON-encoded).
fn generate_graphql(target_size: usize) -> Vec<u8> {
    let query = r#"mutation ProcessBatchData($input: BatchDataInput!) { processBatchData(input: $input) { success processedCount errors { code message } } }"#;
    let escaped_query = query.replace('"', r#"\""#);
    // Build the wrapper to measure exact overhead. The prefix opens three
    // objects (root, "variables", "input") and one array ("items"), so the
    // suffix closes the array and exactly those three objects.
    let prefix = format!(r#"{{"query":"{escaped_query}","variables":{{"input":{{"items":["#);
    let suffix = "]}}}";
    let overhead = prefix.len() + suffix.len();
    let available = target_size.saturating_sub(overhead);
    let format_record =
        |i: usize, padding: &str| format!(r#"{{"id":{i},"type":"benchmark","data":"{padding}"}}"#);

    let mut records_count = (available / 256).clamp(1, 10000);
    let mut base_len = overhead
        + empty_records_len(records_count, &format_record)
        + records_count.saturating_sub(1);
    while base_len > target_size && records_count > 1 {
        records_count -= 1;
        base_len = overhead
            + empty_records_len(records_count, &format_record)
            + records_count.saturating_sub(1);
    }
    let total_padding = target_size.saturating_sub(base_len);
    let padding_per_record = total_padding / records_count;
    let padding_remainder = total_padding % records_count;

    let mut buf = String::with_capacity(target_size + 512);
    buf.push_str(&prefix);
    for i in 0..records_count {
        if i > 0 {
            buf.push(',');
        }
        let extra = usize::from(i < padding_remainder);
        buf.push_str(&format_record(i, &"A".repeat(padding_per_record + extra)));
    }
    buf.push_str(suffix);
    buf.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_sizes() {
        for &size in SIZES {
            for ct in ContentType::all() {
                if *ct == ContentType::Grpc {
                    continue; // gRPC payload is wrapped by protobuf
                }
                let payload = generate_payload(*ct, size);
                // Allow ±5% tolerance
                let min = (size as f64 * 0.90) as usize;
                let max = size + 1024;
                assert!(
                    payload.len() >= min && payload.len() <= max,
                    "{:?} at {}: got {} bytes (expected {}-{})",
                    ct,
                    format_size(size),
                    payload.len(),
                    min,
                    max,
                );
            }
        }
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("10kb"), Some(10 * 1024));
        assert_eq!(parse_size("1mb"), Some(1024 * 1024));
        assert_eq!(parse_size("9MB"), Some(9 * 1024 * 1024));
        assert_eq!(parse_size("1024"), Some(1024));
    }
}
