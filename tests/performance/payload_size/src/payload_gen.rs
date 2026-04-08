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
            Self::MultipartFormData => "multipart/form-data; boundary=----PayloadBenchBoundary7MA4YWxkTrZu0gW",
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
    10 * 1024,      // 10 KB
    50 * 1024,      // 50 KB
    100 * 1024,     // 100 KB
    1024 * 1024,    // 1 MB
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
        ContentType::OctetStream | ContentType::WsBinary | ContentType::TcpBinary
        | ContentType::UdpBinary => generate_binary(target_size),
        ContentType::Grpc => generate_binary(target_size), // raw bytes, protobuf wrapping done by tonic
        ContentType::Sse => generate_sse(target_size),
        ContentType::Ndjson => generate_ndjson(target_size),
        ContentType::SoapXml => generate_soap_xml(target_size),
        ContentType::Graphql => generate_graphql(target_size),
    }
}

/// Generate a realistic JSON payload.
/// Uses a metadata wrapper + padding data field sized to hit the exact target.
fn generate_json(target_size: usize) -> Vec<u8> {
    // Template: {"metadata":{"type":"benchmark","version":"1.0","records":10},"data":"<PADDING>"}
    // The overhead of the wrapper is fixed; we fill the "data" field to hit target_size.
    let prefix = r#"{"metadata":{"type":"benchmark","version":"1.0","timestamp":"2024-01-01T00:00:00Z","tags":["perf","test","payload-size"]},"records":["#;
    let suffix = "]}";
    let record_base = r#"{"id":0,"name":"user_0","email":"user0@bench.example.com","role":"senior_engineer","active":true,"score":98.5,"department":"platform","data":""}"#;
    let record_base_len = record_base.len(); // ~150 bytes

    let fixed_overhead = prefix.len() + suffix.len();
    let available = target_size.saturating_sub(fixed_overhead);

    // For small payloads, use a single record with a large data field
    if available < record_base_len * 3 {
        let data_size = target_size.saturating_sub(fixed_overhead + record_base_len);
        let padding = "A".repeat(data_size);
        let result = format!(
            r#"{prefix}{{"id":0,"name":"user_0","email":"user0@bench.example.com","role":"senior_engineer","active":true,"score":98.5,"department":"platform","data":"{padding}"}}{suffix}"#
        );
        return result.into_bytes();
    }

    // For larger payloads, use multiple records each with padding
    let num_records = (available / 512).clamp(1, 5000);
    // Estimate: each record is record_base_len + data + comma
    let per_record_overhead = record_base_len + 1; // +1 for comma
    let total_data = available.saturating_sub(num_records * per_record_overhead);
    let data_per_record = total_data / num_records;
    let padding_chunk = "A".repeat(data_per_record);

    let mut buf = String::with_capacity(target_size + 512);
    buf.push_str(prefix);
    for i in 0..num_records {
        if i > 0 {
            buf.push(',');
        }
        buf.push_str(&format!(
            r#"{{"id":{i},"name":"user_{i}","email":"user{i}@bench.example.com","role":"senior_engineer","active":true,"score":98.5,"department":"platform","data":"{padding_chunk}"}}"#
        ));
    }
    buf.push_str(suffix);

    let mut bytes = buf.into_bytes();
    // Pad if slightly short
    while bytes.len() < target_size {
        // Insert padding before the closing ]}
        let insert_pos = bytes.len() - suffix.len();
        bytes.insert(insert_pos, b'A');
    }
    bytes.truncate(target_size);
    bytes
}

/// Generate a realistic XML payload.
fn generate_xml(target_size: usize) -> Vec<u8> {
    let header = r#"<?xml version="1.0" encoding="UTF-8"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#;
    let footer = "</root>";
    let overhead = header.len() + footer.len();
    let available = target_size.saturating_sub(overhead);

    let record_base = r#"<record id="0"><name>user_0</name><email>user0@example.com</email><role>engineer</role><active>true</active><score>98.5</score><data></data></record>"#;
    let record_base_len = record_base.len();
    let records_count = (available / 512).clamp(1, 10000);
    let total_data = available.saturating_sub(records_count * record_base_len);
    let data_per_record = total_data / records_count;
    let padding_chunk = "A".repeat(data_per_record);

    let mut buf = String::with_capacity(target_size + 1024);
    buf.push_str(header);
    for i in 0..records_count {
        buf.push_str(&format!(
            r#"<record id="{i}"><name>user_{i}</name><email>user{i}@example.com</email><role>engineer</role><active>true</active><score>98.5</score><data>{padding_chunk}</data></record>"#
        ));
    }
    buf.push_str(footer);

    let mut bytes = buf.into_bytes();
    // Pad if slightly short
    while bytes.len() < target_size {
        let insert_pos = bytes.len() - footer.len();
        bytes.insert(insert_pos, b'A');
    }
    bytes.truncate(target_size);
    bytes
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

    buf.truncate(target_size);
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
    buf.truncate(target_size);
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
fn generate_sse(target_size: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_size + 1024);
    let mut id = 0u64;
    while buf.len() < target_size {
        let remaining = target_size.saturating_sub(buf.len());
        // Each event: "id: N\nevent: message\ndata: {...}\n\n" ~= overhead + data
        let event_overhead = 50;
        let data_size = remaining.min(4096).saturating_sub(event_overhead);
        let padding = "A".repeat(data_size);
        buf.push_str(&format!(
            "id: {id}\nevent: message\ndata: {{\"seq\":{id},\"payload\":\"{padding}\"}}\n\n"
        ));
        id += 1;
    }
    buf.truncate(target_size);
    buf.into_bytes()
}

/// Generate newline-delimited JSON.
fn generate_ndjson(target_size: usize) -> Vec<u8> {
    let mut buf = String::with_capacity(target_size + 1024);
    let mut id = 0u64;
    while buf.len() < target_size {
        let remaining = target_size.saturating_sub(buf.len());
        let record_overhead = 80;
        let data_size = remaining.min(1024).saturating_sub(record_overhead);
        let padding = "A".repeat(data_size);
        buf.push_str(&format!(
            r#"{{"id":{id},"timestamp":"2024-01-01T00:00:00Z","event":"benchmark","data":"{padding}"}}"#
        ));
        buf.push('\n');
        id += 1;
    }
    buf.truncate(target_size);
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

    let record_base = r#"<ws:DataItem id="0"><ws:Value></ws:Value></ws:DataItem>"#;
    let record_base_len = record_base.len();
    let records_count = (available / 256).clamp(1, 10000);
    let total_data = available.saturating_sub(records_count * record_base_len);
    let data_per_record = total_data / records_count;
    let padding_chunk = "A".repeat(data_per_record);

    let mut buf = String::with_capacity(target_size + 1024);
    buf.push_str(header);
    for i in 0..records_count {
        buf.push_str(&format!(
            r#"<ws:DataItem id="{i}"><ws:Value>{padding_chunk}</ws:Value></ws:DataItem>"#
        ));
    }
    buf.push_str(footer);

    let mut bytes = buf.into_bytes();
    while bytes.len() < target_size {
        let insert_pos = bytes.len() - footer.len();
        bytes.insert(insert_pos, b'A');
    }
    bytes.truncate(target_size);
    bytes
}

/// Generate a GraphQL request payload (JSON-encoded).
fn generate_graphql(target_size: usize) -> Vec<u8> {
    let query = r#"mutation ProcessBatchData($input: BatchDataInput!) { processBatchData(input: $input) { success processedCount errors { code message } } }"#;
    let escaped_query = query.replace('"', r#"\""#);
    // Build the wrapper to measure exact overhead
    let prefix = format!(
        r#"{{"query":"{escaped_query}","variables":{{"input":{{"items":["#
    );
    let suffix = "]}}}}";
    let overhead = prefix.len() + suffix.len();
    let available = target_size.saturating_sub(overhead);

    let record_base = r#"{"id":0,"type":"benchmark","data":""}"#;
    let record_base_len = record_base.len() + 1; // +1 for comma
    let records_count = (available / 256).clamp(1, 10000);
    let total_data = available.saturating_sub(records_count * record_base_len);
    let data_per_record = total_data / records_count;
    let padding_chunk = "A".repeat(data_per_record);

    let mut buf = String::with_capacity(target_size + 512);
    buf.push_str(&prefix);
    for i in 0..records_count {
        if i > 0 {
            buf.push(',');
        }
        buf.push_str(&format!(
            r#"{{"id":{i},"type":"benchmark","data":"{padding_chunk}"}}"#
        ));
    }
    buf.push_str(suffix);

    let mut bytes = buf.into_bytes();
    // Pad if slightly short
    while bytes.len() < target_size {
        let insert_pos = bytes.len() - suffix.len();
        bytes.insert(insert_pos, b'A');
    }
    bytes.truncate(target_size);
    bytes
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
