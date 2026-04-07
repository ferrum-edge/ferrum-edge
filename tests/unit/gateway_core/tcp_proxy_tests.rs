use ferrum_edge::_test_support::classify_stream_error;
use ferrum_edge::retry::ErrorClass;

#[test]
fn test_classify_stream_error_preserves_tls_failures() {
    let error =
        anyhow::anyhow!("Backend TLS handshake failed to 127.0.0.1:443: invalid peer certificate");
    assert_eq!(classify_stream_error(&error), ErrorClass::TlsError);
}

#[test]
fn test_classify_stream_error_preserves_dns_failures() {
    let error = anyhow::anyhow!("DNS resolution failed for backend.local: no record found");
    assert_eq!(classify_stream_error(&error), ErrorClass::DnsLookupError);
}
