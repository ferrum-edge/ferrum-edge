//! `CertSource::to_config_value` re-renders a parsed provider URI (exports,
//! admin output, pool keys, the subscription digest). Decoded option values
//! must round-trip through the form-urlencoded option parser, and ordinary
//! values must keep their configured spelling.

use std::collections::BTreeMap;

use ferrum_edge::tls::source::{CertSource, MaterialKind};

fn options(source: &CertSource) -> BTreeMap<String, String> {
    match source {
        CertSource::Uri(uri) => uri.options.clone(),
        _ => panic!("expected a URI source"),
    }
}

#[test]
fn option_values_with_delimiters_round_trip() {
    let source = CertSource::parse(
        "vault://secret/data/gateway/tls?field=a%26b%3Dc%2Bd%25e%23f%20g&kind=cert",
        MaterialKind::Cert,
    );
    let decoded = options(&source);
    assert_eq!(
        decoded.get("field").map(String::as_str),
        Some("a&b=c+d%e#f g")
    );

    let rendered = source.to_config_value();
    let reparsed = CertSource::parse(rendered.clone(), MaterialKind::Cert);
    assert_eq!(options(&reparsed), decoded, "rendered options must round-trip");
    assert_eq!(reparsed.to_config_value(), rendered, "rendering is stable");
}

#[test]
fn distinct_option_maps_render_to_distinct_values() {
    let joined = CertSource::parse("vault://secret/tls?a=1%26b%3D2", MaterialKind::Cert);
    let split = CertSource::parse("vault://secret/tls?a=1&b=2", MaterialKind::Cert);
    assert_ne!(options(&joined), options(&split));
    assert_ne!(
        joined.to_config_value(),
        split.to_config_value(),
        "two option maps must not collapse onto one pool key"
    );
    assert_ne!(joined.pool_key_component(), split.pool_key_component());
}

#[test]
fn ordinary_option_values_keep_their_spelling() {
    let value = "aws://arn:aws:secretsmanager:us-east-1:123456789012:secret:tls/cert?poll=60s&version=v1/2:3";
    let source = CertSource::parse(value, MaterialKind::Cert);
    assert_eq!(source.to_config_value(), value);
}
