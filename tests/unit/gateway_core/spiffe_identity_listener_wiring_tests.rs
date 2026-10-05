fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("source section start must exist");
    let tail = &source[start..];
    let end = tail.find(end).expect("source section end must exist");
    &tail[..end]
}

fn compact_whitespace(source: &str) -> String {
    source.split_whitespace().collect()
}

#[test]
fn h1_h2_tls_listener_shares_spiffe_cache_with_request_contexts() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let connection_handler = source_section(
        source,
        "async fn handle_tls_connection(",
        "\nasync fn handle_backend_admission_rejection(",
    );
    let connection_handler = compact_whitespace(connection_handler);

    assert!(
        connection_handler.contains("SpiffeIdentityConnectionCache::new()"),
        "the H1/H2 TLS connection handler must construct a connection-local SPIFFE cache"
    );
    assert!(
        connection_handler
            .contains("peer_spiffe_extraction_cache:peer_spiffe_extraction_cache.clone(),"),
        "every H1/H2 request must receive the shared cache through RequestConnectionMetadata"
    );

    let request_handler = source_section(
        source,
        "async fn handle_proxy_request_inner(",
        "\nfn backend_dispatch_response(",
    );
    assert!(
        compact_whitespace(request_handler).contains(
            "ctx.peer_spiffe_extraction_cache=connection_metadata.peer_spiffe_extraction_cache;"
        ),
        "H1/H2 RequestConnectionMetadata must stamp the shared cache on RequestContext"
    );
}

#[test]
fn h3_connection_shares_spiffe_cache_with_request_contexts() {
    // Issue #2938 moved H3 peer identity (including the SPIFFE extraction
    // cache) into a per-connection ArcSwap snapshot. The cache is allocated
    // only when an established identity is published — never on the
    // pre-handshake / early-data snapshot — and every request stream clones
    // the cache handle from one coherent identity load.
    let identity_source = include_str!("../../../src/http3/peer_identity.rs");
    assert!(
        compact_whitespace(identity_source).contains("SpiffeIdentityConnectionCache::new()"),
        "H3PeerIdentity::established must construct the connection-local SPIFFE cache"
    );

    let source = include_str!("../../../src/http3/server.rs");
    let connection_handler = source_section(
        source,
        "async fn handle_h3_connection(",
        "\n/// Handle a single HTTP/3 request stream.",
    );
    let connection_handler = compact_whitespace(connection_handler);

    assert!(
        connection_handler.contains(
            "letpeer_spiffe_extraction_cache=identity.peer_spiffe_extraction_cache.clone();"
        ),
        "every H3 request task must clone the SPIFFE cache from the identity snapshot"
    );
    let request_call = connection_handler
        .find("handle_h3_request(")
        .expect("the H3 connection handler must call handle_h3_request");
    assert!(
        connection_handler[request_call..].contains("peer_spiffe_extraction_cache,"),
        "handle_h3_request must receive the connection's shared SPIFFE cache"
    );

    let request_handler = source_section(
        source,
        "async fn handle_h3_request(",
        "\npub(crate) async fn run_h3_backend_admission_or_send_reject(",
    );
    assert!(
        compact_whitespace(request_handler)
            .contains("ctx.peer_spiffe_extraction_cache=peer_spiffe_extraction_cache;"),
        "the H3 request handler must stamp the shared cache on RequestContext"
    );
}
