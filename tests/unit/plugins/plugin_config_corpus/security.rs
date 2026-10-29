//! Config contracts for authentication, authorization, and edge-security
//! built-ins (issue #6616 sweep).
//!
//! Flat-config plugins (every nested value is a scalar or a string array) have
//! no nested object to probe and return `None`: `key_auth`, `basic_auth`,
//! `jwt_auth`, `ldap_auth`, `hmac_auth`, `spiffe_identity`, `ip_restriction`,
//! `bot_detection`, `geo_restriction`, and `spec_expose`.

use ferrum_edge::plugins::PluginConfigContract;
use serde_json::json;

/// Self-signed RSA-2048 CA (`CN=Ferrum Corpus CA, O=Ferrum Corpus`), valid
/// 2026-01-01 through 2125-12-31, with `CA:TRUE` and `keyCertSign`. It pins the
/// `mtls_auth` issuer filter and serves as the `soap_ws_security` X.509 / SAML
/// trust anchor. Public material only; no private key exists for it.
const CORPUS_CA_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIDWTCCAkGgAwIBAgIUZoJLApS65s2Vs+2t3zw7WXc1AAgwDQYJKoZIhvcNAQEL\n",
    "BQAwMzEZMBcGA1UEAwwQRmVycnVtIENvcnB1cyBDQTEWMBQGA1UECgwNRmVycnVt\n",
    "IENvcnB1czAgFw0yNjAxMDEwMDAwMDBaGA8yMTI1MTIzMTAwMDAwMFowMzEZMBcG\n",
    "A1UEAwwQRmVycnVtIENvcnB1cyBDQTEWMBQGA1UECgwNRmVycnVtIENvcnB1czCC\n",
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM52pPXISTz0QPfobQgW28YD\n",
    "7UiEvW/kwdlb3KP5msNIxxHuAzqvyD7CeX8yUAtTC7g6GTEgz0mz1jVIbSCJR2Jn\n",
    "vvnfTjdlBKDFS6OMnQJ8vvxlnohPS9Mj6735BbrhasdXbRcwRwKI9ss9n3VAUNCw\n",
    "VsOcCQlsK2SWot/raMkOYuqpr+DNI9YbJ1loEcIvgF+PqBrxX4/OAISWEEozhATA\n",
    "rYT92mVVnyiqV3+qHsUrLUoOJJVNO4eEBmU6DKP/93GotvNCLA/c2pf+M2XppDzM\n",
    "H8BjVAfud6zL4WxGEkZdMU1TZfU7yc3MHBZpPxmRiVPYND1vMloIntKZdd0wVJsC\n",
    "AwEAAaNjMGEwHQYDVR0OBBYEFE/tix9d7zNgHGqHag3Glw9vOozlMB8GA1UdIwQY\n",
    "MBaAFE/tix9d7zNgHGqHag3Glw9vOozlMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n",
    "AQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQA/FukxrNaZ5eKAqtOnLPoMLNo+\n",
    "ybzXu30HXxokL1u7a55Gvi1WuyynlEqL4E4MwyPrcjTB0BT/CcMBO8nXvJJ3RyBf\n",
    "MKRjmm/j2QtlMh6V0ULFEFom3RFl7bWnxByqL6bfGxuzS8yDQwT12aXWVcDKlGHF\n",
    "J4m47NE6qBEZD8mlW3kpMV6vq+ByascOU2TosgMylo7g3WGIcU/Dcwj3mjGEeAWQ\n",
    "GFlwxCI5pNx2zDWyJCKqu5m0nKTAhMIDISqgfHN8goB7RjsNHDF3/daGrsCZYqlB\n",
    "dcCztgnjR4XX5X9bwINzaP2CsSEoy4jUeo5LOwmdMbKgeyizafqgKYsY6WI7\n",
    "-----END CERTIFICATE-----\n",
);

pub(super) fn contract(name: &str) -> Option<PluginConfigContract> {
    Some(match name {
        "jwks_auth" => PluginConfigContract::closed(vec![json!({
            "claim_headers": { "sub": "x-jwt-subject" },
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": { "keys": [] },
                "from_headers": [{ "name": "x-jwt-assertion", "prefix": "Bearer " }],
                "claim_headers": { "tenant": "x-jwt-tenant" },
                "output_claim_headers": [{ "claim": "email", "header": "x-jwt-email" }]
            }]
        })])
        // Keys are operator-chosen JWT claim paths mapped to header names.
        .with_free_form_objects(&["claim_headers", "providers[].claim_headers"])
        // An inline RFC 7517 JWK Set: a foreign document whose JWK members
        // are an open standard set, deserialized leniently by the key store.
        .with_opaque_documents(&["providers[].jwks"]),
        "oauth2_introspection" => PluginConfigContract::closed(vec![json!({
            "providers": [{
                "introspection_endpoint": "http://127.0.0.1:9/introspect",
                "client_auth": {
                    "method": "client_secret_basic",
                    "client_id": "ferrum-gateway",
                    "client_secret": "corpus-introspection-secret"
                },
                "from_headers": [{ "name": "x-access-token", "prefix": "Token " }],
                "claim_headers": { "sub": "x-introspected-subject" }
            }]
        })])
        // Keys are operator-chosen introspection claim paths.
        .with_free_form_objects(&["providers[].claim_headers"]),
        "oidc_relying_party" => PluginConfigContract::closed(vec![json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
                "client_id": "ferrum-gateway",
                "client_auth": { "method": "client_secret_post", "client_secret": "secret" },
                "scopes": ["openid", "profile"],
                "redirect_uri": "https://app.example.com/oauth/callback",
                "callback_path": "/oauth/callback",
                "logout_path": "/oauth/logout",
                "claim_headers": { "email": "x-oidc-email" },
                "authorization_params": { "prompt": "login" }
            }],
            "session": {
                "store": "cookie",
                "encryption_secret": "9f3a7c1e5b2d8406a1c9e7f3b5d20486",
                "same_site": "lax",
                "ttl_secs": 3600
            },
            "behavior": {
                "trusted_redirect_hosts": ["app.example.com"],
                "refresh_skew_secs": 30
            }
        })])
        .with_free_form_objects(&[
            // Keys are operator-chosen ID-token / userinfo claim paths.
            "providers[].claim_headers",
            // Keys are extension authorization-request parameter names sent
            // to the identity provider (reserved OAuth names are refused).
            "providers[].authorization_params",
        ]),
        "soap_ws_security" => PluginConfigContract::closed(vec![
            json!({
                "content_type": { "mode": "strict", "allow_mtom": false },
                "timestamp": { "require": true, "require_expires": false },
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordDigest",
                    "credentials": [{ "username": "alice", "password": "corpus-soap-password" }]
                },
                "x509_signature": { "enabled": false },
                "saml": { "enabled": false },
                "nonce": { "replay_scope": "process" }
            }),
            json!({
                "require_mechanisms": "all",
                "timestamp": { "require": true },
                "x509_signature": {
                    "enabled": true,
                    "trusted_certs": [CORPUS_CA_PEM],
                    "allowed_algorithms": ["rsa-sha256"],
                    "allowed_digest_algorithms": ["sha256"],
                    "require_signed_timestamp": true
                },
                "saml": {
                    "enabled": true,
                    "trusted_issuers": ["https://idp.example.com"],
                    "trusted_signing_certs": [CORPUS_CA_PEM],
                    "allowed_signature_algorithms": ["rsa-sha256"],
                    "allowed_digest_algorithms": ["sha256"],
                    "audience": "https://service.example.com",
                    "recipient": "https://service.example.com/ws"
                },
                "nonce": { "replay_scope": "process" }
            }),
        ]),
        "waf" => PluginConfigContract::closed(vec![json!({
            "mode": "monitor",
            "category_modes": { "rfi": "enforce" },
            "rule_modes": { "corpus-header-rule": "monitor" },
            "rule_overrides": {
                "corpus-header-rule": {
                    "severity": "critical",
                    "score": 5,
                    "conditions": { "paths": ["/api/*"], "headers": { "x-env": "prod" } },
                    "exclude": { "headers": ["x-corpus-ignored"] }
                }
            },
            "custom_rules": [{
                "id": "corpus-header-rule",
                "category": "custom",
                "severity": "high",
                "target": { "type": "header_values", "names": ["x-corpus-probe"] },
                "match_kind": "contains",
                "pattern": "attack-marker",
                "conditions": {
                    "paths": ["/api/*"],
                    "methods": ["POST"],
                    "headers": { "x-tenant": "corp" },
                    "consumers": ["alice"]
                }
            }],
            "scoring": {
                "enabled": true,
                "block_threshold": 7,
                "weights": { "high": 5, "critical": 10 }
            },
            "global_exemptions": {
                "paths": ["/health"],
                "methods": ["GET"],
                "match": "all",
                "header_present": { "x-waf-trusted-hop": "0123456789abcdef0123" }
            },
            "stream": {
                "inspect_tcp": true,
                "signatures": [{
                    "id": "corpus-stream-sig",
                    "pattern": "EVIL",
                    "severity": "high",
                    "action": "monitor"
                }]
            }
        })])
        .with_free_form_objects(&[
            // Keys are operator-chosen request header names to match.
            "custom_rules[].conditions.headers",
            "rule_overrides.*.conditions.headers",
            // Keys are operator-chosen trusted-hop header names.
            "global_exemptions.header_present",
        ]),
        "cors" => PluginConfigContract::closed(vec![json!({
            "allowed_origins": [
                { "exact": "https://app.example.com" },
                { "prefix": "https://app." }
            ]
        })]),
        "security_headers" => PluginConfigContract::closed(vec![json!({
            "hsts": { "max_age": 63072000, "include_subdomains": true, "preload": true },
            "set": { "cross-origin-opener-policy": "same-origin" }
        })])
        // Keys are operator-chosen response header names.
        .with_free_form_objects(&["set"]),
        "access_control" => PluginConfigContract::closed(vec![json!({
            "allowed_external_identities": [
                { "identity": "alice@example.com", "mechanism": "jwks_auth" }
            ],
            "disallowed_external_identities": [{ "identity": "mallory@example.com" }]
        })]),
        "mtls_auth" => PluginConfigContract::closed(vec![json!({
            "allowed_issuers": [{
                "cn": "Ferrum Corpus CA",
                "o": "Ferrum Corpus",
                "ca_certificate_pem": CORPUS_CA_PEM
            }]
        })]),
        "opa" => PluginConfigContract::closed(vec![json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": "ferrum/authz/allow",
            "headers": { "x-opa-tenant": "edge" },
            "deny_headers": { "x-deny-reason": "policy" },
            "fail_closed_headers": { "retry-after": "5" }
        })])
        // Keys are operator-chosen header names (decision request, deny
        // response, and fail-closed response headers).
        .with_free_form_objects(&["headers", "deny_headers", "fail_closed_headers"]),
        _ => return None,
    })
}
