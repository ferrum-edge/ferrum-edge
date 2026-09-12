//! Fail-closed FIPS admission policy.
//!
//! One policy, evaluated identically at every admission point:
//!
//! | Surface | Entry point |
//! |---|---|
//! | `ferrum-edge validate` | [`check_env_config`] + [`check_gateway_config`] |
//! | bootstrap / startup | [`check_env_config`] + [`check_gateway_config`] |
//! | file-mode SIGHUP reload | [`check_gateway_config`] |
//! | database poll apply | [`check_gateway_config`] |
//! | CP publication / DP apply | [`check_gateway_config`] |
//! | CP/DP namespace trust-bundle load | [`is_approved_jwt_algorithm`] |
//! | rustls policy construction | [`check_tls_policy`] |
//! | external secret resolution | [`check_external_secret_sources`] |
//! | PEM certificate / JWKS key load | [`super::keys`] |
//!
//! Every diagnostic is bounded: it names the setting, states the rule, and — for
//! collection-valued settings — reports at most [`MAX_REPORTED_VIOLATIONS`]
//! offending entries followed by a count. Operator-supplied values are echoed
//! only where they are already a fixed, non-secret vocabulary (algorithm names,
//! cipher-suite names, plugin names); secrets, key material, paths, and free-form
//! configuration are never interpolated.
//!
//! When FIPS mode is off every function here returns `Ok(())` without inspecting
//! anything, so ordinary deployments are behaviourally unchanged.

use std::fmt::Write as _;

use crate::config::env_config::{DbTlsMode, EnvConfig, SqlUrlTlsPeerAuth};
use crate::config::types::{BackendScheme, GatewayConfig, PluginConfig};

/// Maximum number of individual offending entries named in one diagnostic.
///
/// A hostile or merely large configuration must not be able to turn a startup
/// failure into an unbounded log record.
pub const MAX_REPORTED_VIOLATIONS: usize = 8;

/// JWT/JWS algorithms Ferrum admits while FIPS mode is enforced.
///
/// HMAC-SHA2 (FIPS 198-1), RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-2, and
/// ECDSA over P-256/P-384 (FIPS 186-5). `none` is always rejected.
///
/// `EdDSA` is deliberately absent: Ed25519 is approved by FIPS 186-5, but it is
/// not part of the algorithm set Ferrum routes through the selected AWS-LC FIPS
/// module implementation, so admitting it would be a claim this build cannot
/// back.
///
/// `ES512` is deliberately absent for the same reason, and it is worth being
/// precise about why, because ECDSA over P-521 *is* an approved FIPS 186-5
/// scheme. The exclusion is about the *implementation contract*, not the
/// algorithm: the `jsonwebtoken` backend this profile selects
/// (`jsonwebtoken/aws_lc_rs`) does not expose a supportable P-521 signing and
/// verification path for JWS, so an `ES512` selection admitted here would
/// either fail at first use or fall through to an implementation outside the
/// selected module. Admitting an algorithm Ferrum cannot actually route is the
/// exact failure mode this allow-list exists to prevent, so it is refused at
/// admission with an actionable diagnostic instead. See `docs/fips.md`
/// §"Deliberately unsupported in FIPS mode".
pub const APPROVED_JWT_ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384",
];

/// Whether a configured JWS algorithm is in Ferrum's FIPS-approved set.
///
/// This helper is public because not every JWT admission surface lives inside
/// [`GatewayConfig`]. In particular, the CP/DP namespace trust bundle is an
/// environment-selected JSON document loaded directly by the control-plane
/// runtime and must apply the identical algorithm policy at its own parser.
pub fn is_approved_jwt_algorithm(algorithm: &str) -> bool {
    APPROVED_JWT_ALGORITHMS
        .iter()
        .any(|approved| approved.eq_ignore_ascii_case(algorithm.trim()))
}

/// Minimum HMAC key length, in bytes, for an approved JWT/JWS MAC key.
///
/// SP 800-107 requires an HMAC key at least as long as the security strength
/// being claimed. Ferrum already enforces 32 characters on admin and CP/DP JWT
/// secrets; FIPS mode applies that same floor to the operator-owned JWT and
/// stored-password MAC keys it admits at the environment boundary.
pub const MIN_HMAC_KEY_BYTES: usize = 32;

/// Plugins whose cryptography is provided by a library outside the selected
/// AWS-LC FIPS module implementation, and which are therefore refused while
/// FIPS mode is enforced.
///
/// `kafka_logging` binds librdkafka, which performs its TLS through OpenSSL
/// rather than through the module Ferrum selected. Ferrum cannot attest to that
/// stack, so it refuses the plugin instead of implying coverage it does not
/// have. See `docs/fips.md` for the supported alternatives
/// (`tcp_logging`/`ws_logging`/`http_logging`, all of which are rustls-based
/// and therefore module-backed).
pub const NON_APPROVED_PLUGINS: &[&str] = &["kafka_logging"];

/// Algorithm selections a plugin may expose that name a non-approved primitive.
///
/// SHA-1 is not an approved hash for a digital signature or a signature-bearing
/// digest (SP 800-131A Rev. 2 disallowed it for signature generation and
/// verification). `soap_ws_security` lets an operator admit `rsa-sha1`
/// signatures and `sha1` reference digests for XML-DSig interoperability; both
/// are refused while FIPS mode is enforced rather than silently computed
/// outside the approved set. The values are Ferrum's own fixed configuration
/// vocabulary, so echoing them in a diagnostic discloses nothing.
const NON_APPROVED_ALGORITHM_SELECTIONS: &[(&str, &[&str], &[&str])] = &[(
    "soap_ws_security",
    &[
        "x509_signature.allowed_algorithms",
        "x509_signature.allowed_digest_algorithms",
        "saml.allowed_signature_algorithms",
        "saml.allowed_digest_algorithms",
    ],
    &["rsa-sha1", "sha1"],
)];

/// Why every DTLS surface is refused while FIPS mode is enforced.
///
/// DTLS is the one transport Ferrum terminates outside rustls: it runs on the
/// vendored `dimpl` stack (`vendor/dimpl-0.6.1-ferrum-patched`). That stack does
/// resolve key agreement, signing, hashing, and record AEAD through `aws-lc-rs`,
/// so those primitives reach the selected module — but it draws its *random*
/// values from the `rand` crate's thread RNG (`src/rng.rs`, `SeededRng`), not
/// from the module DRBG that `crypto/aws_lc_rs/random.rs` exposes. Three of
/// those values are inputs to an approved security function:
///
/// * the DTLS handshake `Random` (`src/types.rs`, used by both the 1.2 and 1.3
///   engines), which feeds the key schedule;
/// * the DTLS 1.2 `HelloVerifyRequest` cookie secret; and
/// * the DTLS 1.2 explicit AES-GCM record nonce, whose construction SP 800-38D
///   pins to an approved source.
///
/// `docs/fips.md` places the DRBG *inside* the module boundary, so admitting
/// DTLS under enforcement would be exactly the "uses a FIPS-capable library"
/// claim this mode exists to refuse. It is therefore rejected before serving,
/// like `kafka_logging`, rather than allowed under an implicit claim.
pub const DTLS_REFUSAL_DETAIL: &str = "DTLS runs on the vendored `dimpl` stack, whose handshake \
                                       and record randomness does not come from the selected \
                                       module's approved DRBG, so it is refused while FIPS mode \
                                       is enforced. Use a TLS-terminating listener or sink \
                                       instead. See docs/fips.md.";

/// Approved stored-password representation.
///
/// Ferrum stores consumer Basic credentials as `hmac_sha256:<64 hex>` — an
/// HMAC-SHA-256 under an operator secret, which is an approved keyed MAC and,
/// since this change, computed by the selected module
/// ([`crate::fips::approved`]). Any other prefix would be a password KDF Ferrum
/// has not classified, so FIPS mode refuses it rather than assuming.
pub const APPROVED_PASSWORD_HASH_PREFIX: &str = "hmac_sha256:";

/// Process-environment escape hatches that admit an unverified peer.
///
/// Each is consumed directly from the process environment rather than through
/// `EnvConfig`, so FIPS mode reads it from the same place its consumer does.
/// The second element completes the sentence "`<NAME>` …".
pub const PROCESS_PEER_BYPASS_ENV: &[(&str, &str)] = &[
    (
        "FERRUM_MESH_ALLOW_NO_CA",
        "starts the mesh with no workload trust anchor, so no peer identity is verified at all",
    ),
    (
        "FERRUM_MESH_ALLOW_STATIC_ID",
        "admits an unattested static workload identity in place of a real attestation",
    ),
    (
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
        "bootstraps a self-signed development mesh CA rather than an operator-established trust \
         anchor",
    ),
    (
        "FERRUM_INJECTOR_ALLOW_PLAINTEXT",
        "serves the Kubernetes admission webhook over plaintext HTTP instead of authenticated \
         TLS",
    ),
];

/// `true` when an environment-only boolean switch is engaged.
///
/// Deliberately permissive about spelling in the *rejecting* direction: any
/// value the mesh's own consumers would read as "on" must reject here. An
/// unset, empty, or explicitly-off value is not engaged.
fn env_flag_engaged(name: &str) -> bool {
    match std::env::var(name) {
        Ok(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "off" | "no" | "disabled" | "disable"
        ),
        // A non-Unicode value is reported as absent by `var`. Ferrum's startup
        // env sweep rejects undecodable `FERRUM_*` values before the gateway
        // runs, so this cannot silently drop an engaged switch.
        Err(_) => false,
    }
}

/// A plugin configuration key that admits an unauthenticated TLS/DTLS peer.
///
/// `path` is a dotted path into the plugin's `config` object. A `[]` segment
/// walks every element of an array, so one entry covers a per-rule or
/// per-provider override without needing a bespoke traversal.
struct UnauthenticatedPeerKey {
    /// Plugin this key belongs to.
    plugin: &'static str,
    /// Dotted path into the plugin's config object.
    path: &'static str,
    /// The boolean value that *disables* verification.
    disabling_value: bool,
    /// When `Some`, the key only takes effect if this sibling path is `true`,
    /// and its absence then means "disabled" (an insecure default).
    gated_by: Option<&'static str>,
    /// Whether an *absent* key is itself a bypass, because the plugin defaults
    /// it insecurely once `gated_by` is engaged.
    absent_is_bypass: bool,
}

/// Every plugin-owned, independently configurable verification opt-out.
///
/// The gateway-wide `FERRUM_TLS_NO_VERIFY` is already refused at the
/// environment gate, and most plugins can only *inherit* it. These are the
/// plugins that own a switch of their own, so a FIPS deployment that fixed the
/// global flag could still be admitting unauthenticated peers on one sink.
///
/// `kafka_logging`'s `ssl_no_verify` is deliberately absent: the whole plugin
/// is refused by [`NON_APPROVED_PLUGINS`], so a second rule for one of its keys
/// would be unreachable. `tests/unit/tls/fips_policy_tests.rs` pins that
/// relationship so removing the plugin-level rejection cannot silently orphan
/// the key.
const UNAUTHENTICATED_PEER_PLUGIN_KEYS: &[UnauthenticatedPeerKey] = &[
    // Builds its own reqwest client and, when set, *also* drops the gateway CA
    // bundle rather than merely skipping verification.
    UnauthenticatedPeerKey {
        plugin: "spec_expose",
        path: "tls_no_verify",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    // The one insecure-by-default surface in the inventory: when `gateway_tls`
    // is on, an *absent* `gateway_tls_no_verify` resolves to `true`. An
    // absence therefore has to reject here, or the default silently wins.
    UnauthenticatedPeerKey {
        plugin: "load_testing",
        path: "gateway_tls_no_verify",
        disabling_value: true,
        gated_by: Some("gateway_tls"),
        absent_is_bypass: true,
    },
    // DTLS server-certificate verifier is skipped entirely.
    UnauthenticatedPeerKey {
        plugin: "udp_logging",
        path: "dtls_no_verify",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    // ClickHouse sink: certificate and hostname verification are separate
    // switches, so both are listed.
    UnauthenticatedPeerKey {
        plugin: "api_chargeback_sink",
        path: "clickhouse.tls.insecure_skip_verify",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    UnauthenticatedPeerKey {
        plugin: "api_chargeback_sink",
        path: "clickhouse.tls.verify_hostname",
        disabling_value: false,
        gated_by: None,
        absent_is_bypass: false,
    },
    // Per-route backend TLS override; overrides the proxy's resolved backend
    // TLS, so the `GatewayConfig` upstream/proxy check below does not see it.
    UnauthenticatedPeerKey {
        plugin: "mesh_route_dispatch",
        path: "rules[].destination.backend_tls.verify_server_cert",
        disabling_value: false,
        gated_by: None,
        absent_is_bypass: false,
    },
    // Not a certificate bypass, but it admits a plaintext `http://` audit sink,
    // which is an unauthenticated transport for security-relevant records.
    UnauthenticatedPeerKey {
        plugin: "ai_transcript_audit",
        path: "sink.allow_insecure_loopback",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    // These dev-only switches permit credential- or request-bearing plugin
    // egress over plaintext to a non-loopback peer.
    UnauthenticatedPeerKey {
        plugin: "ldap_auth",
        path: "allow_plaintext",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    UnauthenticatedPeerKey {
        plugin: "ai_federation",
        path: "providers[].allow_plaintext",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
    UnauthenticatedPeerKey {
        plugin: "ai_stream_router",
        path: "providers[].allow_plaintext",
        disabling_value: true,
        gated_by: None,
        absent_is_bypass: false,
    },
];

/// Render a bounded list of offending entries.
fn bounded_list(entries: &[String]) -> String {
    let mut out = String::new();
    for (index, entry) in entries.iter().take(MAX_REPORTED_VIOLATIONS).enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(entry);
    }
    if entries.len() > MAX_REPORTED_VIOLATIONS {
        let _ = write!(
            out,
            " (and {} more)",
            entries.len() - MAX_REPORTED_VIOLATIONS
        );
    }
    out
}

/// Validate process-level configuration against FIPS policy.
///
/// Returns the first violation. Callers surface it verbatim; it is already
/// bounded and secret-free.
pub fn check_env_config(env_config: &EnvConfig) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_env_config_enforced(env_config)
}

/// The enforced half of [`check_env_config`], with the mode gate removed.
///
/// Split out so the policy itself is directly testable on a build where
/// [`super::BUILD_CAPABLE`] is `false` and enforcement can therefore never be
/// established at runtime. Production callers use the gated wrapper.
pub fn check_env_config_enforced(env_config: &EnvConfig) -> Result<(), String> {
    // ── Provider pin ────────────────────────────────────────────────────
    // The operator names the integration they audited. Today exactly one is
    // supported; pinning it means a future build that changed integrations
    // cannot silently satisfy an existing FIPS deployment contract.
    let required = env_config.fips_required_provider.trim();
    if required != super::SUPPORTED_PROVIDER_ID {
        return Err(format!(
            "FERRUM_FIPS_REQUIRED_PROVIDER names a validated-module integration this build does \
             not provide. This build supports `{}` only.",
            super::SUPPORTED_PROVIDER_ID
        ));
    }

    // The MongoDB driver performs authentication and protocol cryptography
    // through its own HMAC, PBKDF2, SHA-1, SHA-2, and MD5 implementations.
    // Selecting its AWS-LC-backed rustls feature routes only TLS, not those
    // primitives, so the config store cannot be admitted into this boundary.
    if env_config
        .db_type
        .as_deref()
        .is_some_and(|db_type| db_type.eq_ignore_ascii_case("mongodb"))
    {
        return Err(
            "FERRUM_DB_TYPE=mongodb uses database-driver cryptography outside Ferrum's selected \
             validated-module boundary and is refused while FIPS mode is enforced. Use a SQL \
             config database or file mode."
                .to_string(),
        );
    }

    // SQL modes that do not authenticate the config-database peer must not be
    // admitted into the enforced boundary. `verify-ca` and `verify-full` are
    // the only explicit modes that validate the server certificate chain.
    // When `FERRUM_DB_TLS_MODE` is unset, peer authentication must be selected
    // by URL-owned parameters on every configured SQL URL (primary, failover,
    // and read replica); otherwise the same unauthenticated-peer exposure is
    // reachable by omitting the env var rather than setting a weak one.
    let sql_config_store = env_config.db_type.as_deref().is_some_and(|db_type| {
        db_type.eq_ignore_ascii_case("postgres") || db_type.eq_ignore_ascii_case("mysql")
    });
    if sql_config_store {
        let dialect = if env_config
            .db_type
            .as_deref()
            .is_some_and(|db_type| db_type.eq_ignore_ascii_case("postgres"))
        {
            "postgres"
        } else {
            "mysql"
        };
        if let Some(mode) = env_config.db_tls_mode {
            // Exhaustive on purpose: a future `DbTlsMode` variant must be an
            // explicit decision here, and until it is made it falls into the
            // refusal arm rather than being silently admitted.
            match mode {
                DbTlsMode::VerifyCa | DbTlsMode::VerifyFull => {}
                unverified => {
                    return Err(format!(
                        "FERRUM_DB_TLS_MODE={unverified} does not authenticate the SQL \
                         config-database peer and is refused while FIPS mode is enforced; use \
                         `verify-ca` or `verify-full`."
                    ));
                }
            }
        } else {
            refuse_unverified_sql_url_tls(env_config, dialect)?;
        }
    }

    // ── TLS versions ────────────────────────────────────────────────────
    // Ferrum already restricts both bounds to 1.2/1.3, and SP 800-52r2 permits
    // both. Re-assert here so a future widening of the ordinary vocabulary
    // cannot silently widen the FIPS one.
    for (name, value) in [
        (
            "FERRUM_TLS_MIN_VERSION",
            env_config.tls_min_version.as_str(),
        ),
        (
            "FERRUM_TLS_MAX_VERSION",
            env_config.tls_max_version.as_str(),
        ),
    ] {
        if !matches!(value, "1.2" | "1.3") {
            return Err(format!(
                "{name} must be `1.2` or `1.3` while FIPS mode is enforced; earlier TLS versions \
                 are outside the approved boundary."
            ));
        }
    }

    // ── DTLS ────────────────────────────────────────────────────────────
    // Frontend DTLS termination is the one transport Ferrum terminates outside
    // rustls: it runs on the vendored `dimpl` DTLS stack. See
    // [`DTLS_REFUSAL_DETAIL`] for why that stack cannot be routed onto the
    // selected module even though its suites and signatures already are.
    for (name, configured) in [
        ("FERRUM_DTLS_CERT_PATH", &env_config.dtls_cert_path),
        ("FERRUM_DTLS_KEY_PATH", &env_config.dtls_key_path),
    ] {
        // Blank means unset everywhere else in `EnvConfig`; a whitespace-only
        // value must not be read as a configured listener.
        if configured.iter().any(|value| !value.trim().is_empty()) {
            return Err(format!(
                "{name} configures a frontend DTLS listener. {DTLS_REFUSAL_DETAIL}"
            ));
        }
    }

    // ── Peer verification ───────────────────────────────────────────────
    // An unauthenticated peer defeats the point of an approved key exchange:
    // the module can perform a perfect ECDHE, and it is still a key agreement
    // with whoever answered. Every *independently configurable* opt-out is
    // covered, not just the global one, because a per-surface switch is exactly
    // the hole a global-only gate leaves open.
    //
    // `FERRUM_DP_GRPC_TLS_NO_VERIFY` is deliberately absent from this list. It
    // is already refused unconditionally, on every build and in every mode, by
    // `EnvConfig::validate_cp_dp_grpc_transport_security`, so a FIPS rule for it
    // would be unreachable.
    // `dp_grpc_no_verify_is_covered_by_the_ordinary_validator_not_by_fips` in
    // `tests/unit/tls/fips_key_admission_tests.rs` pins that reasoning: it
    // asserts the ordinary rejection is still unconditional, so a future
    // relaxation there fails a FIPS test rather than silently opening a bypass.
    for (name, engaged, detail) in [
        (
            "FERRUM_TLS_NO_VERIFY",
            env_config.tls_no_verify,
            "outbound backend, service-discovery, and plugin HTTP/TLS server certificate \
             verification",
        ),
        (
            "FERRUM_ADMIN_TLS_NO_VERIFY",
            env_config.admin_tls_no_verify,
            "admin listener client-certificate requirement and verification",
        ),
        (
            "FERRUM_ALLOW_INSECURE_ADMIN_HTTP",
            env_config.allow_insecure_admin_http,
            "TLS on a non-loopback admin API listener, leaving it a plaintext, unauthenticated \
             transport",
        ),
        (
            "FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT",
            env_config.mesh_egress_stream_allow_plaintext,
            "SVID mTLS termination on mesh TCP/UDP egress, admitting unauthenticated peers",
        ),
        (
            "FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT",
            env_config.cp_dp_grpc_allow_plaintext,
            "TLS on non-loopback CP/DP configuration transport, exposing the authentication JWT \
             and distributed gateway configuration to active interception",
        ),
    ] {
        if engaged {
            return Err(format!(
                "{name} disables {detail}, and is refused while FIPS mode is enforced."
            ));
        }
    }

    // Direct process-environment escape hatches. These are read here rather
    // than through `EnvConfig` because that is where their own consumers read
    // them, and a FIPS gate that consulted a different source would be checking
    // a value that is not the one in effect. They are boolean-ish dev switches,
    // so only the variable name is reported.
    for (name, detail) in PROCESS_PEER_BYPASS_ENV {
        if env_flag_engaged(name) {
            return Err(format!(
                "{name} {detail}, and is refused while FIPS mode is enforced."
            ));
        }
    }

    // ── Admin and CP/DP JWT MAC keys ────────────────────────────────────
    for (name, secret) in [
        (
            "FERRUM_ADMIN_JWT_SECRET",
            env_config.admin_jwt_secret.as_deref(),
        ),
        (
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            env_config.cp_dp_grpc_jwt_secret.as_deref(),
        ),
        (
            "FERRUM_BASIC_AUTH_HMAC_SECRET",
            env_config.basic_auth_hmac_secret.as_deref(),
        ),
        (
            "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET",
            env_config.datagram_proxy_protocol_secret.as_deref(),
        ),
    ] {
        if let Some(secret) = secret.filter(|s| !s.is_empty())
            && secret.len() < MIN_HMAC_KEY_BYTES
        {
            // The length is a property of the secret, not the secret; it is the
            // only actionable fact and is already reported by the ordinary
            // (non-FIPS) validator for these same keys.
            return Err(format!(
                "{name} must be at least {MIN_HMAC_KEY_BYTES} bytes while FIPS mode is enforced \
                 (SP 800-107 HMAC key strength)."
            ));
        }
    }

    Ok(())
}

/// Refuse SQL config-database URLs that do not demonstrably authenticate the
/// peer when `FERRUM_DB_TLS_MODE` is unset.
///
/// Checks `FERRUM_DB_URL`, every `FERRUM_DB_FAILOVER_URLS` entry, and
/// `FERRUM_DB_READ_REPLICA_URL`. Diagnostics name the env setting and the
/// offending query-parameter key only — never the URL or its credentials.
fn refuse_unverified_sql_url_tls(env_config: &EnvConfig, dialect: &str) -> Result<(), String> {
    let mut checks: Vec<(String, &str)> = Vec::new();
    if let Some(url) = env_config
        .db_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
    {
        checks.push(("FERRUM_DB_URL".to_string(), url));
    }
    for (index, url) in env_config.db_failover_urls.iter().enumerate() {
        if url.trim().is_empty() {
            continue;
        }
        checks.push((
            format!("FERRUM_DB_FAILOVER_URLS[#{}]", index + 1),
            url.as_str(),
        ));
    }
    if let Some(url) = env_config
        .db_read_replica_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
    {
        checks.push(("FERRUM_DB_READ_REPLICA_URL".to_string(), url));
    }

    for (label, url) in checks {
        match EnvConfig::sql_url_tls_peer_auth(url, dialect) {
            SqlUrlTlsPeerAuth::Verified => {}
            SqlUrlTlsPeerAuth::Absent { expected_param } => {
                return Err(format!(
                    "{label} does not set `{expected_param}` to a peer-authenticating value and is \
                     refused while FIPS mode is enforced with FERRUM_DB_TLS_MODE unset; embed a \
                     verifying `{expected_param}` in the URL (`verify-ca`/`verify-full` for \
                     PostgreSQL, `VERIFY_CA`/`VERIFY_IDENTITY` for MySQL) or set \
                     FERRUM_DB_TLS_MODE to `verify-ca` or `verify-full`."
                ));
            }
            SqlUrlTlsPeerAuth::Unverified { param } => {
                return Err(format!(
                    "{label} query parameter `{param}` does not authenticate the SQL \
                     config-database peer and is refused while FIPS mode is enforced with \
                     FERRUM_DB_TLS_MODE unset; use a verifying mode (`verify-ca`/`verify-full` \
                     for PostgreSQL, `VERIFY_CA`/`VERIFY_IDENTITY` for MySQL) or set \
                     FERRUM_DB_TLS_MODE to `verify-ca` or `verify-full`."
                ));
            }
        }
    }
    Ok(())
}

/// External secret-provider suffixes whose SDK carries its own TLS stack.
///
/// `_FILE` is deliberately absent: it is a local filesystem read that performs
/// no cryptography and reaches no network peer, so it stays supported.
pub const REMOTE_SECRET_PROVIDER_SUFFIXES: &[&str] = &["_VAULT", "_AWS", "_AZURE", "_GCP"];

/// Refuse remote external secret providers while FIPS mode is enforced.
///
/// # Why this is a refusal rather than a claim
///
/// Vault, AWS, Azure, and GCP each resolve secrets over their own SDK's TLS
/// stack. Those stacks are not built from [`super::base_crypto_provider`] and
/// are not selected by the `crypto-ring` / `fips` feature pair, so Ferrum
/// cannot route them onto the selected module and cannot attest to what they
/// use. The previous position — "outside the boundary, but allowed, because
/// secrets resolve once at startup" — was an *implicit* claim that a
/// pre-serving TLS session to a credential store does not matter. It does: that
/// session carries the gateway's private keys and JWT secrets, and it is the
/// one connection whose compromise hands over everything else.
///
/// So an enforcing FIPS process refuses it, before the provider is contacted,
/// with a diagnostic that names the alternative. `_FILE` (and an ordinary
/// direct environment value) remain supported, which is the shape a FIPS
/// deployment already needs: the secret is delivered by an operator-controlled
/// mechanism — a mounted secret, an init container, a KMS-backed volume — whose
/// own transport the operator has validated.
///
/// # Where this runs
///
/// Called from `main::resolve_startup_secrets`, which runs *after*
/// [`super::install_crypto_provider`] has established the FIPS state and
/// *before* any provider client is constructed. That ordering is what makes it
/// a refusal rather than a post-hoc complaint.
pub fn check_external_secret_sources() -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_external_secret_sources_enforced(configured_remote_secret_providers())
}

/// The enforced half of [`check_external_secret_sources`], over an already
/// collected suffix set so it is directly testable without mutating the
/// process environment.
pub fn check_external_secret_sources_enforced(configured: Vec<&'static str>) -> Result<(), String> {
    if configured.is_empty() {
        return Ok(());
    }
    // Only the suffixes are named — a fixed Ferrum vocabulary. The base keys
    // are withheld: they are the names of the settings an operator chose to
    // source remotely, which is deployment intelligence, and a diagnostic does
    // not need them to be actionable.
    let suffixes: Vec<String> = configured.into_iter().map(str::to_string).collect();
    Err(format!(
        "external secret provider suffix(es) [{}] are configured. Those SDKs resolve secrets over \
         their own TLS stacks, which Ferrum cannot route through the selected \
         `{}` module, so they are refused while FIPS mode is enforced. Supply the affected \
         settings directly, or through the local `_FILE` suffix backed by an \
         operator-validated delivery mechanism. See docs/fips.md.",
        bounded_list(&suffixes),
        super::SUPPORTED_PROVIDER_ID
    ))
}

/// Refuse a typed remote-provider URI before its SDK client is constructed.
///
/// This complements [`check_external_secret_sources`]: TLS material sources can
/// arrive through config files, the admin API, or a resolved `_FILE` value and
/// therefore need enforcement at the common URI-loading boundary too.
pub fn check_external_secret_uri_scheme(scheme: &'static str) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_external_secret_uri_scheme_enforced(scheme)
}

/// The enforced half of [`check_external_secret_uri_scheme`].
pub fn check_external_secret_uri_scheme_enforced(scheme: &'static str) -> Result<(), String> {
    if !matches!(scheme, "vault" | "aws" | "azure" | "gcp") {
        return Ok(());
    }

    Err(format!(
        "external secret provider URI scheme `{scheme}` is configured. Its SDK resolves secrets \
         over its own TLS stack, which Ferrum cannot route through the selected `{}` module, so \
         it is refused while FIPS mode is enforced. Supply the material directly or through a \
         local file backed by an operator-validated delivery mechanism. See docs/fips.md.",
        super::SUPPORTED_PROVIDER_ID
    ))
}

/// Remote-provider suffixes present on at least one `FERRUM_*` variable.
///
/// Iterates `vars_os` rather than `vars`, which panics on a non-Unicode name or
/// value, and screens the prefix on raw bytes so unrelated variables are never
/// decoded — the same discipline `src/secrets/` uses for the identical sweep.
fn configured_remote_secret_providers() -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for (name, value) in std::env::vars_os() {
        if !name.as_encoded_bytes().starts_with(b"FERRUM_") {
            continue;
        }
        let Some(name) = name.to_str() else {
            continue;
        };
        // "Set" means non-empty, matching `secrets::external_source_configured`
        // so the two cannot disagree about whether a source exists.
        if value.is_empty() {
            continue;
        }
        for suffix in REMOTE_SECRET_PROVIDER_SUFFIXES {
            if name.ends_with(suffix) && !found.contains(suffix) {
                found.push(suffix);
            }
        }
    }
    found.sort_unstable();
    found
}

/// Validate a gateway configuration document against FIPS policy.
///
/// This is the shared admission gate for `validate`, startup, file-mode SIGHUP
/// reload, database poll application, CP publication, and DP snapshot/delta
/// application, so a configuration that could not start also cannot be
/// hot-loaded or distributed.
pub fn check_gateway_config(config: &GatewayConfig) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_gateway_config_enforced(config)
}

/// The enforced half of [`check_gateway_config`]. See
/// [`check_env_config_enforced`] for why the gate is split out.
pub fn check_gateway_config_enforced(config: &GatewayConfig) -> Result<(), String> {
    let mut non_approved_plugins: Vec<String> = Vec::new();
    let mut jwt_violations: Vec<String> = Vec::new();
    let mut algorithm_violations: Vec<String> = Vec::new();
    let mut peer_verification_violations: Vec<String> = Vec::new();
    let mut dtls_violations: Vec<String> = Vec::new();

    for (index, plugin) in config.plugin_configs.iter().enumerate() {
        if !plugin.enabled {
            continue;
        }
        // `udp_logging` opens its own DTLS client session. The plugin itself is
        // approved in plaintext UDP form, so only the DTLS selection is
        // refused — the key is Ferrum's own fixed vocabulary and the position
        // is enough to find the instance without echoing its operator-chosen
        // id. See [`DTLS_REFUSAL_DETAIL`].
        if plugin.plugin_name == "udp_logging"
            && matches!(
                lookup_dotted(&plugin.config, "dtls"),
                Some(serde_json::Value::Bool(true))
            )
        {
            dtls_violations.push(format!("plugin_configs[#{}].udp_logging.dtls", index + 1));
        }
        if NON_APPROVED_PLUGINS.contains(&plugin.plugin_name.as_str()) {
            // The plugin name is a fixed Ferrum vocabulary entry, not operator
            // free text, so echoing it discloses nothing the operator did not
            // already write and is what makes the diagnostic actionable.
            non_approved_plugins.push(plugin.plugin_name.clone());
        }
        collect_jwt_algorithm_violations(plugin, &mut jwt_violations);
        collect_non_approved_algorithm_selections(plugin, &mut algorithm_violations);
        collect_unauthenticated_peer_keys(plugin, &mut peer_verification_violations);
        collect_redis_url_verification_fragments(plugin, &mut peer_verification_violations);
    }

    // ── Per-upstream and per-proxy backend peer verification ────────────
    //
    // These are refused whenever they are `false`, including on a plaintext
    // backend where the field has no runtime effect. That is a deliberate
    // choice, not an oversight, and it is pinned by
    // `a_declared_upstream_verification_opt_out_is_refused_even_when_dormant`
    // in `tests/unit/tls/fips_key_admission_tests.rs`:
    //
    //  * An `Upstream` carries no scheme of its own — TLS-ness is a property of
    //    each target and of every proxy that references the upstream, so
    //    "inert" is not a stable property of the document being admitted. A
    //    later target edit turns a dormant `false` into a live bypass with no
    //    change to this field, and that edit would arrive through a hot reload
    //    or CP publication that this same gate is supposed to be the backstop
    //    for.
    //  * The remedy is free and unambiguous: set it to `true`, which is both
    //    the schema default and a no-op on a plaintext backend.
    //
    // The mesh `DestinationRule.trafficPolicy.tls.insecureSkipVerify` override
    // needs no rule of its own: it is projected onto
    // `Upstream.backend_tls_verify_server_cert` before admission, so it is
    // caught here at exactly the point it takes effect.
    //
    // Entries are named by their one-based *position* in the document, never by
    // their `id`. An id is operator-supplied free text; a position is
    // sufficient to find the entry and discloses nothing.
    for (index, upstream) in config.upstreams.iter().enumerate() {
        if !upstream.backend_tls_verify_server_cert {
            peer_verification_violations.push(format!(
                "upstreams[#{}].backend_tls_verify_server_cert=false",
                index + 1
            ));
        }
    }
    for (index, proxy) in config.proxies.iter().enumerate() {
        // The *declared* field, deliberately, not `resolved_tls`.
        // `BackendTlsConfig` derives `Default`, so `resolved_tls` reads `false`
        // on any document this gate sees before `normalize_fields()` has run —
        // and this gate runs at `validate`, at startup, and at every reload and
        // publication boundary, not only after normalization. Screening the
        // resolved projection would therefore reject every not-yet-normalized
        // proxy. The declared fields are what an operator writes and what
        // normalization projects *from*, and a proxy that references an
        // upstream inherits that upstream's value, which the loop above already
        // covers.
        if !proxy.backend_tls_verify_server_cert {
            peer_verification_violations.push(format!(
                "proxies[#{}].backend_tls_verify_server_cert=false",
                index + 1
            ));
        }
        // A `dtls` backend scheme is both the DTLS listener selector and the
        // DTLS dial selector for a stream proxy, so one rule covers both ends.
        // See [`DTLS_REFUSAL_DETAIL`].
        if proxy.backend_scheme == Some(BackendScheme::Dtls) {
            dtls_violations.push(format!("proxies[#{}].backend_scheme=dtls", index + 1));
        }
    }

    if !peer_verification_violations.is_empty() {
        peer_verification_violations.sort();
        peer_verification_violations.dedup();
        return Err(format!(
            "configuration entr(ies) [{}] disable TLS/DTLS peer certificate verification, or \
             admit an unauthenticated transport, and are refused while FIPS mode is enforced. An \
             unverified peer defeats the point of an approved key exchange. See docs/fips.md.",
            bounded_list(&peer_verification_violations)
        ));
    }

    // Reported after peer verification, deliberately: a DTLS surface that
    // *also* disables peer verification gets the more specific opt-out
    // diagnostic first, exactly as it did before DTLS itself became a refusal.
    if !dtls_violations.is_empty() {
        dtls_violations.sort();
        dtls_violations.dedup();
        return Err(format!(
            "configuration entr(ies) [{}] terminate or dial DTLS. {DTLS_REFUSAL_DETAIL}",
            bounded_list(&dtls_violations)
        ));
    }

    // ── Stored password representation ──────────────────────────────────
    // Ordinary validation already pins the `hmac_sha256:` form, so this is a
    // fail-closed backstop rather than the primary gate: it is what refuses a
    // future stored-credential format that has not been classified against the
    // approved KDF/MAC set. No credential material is interpolated — only the
    // consumer count, which the operator already knows.
    let unclassified_hashes = config
        .consumers
        .iter()
        .filter(|consumer| {
            consumer.credentials.get("basicauth").is_some_and(|value| {
                stored_password_hash_representations(value).any(|hash| match hash {
                    Some(hash) => !is_approved_password_hash(hash),
                    None => true,
                })
            })
        })
        .count();
    if unclassified_hashes > 0 {
        return Err(format!(
            "{unclassified_hashes} consumer(s) carry a stored password hash in a representation \
             Ferrum has not classified against the approved MAC/KDF set. FIPS mode admits only \
             `{APPROVED_PASSWORD_HASH_PREFIX}<64 lowercase hex>`. See docs/fips.md."
        ));
    }

    if !non_approved_plugins.is_empty() {
        non_approved_plugins.sort();
        non_approved_plugins.dedup();
        return Err(format!(
            "plugin(s) [{}] perform cryptography outside the selected AWS-LC FIPS module \
             implementation and are refused while FIPS mode is enforced. See docs/fips.md for \
             module-routed \
             alternatives.",
            bounded_list(&non_approved_plugins)
        ));
    }

    if !jwt_violations.is_empty() {
        jwt_violations.sort();
        jwt_violations.dedup();
        return Err(format!(
            "JWT/JWS algorithm(s) [{}] are not in the approved set while FIPS mode is enforced. \
             Approved: {}.",
            bounded_list(&jwt_violations),
            APPROVED_JWT_ALGORITHMS.join(", ")
        ));
    }

    if !algorithm_violations.is_empty() {
        algorithm_violations.sort();
        algorithm_violations.dedup();
        return Err(format!(
            "plugin algorithm selection(s) [{}] name a primitive that is not approved for \
             signature generation or verification and are refused while FIPS mode is enforced. \
             See docs/fips.md.",
            bounded_list(&algorithm_violations)
        ));
    }

    Ok(())
}

/// Stored password hashes carried by one credential value.
///
/// A credential is either a single object or an array of objects (multi-
/// credential rotation), so both shapes are walked. Only the `password_hash`
/// member is read and its representation is checked in place — the value
/// itself never leaves this function.
fn stored_password_hash_representations(
    value: &serde_json::Value,
) -> impl Iterator<Item = Option<&str>> {
    let entries: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(entries) => entries.iter().collect(),
        other => vec![other],
    };
    entries
        .into_iter()
        .map(|entry| {
            entry
                .get("password_hash")
                .and_then(serde_json::Value::as_str)
        })
        .collect::<Vec<_>>()
        .into_iter()
}

fn is_approved_password_hash(value: &str) -> bool {
    value
        .strip_prefix(APPROVED_PASSWORD_HASH_PREFIX)
        .is_some_and(|hex_hash| {
            hex_hash.len() == 64
                && hex_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Collect non-approved algorithm names a plugin's configuration selects.
///
/// The keys are dotted paths into the plugin's config object, matching the
/// spelling the plugin's own validator uses, so the diagnostic names the field
/// the operator must edit.
fn collect_non_approved_algorithm_selections(plugin: &PluginConfig, out: &mut Vec<String>) {
    for (plugin_name, keys, non_approved) in NON_APPROVED_ALGORITHM_SELECTIONS {
        if plugin.plugin_name != *plugin_name {
            continue;
        }
        for key in *keys {
            let Some(value) = lookup_dotted(&plugin.config, key) else {
                continue;
            };
            let serde_json::Value::Array(entries) = value else {
                continue;
            };
            for entry in entries {
                let Some(selected) = entry.as_str() else {
                    continue;
                };
                if non_approved
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(selected.trim()))
                {
                    out.push(format!("{plugin_name}.{key}={}", selected.trim()));
                }
            }
        }
    }
}

/// Resolve a dotted path through nested JSON objects.
fn lookup_dotted<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Resolve a dotted path that may contain `[]` array-walk segments.
///
/// Returns every value the path reaches. A `name[]` segment descends into
/// `name` and continues from each element, so
/// `rules[].destination.backend_tls.verify_server_cert` yields one value per
/// configured rule that sets it. Bounded by the configuration document itself;
/// this runs at admission, never on the request path.
fn lookup_path_all<'a>(root: &'a serde_json::Value, path: &str) -> Vec<&'a serde_json::Value> {
    let mut current = vec![root];
    for segment in path.split('.') {
        if current.is_empty() {
            return current;
        }
        let (name, walk_array) = match segment.strip_suffix("[]") {
            Some(name) => (name, true),
            None => (segment, false),
        };
        let mut next = Vec::new();
        for value in current {
            let Some(child) = value.get(name) else {
                continue;
            };
            if walk_array {
                match child {
                    serde_json::Value::Array(entries) => next.extend(entries.iter()),
                    // A non-array where an array was expected is a schema fault
                    // the plugin's own validator reports; it is not a
                    // verification bypass, so it is skipped rather than
                    // double-reported here.
                    _ => continue,
                }
            } else {
                next.push(child);
            }
        }
        current = next;
    }
    current
}

/// Collect verification opt-outs a plugin's configuration engages.
///
/// The reported entry is `plugin.path`, both of which are fixed Ferrum
/// configuration vocabulary — never an operator-supplied value.
fn collect_unauthenticated_peer_keys(plugin: &PluginConfig, out: &mut Vec<String>) {
    for key in UNAUTHENTICATED_PEER_PLUGIN_KEYS {
        if plugin.plugin_name != key.plugin {
            continue;
        }

        // A key whose enabling sibling is off cannot bypass anything, so it is
        // not reported. This is the one place an "inert" setting is tolerated,
        // because here the gate is a value in the *same document* being
        // admitted rather than an inference about a different one.
        if let Some(gate) = key.gated_by
            && !matches!(
                lookup_dotted(&plugin.config, gate),
                Some(serde_json::Value::Bool(true))
            )
        {
            continue;
        }

        let values = lookup_path_all(&plugin.config, key.path);
        if values.is_empty() {
            if key.absent_is_bypass {
                out.push(format!(
                    "{}.{} (unset, defaults open)",
                    key.plugin, key.path
                ));
            }
            continue;
        }
        for value in values {
            match value {
                serde_json::Value::Bool(observed) if *observed == key.disabling_value => {
                    out.push(format!("{}.{}", key.plugin, key.path));
                }
                // An explicit JSON `null` is "absent" to every one of these
                // plugins, so it takes the insecure default where there is one.
                serde_json::Value::Null if key.absent_is_bypass => {
                    out.push(format!("{}.{} (null, defaults open)", key.plugin, key.path));
                }
                _ => {}
            }
        }
    }
}

/// Collect `redis_url` values that carry a URL fragment.
///
/// redis-rs treats `#insecure` as `ConnectionAddr::TcpTls.insecure = true`,
/// which is a verification opt-out that is not `FERRUM_TLS_NO_VERIFY`. Plugin
/// construction already rejects any fragment; this is the FIPS-enforce
/// backstop so a fragment-bearing spec cannot be admitted even if a future
/// caller bypasses `RedisConfig::from_plugin_config`. The URL itself is never
/// interpolated — it can carry Redis ACL credentials.
fn collect_redis_url_verification_fragments(plugin: &PluginConfig, out: &mut Vec<String>) {
    let Some(raw) = plugin
        .config
        .get("redis_url")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    if raw.contains('#') {
        out.push(format!("{}.redis_url", plugin.plugin_name));
    }
}

/// Collect non-approved JWT algorithm names from one plugin's configuration.
///
/// Ferrum's JWT-bearing plugins spell their accepted algorithms as either a
/// scalar `algorithm`/`alg` string or an `algorithms` array, depending on the
/// plugin. Both shapes are inspected; anything that is not a string is left to
/// the plugin's own schema validation rather than reported twice.
fn collect_jwt_algorithm_violations(plugin: &PluginConfig, out: &mut Vec<String>) {
    const ALGORITHM_KEYS: &[&str] = &["algorithm", "alg", "algorithms", "allowed_algorithms"];

    for key in ALGORITHM_KEYS {
        let Some(value) = plugin.config.get(*key) else {
            continue;
        };
        match value {
            serde_json::Value::String(alg) => push_if_not_approved(alg, out),
            serde_json::Value::Array(entries) => {
                for entry in entries {
                    if let serde_json::Value::String(alg) = entry {
                        push_if_not_approved(alg, out);
                    }
                }
            }
            _ => {}
        }
    }

    // OIDC RP and OAuth2 introspection can sign private_key_jwt client
    // assertions. Their algorithm selector is nested per provider rather than
    // at the plugin root, so inspect that production shape explicitly. EdDSA
    // is valid ordinary configuration but is outside the algorithm set routed
    // through the selected module and must fail FIPS admission.
    if matches!(
        plugin.plugin_name.as_str(),
        "oidc_relying_party" | "oauth2_introspection"
    ) && let Some(providers) = plugin
        .config
        .get("providers")
        .and_then(serde_json::Value::as_array)
    {
        for provider in providers {
            if let Some(algorithm) = provider
                .get("client_auth")
                .and_then(|value| value.get("private_key_jwt_alg"))
                .and_then(serde_json::Value::as_str)
            {
                push_if_not_approved(algorithm, out);
            }
        }
    }
}

fn push_if_not_approved(alg: &str, out: &mut Vec<String>) {
    let candidate = alg.trim();
    if candidate.is_empty() {
        return;
    }
    // Only JWS algorithm names are screened here. Plugins that reuse the
    // `algorithm` key for a non-JWS vocabulary (for example `hmac_auth`'s
    // `hmac-sha256`) name algorithms that are themselves approved and are
    // covered by their own admission checks; screening them against the JWS set
    // would produce a false rejection.
    if !looks_like_jws_algorithm(candidate) {
        return;
    }
    if !is_approved_jwt_algorithm(candidate) {
        out.push(candidate.to_ascii_uppercase());
    }
}

/// `true` when a value is spelled like an RFC 7518 `alg` header parameter.
///
/// Matches the registered families (`HS`/`RS`/`PS`/`ES`/`Ed`) and the
/// unauthenticated `none` sentinel, which must always be rejected.
fn looks_like_jws_algorithm(candidate: &str) -> bool {
    if candidate.eq_ignore_ascii_case("none") {
        return true;
    }
    let upper = candidate.to_ascii_uppercase();
    matches!(upper.as_str(), "EDDSA")
        || (upper.len() == 5
            && matches!(&upper[..2], "HS" | "RS" | "PS" | "ES")
            && upper[2..].chars().all(|c| c.is_ascii_digit()))
}

/// Validate a constructed rustls policy against FIPS policy.
///
/// This is the last gate before any listener or backend client is built. It
/// delegates the algorithm classification to rustls/AWS-LC rather than
/// re-deriving an allow-list, so Ferrum's notion of "approved" cannot drift from
/// the module's: `SupportedCipherSuite::fips()` and `SupportedKxGroup::fips()`
/// are `false` for every suite and group the module does not treat as approved,
/// including everything provided by a non-validated backend.
pub fn check_tls_policy(policy: &crate::tls::TlsPolicy) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_tls_policy_enforced(policy)
}

/// The enforced half of [`check_tls_policy`]. See
/// [`check_env_config_enforced`] for why the gate is split out.
pub fn check_tls_policy_enforced(policy: &crate::tls::TlsPolicy) -> Result<(), String> {
    let provider = policy.crypto_provider.as_ref();

    let rejected_suites: Vec<String> = provider
        .cipher_suites
        .iter()
        .filter(|suite| !suite.fips())
        .map(|suite| format!("{:?}", suite.suite()))
        .collect();
    if !rejected_suites.is_empty() {
        return Err(format!(
            "cipher suite(s) [{}] are not FIPS-approved and are refused while FIPS mode is \
             enforced. Remove them from FERRUM_TLS_CIPHER_SUITES, or unset it to take the \
             approved defaults.",
            bounded_list(&rejected_suites)
        ));
    }

    let rejected_groups: Vec<String> = provider
        .kx_groups
        .iter()
        .filter(|group| !group.fips())
        .map(|group| format!("{:?}", group.name()))
        .collect();
    if !rejected_groups.is_empty() {
        return Err(format!(
            "key-exchange group(s) [{}] are not FIPS-approved and are refused while FIPS mode is \
             enforced. Remove them from FERRUM_TLS_KEY_EXCHANGE_GROUPS, or unset it to take the \
             approved defaults.",
            bounded_list(&rejected_groups)
        ));
    }

    // Belt-and-braces over the whole provider: this also covers the signature
    // verification algorithms, the secure random source, and the key provider,
    // none of which Ferrum lets the operator select but all of which would be
    // non-approved on a build whose crypto features drifted.
    if !provider.fips() {
        return Err(
            "the constructed rustls provider is not FIPS-approved. This indicates a build whose \
             crypto features do not match the FIPS profile documented in docs/fips.md."
                .to_string(),
        );
    }

    Ok(())
}

/// Approved-default cipher suites, expressed as protocol identifiers.
///
/// Used by `crate::tls` to seed the default suite list from whichever provider
/// this build links. ChaCha20-Poly1305 is absent: it is not an approved AEAD, so
/// including it in the FIPS defaults would make every FIPS startup fail on a
/// default configuration.
pub const FIPS_DEFAULT_CIPHER_SUITES: &[rustls::CipherSuite] = &[
    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// Approved-default key-exchange groups.
///
/// X25519 is absent: ECDH over Curve25519 is not an approved SP 800-56A scheme,
/// so it cannot be a FIPS default even though it is Ferrum's ordinary first
/// preference.
pub const FIPS_DEFAULT_KX_GROUPS: &[rustls::NamedGroup] =
    &[rustls::NamedGroup::secp256r1, rustls::NamedGroup::secp384r1];
