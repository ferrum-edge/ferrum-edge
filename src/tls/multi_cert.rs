//! SNI-aware frontend certificate selection for Gateway-delivered TLS.
//!
//! A Kubernetes Gateway may terminate TLS for several hostnames from one data
//! plane: one listener may carry several `certificateRefs`, and several
//! Gateways in one namespace may each own their own certificate (issues #3267
//! and #3268). rustls selects a credential per ClientHello through a
//! [`rustls::server::ResolvesServerCert`], so that is where the choice belongs.
//!
//! Selection is exact-match first, then one-label wildcard, then the
//! deterministic fallback certificate. The index is built once per config
//! snapshot from data the control plane already authorized — no per-handshake
//! parsing, allocation, or locking, and no growth with request volume.
//!
//! Nothing here logs or formats key material: an entry is identified by its
//! `serving-namespace/serialized-owner/listener`, which is public Kubernetes
//! metadata.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info, warn};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::tls::TlsPolicy;
use crate::tls::ocsp_recheck::{AcceptedStaple, StapleRetiringResolver, StapleTarget};
use crate::tls::source::{CertSource, MaterialKind, SourceScheme, load_material_blocking};

/// Upper bound on SNI names indexed across the whole snapshot.
///
/// The certificate set is already capped at admission
/// (`MAX_FRONTEND_TLS_CERTIFICATE_SOURCES`), but a single certificate may carry
/// an arbitrary number of SANs, so the derived index needs its own ceiling.
/// Every explicit listener hostname is indexed first. Only additional
/// certificate-derived SAN aliases beyond the bound are dropped with a warning,
/// so a SAN-heavy certificate can never displace another listener's declared
/// SNI mapping. An omitted catch-all alias falls through to the deterministic
/// fallback (and therefore to normal client certificate-name verification).
pub const MAX_SNI_INDEX_ENTRIES: usize = 4096;

/// One Gateway-owned certificate to install in the resolver.
#[derive(Debug, Clone)]
pub struct GatewayCertificateInput {
    pub cert_source: String,
    pub key_source: String,
    /// The owning listener's `hostname`, ASCII-lowercased. `None` is a
    /// catch-all listener: it contributes only the certificate's own SANs.
    pub hostname: Option<String>,
    /// `serving-namespace/serialized-owner/listener` — public metadata, used
    /// for diagnostics. Never contains certificate or key bytes.
    pub identity: String,
    /// Whether this certificate belongs to the snapshot's fallback listener.
    /// Runtime grouping by `identity` retains every RSA/ECDSA alternative on
    /// that listener even when only one serialized entry carries the marker.
    pub is_default: bool,
}

/// SNI → certificate index built once per config snapshot.
struct SniIndex {
    /// Listener hostnames are authoritative routing/ownership claims. Keep
    /// them separate from certificate-derived aliases so an unrelated
    /// certificate SAN can never become a signature-compatible fallback for a
    /// name another listener explicitly owns.
    declared_exact: HashMap<String, Vec<Arc<CertifiedKey>>>,
    declared_wildcard: HashMap<String, Vec<Arc<CertifiedKey>>>,
    /// Certificate-derived aliases are considered only when no listener
    /// hostname claims the SNI.
    san_exact: HashMap<String, Vec<Arc<CertifiedKey>>>,
    /// Keyed by the suffix AFTER `*.`, so `*.example.com` is stored as
    /// `example.com` and matched against a client name's parent domain.
    san_wildcard: HashMap<String, Vec<Arc<CertifiedKey>>>,
    fallback: Vec<Arc<CertifiedKey>>,
}

/// The SNI-selecting resolver a Gateway listener serves.
///
/// The index is held in an [`ArcSwap`] rather than inline so a stapled OCSP
/// response can be retired in place once it reaches its `nextUpdate` (issue
/// #4773): the published `Arc<ServerConfig>` is not replaceable without
/// `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`, and the HTTP/3 listener rebuilds
/// its TLS 1.3-only config around this same resolver, so one atomic store is
/// what reaches HTTP/1.1, HTTP/2, HTTP/3 and TCP+TLS together. The handshake
/// path pays one `ArcSwap::load()` and nothing else — no lock, no allocation,
/// no per-request work.
///
/// `Debug` deliberately reports only counts: a `CertifiedKey` holds a live
/// signing key, and a resolver is reachable from broad runtime state dumps.
pub struct SniCertResolver {
    index: ArcSwap<SniIndex>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let index = self.index.load();
        f.debug_struct("SniCertResolver")
            .field(
                "exact_names",
                &(index.declared_exact.len() + index.san_exact.len()),
            )
            .field(
                "wildcard_names",
                &(index.declared_wildcard.len() + index.san_wildcard.len()),
            )
            .finish_non_exhaustive()
    }
}

impl SniIndex {
    /// The certificate candidates a server name selects, or `None` to use the
    /// fallback listener's candidates.
    ///
    /// Declared listener ownership beats every certificate-derived alias;
    /// within each tier exact beats wildcard. Wildcards match a single label,
    /// per RFC 6125 — `*.example.com` covers `a.example.com` but not
    /// `a.b.example.com` and not bare `example.com`.
    fn candidates(&self, server_name: &str) -> Option<&[Arc<CertifiedKey>]> {
        if let Some(certified_keys) = self.declared_exact.get(server_name) {
            return Some(certified_keys);
        }
        let wildcard_parent = server_name.split_once('.').and_then(|(label, parent)| {
            (!label.is_empty() && !parent.is_empty()).then_some(parent)
        });
        if let Some(parent) = wildcard_parent
            && let Some(certified_keys) = self.declared_wildcard.get(parent)
        {
            return Some(certified_keys);
        }
        if let Some(certified_keys) = self.san_exact.get(server_name) {
            return Some(certified_keys);
        }
        wildcard_parent.and_then(|parent| self.san_wildcard.get(parent).map(Vec::as_slice))
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // rustls already lowercases and validates the SNI host_name, and a
        // ClientHello without SNI (or with an unknown one) is answered with the
        // fallback rather than a handshake failure — the same credential a
        // single-certificate listener would have presented.
        let index = self.index.load();
        let signature_schemes = client_hello.signature_schemes();
        if let Some(candidates) = client_hello
            .server_name()
            .and_then(|server_name| index.candidates(server_name))
        {
            // A claimed exact/wildcard name is authoritative. If none of its
            // certificates supports the client's signature schemes, fail the
            // handshake rather than answering that name with an unrelated
            // fallback certificate.
            return select_compatible_certified_key(candidates, signature_schemes);
        }
        select_compatible_certified_key(&index.fallback, signature_schemes)
    }
}

impl StapleRetiringResolver for SniCertResolver {
    /// Publish a stapleless generation of the whole index.
    ///
    /// A staple is attached only when the snapshot serves exactly one
    /// certificate, but that one `Arc<CertifiedKey>` is reachable from several
    /// index entries (its listener hostname, each of its SANs, and the
    /// fallback). Rebuilding through one identity map keeps those entries
    /// pointing at the *same* replacement, so the candidate-set identity the
    /// index was built with survives the retirement.
    fn drop_stapled_ocsp_response(&self) -> bool {
        let current = self.index.load_full();
        let mut replacements: HashMap<usize, Arc<CertifiedKey>> = HashMap::new();
        for certified_key in current
            .declared_exact
            .values()
            .chain(current.declared_wildcard.values())
            .chain(current.san_exact.values())
            .chain(current.san_wildcard.values())
            .flatten()
            .chain(current.fallback.iter())
        {
            if certified_key.ocsp.is_none() {
                continue;
            }
            replacements
                .entry(Arc::as_ptr(certified_key) as usize)
                .or_insert_with(|| {
                    let mut without_staple = (**certified_key).clone();
                    without_staple.ocsp = None;
                    Arc::new(without_staple)
                });
        }
        if replacements.is_empty() {
            return false;
        }
        self.index.store(Arc::new(SniIndex {
            declared_exact: retire_index(&current.declared_exact, &replacements),
            declared_wildcard: retire_index(&current.declared_wildcard, &replacements),
            san_exact: retire_index(&current.san_exact, &replacements),
            san_wildcard: retire_index(&current.san_wildcard, &replacements),
            fallback: retire_candidates(&current.fallback, &replacements),
        }));
        true
    }
}

/// One index map with every stapled credential swapped for its replacement.
fn retire_index(
    names: &HashMap<String, Vec<Arc<CertifiedKey>>>,
    replacements: &HashMap<usize, Arc<CertifiedKey>>,
) -> HashMap<String, Vec<Arc<CertifiedKey>>> {
    names
        .iter()
        .map(|(name, candidates)| (name.clone(), retire_candidates(candidates, replacements)))
        .collect()
}

/// One candidate list with every stapled credential swapped for its
/// replacement, preserving order and the identity relationship between entries.
fn retire_candidates(
    candidates: &[Arc<CertifiedKey>],
    replacements: &HashMap<usize, Arc<CertifiedKey>>,
) -> Vec<Arc<CertifiedKey>> {
    candidates
        .iter()
        .map(|candidate| {
            replacements
                .get(&(Arc::as_ptr(candidate) as usize))
                .cloned()
                .unwrap_or_else(|| candidate.clone())
        })
        .collect()
}

/// First certificate whose signing key can satisfy the ClientHello. One
/// listener may legitimately carry RSA and ECDSA certificateRefs for the same
/// SNI; retaining only the first would make the other credential unreachable.
fn select_compatible_certified_key(
    candidates: &[Arc<CertifiedKey>],
    signature_schemes: &[rustls::SignatureScheme],
) -> Option<Arc<CertifiedKey>> {
    candidates
        .iter()
        .find(|candidate| candidate.key.choose_scheme(signature_schemes).is_some())
        .cloned()
}

/// Build the frontend `ServerConfig` that serves a Gateway's whole certificate
/// set, selecting per ClientHello by SNI.
///
/// Fails closed: if ANY certificate in the set cannot be loaded, parsed,
/// paired, or is expired, the whole config fails and the caller keeps its
/// previous one. Serving a partial set would silently answer some hostnames
/// with the fallback certificate — a name mismatch the operator never asked
/// for — so a broken certificate is a rejected snapshot, not a degraded one.
#[allow(dead_code)] // Public integration-test entry point; production binds an explicit scope.
pub fn load_gateway_multi_cert_tls_config(
    certificates: &[GatewayCertificateInput],
    client_ca_bundle_path: Option<&str>,
    ocsp_response_source: Option<&str>,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    revocation_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<rustls::ServerConfig>, anyhow::Error> {
    load_gateway_multi_cert_tls_config_with_handshake_scope(
        certificates,
        client_ca_bundle_path,
        ocsp_response_source,
        tls_policy,
        cert_expiry_warning_days,
        revocation_expiry_warning_days,
        crls,
        None,
    )
}

/// [`load_gateway_multi_cert_tls_config`] that binds
/// [`crate::tls::client_trust::bind_live_handshake_verifier`] for `handshake_scope`.
///
/// CP-delivered Gateway snapshots must pass
/// [`crate::tls::ClientTrustScope::ProxyFrontend`]: the resulting `ServerConfig`
/// keeps this resolver (the CP server certificate) while handshake-time
/// client-certificate verification reads the live operator verifier and
/// CertificateRequest CA-name hints stay generation-neutral. Without the
/// wrapper, an accepted additive CA/CRL reload would keep rejecting new
/// H1/H2/TCP handshakes against the snapshot's stale inner verifier (issue
/// #3857).
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_gateway_multi_cert_tls_config_with_handshake_scope(
    certificates: &[GatewayCertificateInput],
    client_ca_bundle_path: Option<&str>,
    ocsp_response_source: Option<&str>,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    revocation_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
    handshake_scope: Option<crate::tls::ClientTrustScope>,
) -> Result<Arc<rustls::ServerConfig>, anyhow::Error> {
    if certificates.is_empty() {
        anyhow::bail!("Gateway frontend TLS was requested with no certificate sources");
    }
    if certificates.len() > crate::config::types::MAX_FRONTEND_TLS_CERTIFICATE_SOURCES {
        anyhow::bail!(
            "Gateway frontend TLS certificate set exceeds {} sources",
            crate::config::types::MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
        );
    }
    validate_explicit_listener_claims(certificates)?;

    // A single stapled OCSP response is bound to ONE certificate, so it is
    // only correct to attach while there is exactly one. With several, it is
    // deliberately not attached to any: stapling a response for the wrong
    // certificate breaks handshakes with clients that check staple validity,
    // and guessing which certificate it belongs to is not something the
    // operator asked for.
    let staple_source = match (ocsp_response_source, certificates.len()) {
        (Some(source), 1) => {
            let cert_source = CertSource::parse(source, MaterialKind::Ocsp);
            let material = load_material_blocking(&cert_source, MaterialKind::Ocsp)?;
            let bytes = material.bytes.expose_secret().to_vec();
            // Bounded structural admission here; the certificate-bound half
            // runs in `load_certified_key` against the chain that will serve
            // the response (issue #4300).
            let structure = crate::tls::ocsp::validate_structure(&bytes).map_err(|error| {
                anyhow::anyhow!(
                    "OCSP response source '{}' was rejected: {error}",
                    material.display_source_id
                )
            })?;
            debug!(
                ocsp_source = %material.display_source_id,
                ocsp_der_bytes = structure.der_len,
                ocsp_single_responses = structure.single_responses,
                "Admitted the structure of a stapled OCSP response; certificate binding is \
                 checked against the served leaf and issuer before it is attached"
            );
            Some(StapleSource {
                bytes,
                configured_source_id: cert_source.source_id(),
                display_source_id: material.display_source_id,
            })
        }
        (Some(_), _) => {
            warn!(
                certificate_count = certificates.len(),
                "A stapled OCSP response is configured but this data plane serves several Gateway \
                 certificates; the response is bound to one certificate and is not stapled to any \
                 of them"
            );
            None
        }
        (None, _) => None,
    };

    let mut cert_display = String::new();
    let mut key_display = String::new();
    let mut loaded = Vec::with_capacity(certificates.len());
    let mut accepted_staple: Option<AcceptedStaple> = None;

    for input in certificates {
        let LoadedCertificate {
            certified_key,
            leaf,
            cert_source_id,
            key_source_id,
            accepted_staple: staple,
        } = load_certified_key(
            input,
            staple_source.as_ref(),
            tls_policy,
            cert_expiry_warning_days,
            revocation_expiry_warning_days,
        )?;
        if cert_display.is_empty() {
            cert_display = cert_source_id;
            key_display = key_source_id;
        }
        // A staple is attached only to a single-certificate snapshot, so at
        // most one certificate accepts one.
        if staple.is_some() {
            accepted_staple = staple;
        }

        loaded.push((input, certified_key, leaf));
    }

    let mut declared_exact: HashMap<String, Vec<Arc<CertifiedKey>>> = HashMap::new();
    let mut declared_wildcard: HashMap<String, Vec<Arc<CertifiedKey>>> = HashMap::new();
    let mut san_exact: HashMap<String, Vec<Arc<CertifiedKey>>> = HashMap::new();
    let mut san_wildcard: HashMap<String, Vec<Arc<CertifiedKey>>> = HashMap::new();
    let mut indexed_names = 0usize;
    let mut dropped_names = 0usize;

    // Declared listener hostnames are the operator's routing contract and must
    // never lose an index slot to certificate-derived SANs. Index every one in
    // a first pass; the admitted certificate set is capped at 256, so these
    // always fit under the separate 4096-name ceiling. If this public loader is
    // called with a larger hand-built set, fail the snapshot closed rather than
    // answering a declared hostname with the fallback certificate.
    for (input, certified_key, _) in &loaded {
        let Some(raw_hostname) = input.hostname.as_deref() else {
            continue;
        };
        let hostname = normalize_indexable_sni_name(raw_hostname).ok_or_else(|| {
            anyhow::anyhow!(
                "Gateway certificate {} has an invalid explicit listener hostname",
                input.identity
            )
        })?;
        if !index_sni_name(
            &mut declared_exact,
            &mut declared_wildcard,
            hostname,
            certified_key,
            &input.identity,
            &mut indexed_names,
        ) {
            anyhow::bail!(
                "Gateway frontend TLS explicit listener hostname index exceeds {} entries",
                MAX_SNI_INDEX_ENTRIES
            );
        }
    }

    // Certificate SANs are useful aliases, especially for catch-all listeners,
    // but they are subordinate to declared listener hostnames. Once the bound
    // is reached, omit only additional SAN aliases; no later listener can lose
    // its explicit SNI mapping because those mappings were installed above.
    for (input, certified_key, leaf) in &loaded {
        for name in leaf_dns_sans(leaf)
            .into_iter()
            .filter_map(|name| normalize_indexable_sni_name(&name))
        {
            if !index_sni_name(
                &mut san_exact,
                &mut san_wildcard,
                name,
                certified_key,
                &input.identity,
                &mut indexed_names,
            ) {
                dropped_names += 1;
            }
        }
    }

    if dropped_names > 0 {
        warn!(
            dropped_names,
            limit = MAX_SNI_INDEX_ENTRIES,
            "Gateway frontend TLS SNI index reached its limit; additional certificate SAN aliases \
             were omitted after every declared listener hostname was indexed"
        );
    }

    // The fallback is listener-scoped, not certificate-scoped. If the selected
    // catch-all/default listener carries RSA + ECDSA refs, retain both so an
    // unmatched/no-SNI ClientHello can negotiate a compatible signing key.
    // A snapshot with no marker (older CP / hand-written config) uses the first
    // listener identity in deterministic input order.
    let fallback_identity = certificates
        .iter()
        .find(|input| input.is_default)
        .or_else(|| certificates.first())
        .map(|input| input.identity.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Gateway frontend TLS produced no fallback listener identity")
        })?;
    let fallback: Vec<Arc<CertifiedKey>> = loaded
        .iter()
        .filter(|(input, _, _)| input.identity == fallback_identity)
        .map(|(_, certified_key, _)| certified_key.clone())
        .collect();
    if fallback.is_empty() {
        anyhow::bail!("Gateway frontend TLS produced no usable fallback certificate");
    }

    info!(
        certificate_count = certificates.len(),
        declared_exact_names = declared_exact.len(),
        declared_wildcard_names = declared_wildcard.len(),
        san_exact_names = san_exact.len(),
        san_wildcard_names = san_wildcard.len(),
        "Built SNI-aware Gateway frontend TLS certificate resolver"
    );

    let sni_resolver = Arc::new(SniCertResolver {
        index: ArcSwap::new(Arc::new(SniIndex {
            declared_exact,
            declared_wildcard,
            san_exact,
            san_wildcard,
            fallback,
        })),
    });
    // ACME TLS-ALPN-01 validation still wins over SNI selection, exactly as it
    // does on a single-certificate listener.
    let resolver = Arc::new(crate::tls::acme::AcmeTlsAlpnResolver::with_resolver(
        sni_resolver,
    ));
    // Issue #4773: hand the exact resolver this snapshot installs to the
    // periodic re-check, which retires the staple once it reaches
    // `nextUpdate`. Without this the Gateway frontend validated a staple,
    // recorded its deadline, and then served it forever — the single
    // certificate path has been enrolled since issue #4505 item 4.
    if let Some(accepted_staple) = accepted_staple {
        accepted_staple.enroll(&resolver);
    }
    let client_ca_source =
        client_ca_bundle_path.map(|source| CertSource::parse(source, MaterialKind::CaBundle));

    crate::tls::finish_frontend_server_config(
        resolver,
        client_ca_source.as_ref(),
        false,
        tls_policy,
        cert_expiry_warning_days,
        crls,
        &cert_display,
        &key_display,
        handshake_scope,
    )
}

/// Revalidate listener ownership on the data plane before loading key material.
///
/// Kubernetes translation already withdraws an explicit-hostname collision,
/// but ConfigSync is still a hostile serialization boundary. A buggy or
/// compromised control plane must not be able to bypass that decision and make
/// the resolver combine two listeners' different certificate sets as signing
/// candidates for one claimed name. One listener identity must also carry one
/// consistent hostname across all of its certificateRefs.
fn validate_explicit_listener_claims(
    certificates: &[GatewayCertificateInput],
) -> Result<(), anyhow::Error> {
    let mut listener_hostnames: HashMap<&str, Option<String>> = HashMap::new();
    let mut listener_certificates: HashMap<(String, &str), Vec<(String, String)>> = HashMap::new();

    for input in certificates {
        let hostname = input
            .hostname
            .as_deref()
            .map(|hostname| {
                normalize_indexable_sni_name(hostname).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Gateway certificate entry has an invalid explicit listener hostname"
                    )
                })
            })
            .transpose()?;
        match listener_hostnames.entry(input.identity.as_str()) {
            Entry::Occupied(entry) if entry.get() != &hostname => {
                anyhow::bail!(
                    "Gateway frontend TLS listener identity carries inconsistent hostname claims"
                );
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(hostname.clone());
            }
        }
        if let Some(hostname) = hostname {
            listener_certificates
                .entry((hostname, input.identity.as_str()))
                .or_default()
                .push((input.cert_source.clone(), input.key_source.clone()));
        }
    }

    let mut hostname_certificates: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for ((hostname, _identity), certificate_set) in listener_certificates {
        match hostname_certificates.entry(hostname) {
            Entry::Occupied(entry) if entry.get() != &certificate_set => {
                anyhow::bail!(
                    "Gateway frontend TLS snapshot contains conflicting certificate sets for one explicit listener hostname"
                );
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(certificate_set);
            }
        }
    }
    Ok(())
}

/// The configured stapled OCSP response, loaded and structurally admitted, with
/// the identities [`crate::tls::ocsp_recheck`] needs to track and retire it.
struct StapleSource {
    bytes: Vec<u8>,
    /// The operator's configured source string — the TLS inventory's
    /// `source.identifier`, so a retirement reaches the right entry.
    configured_source_id: String,
    /// The already-redacted display id, the only form ever logged.
    display_source_id: String,
}

/// One loaded Gateway certificate, plus the staple acceptance it produced.
struct LoadedCertificate {
    certified_key: Arc<CertifiedKey>,
    leaf: CertificateDer<'static>,
    cert_source_id: String,
    key_source_id: String,
    /// `Some` only for the single certificate a staple was attached to; it must
    /// be enrolled with the resolver that ends up serving it.
    accepted_staple: Option<AcceptedStaple>,
}

/// Load and pair one certificate, returning it plus its parsed leaf DER.
fn load_certified_key(
    input: &GatewayCertificateInput,
    staple_source: Option<&StapleSource>,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    revocation_expiry_warning_days: u64,
) -> Result<LoadedCertificate, anyhow::Error> {
    let cert_source = CertSource::parse(input.cert_source.as_str(), MaterialKind::Cert);
    let key_source = CertSource::parse(input.key_source.as_str(), MaterialKind::Key);
    if matches!(&key_source, CertSource::Uri(uri) if uri.scheme == SourceScheme::Pkcs11) {
        anyhow::bail!(
            "Gateway certificate {} uses a PKCS#11 key source, which the multi-certificate \
             frontend does not support",
            input.identity
        );
    }

    let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert)?;
    crate::tls::check_cert_expiry_from_pem_bytes(
        cert_material.bytes.expose_secret(),
        "Gateway server TLS cert",
        &cert_material.display_source_id,
        cert_expiry_warning_days,
    )?;
    let cert_chain = crate::tls::parse_pem_certificate_bundle(
        cert_material.bytes.expose_secret(),
        "Gateway server TLS cert",
        &cert_material.display_source_id,
    )?;
    let leaf = cert_chain.first().cloned().ok_or_else(|| {
        anyhow::anyhow!("Gateway certificate {} has an empty chain", input.identity)
    })?;

    let key_material = load_material_blocking(&key_source, MaterialKind::Key)?;
    let key = crate::tls::parse_pem_private_key(
        key_material.bytes.expose_secret(),
        "Gateway server TLS private key",
        &key_material.display_source_id,
    )?;

    // Issue #4300: bind the staple to this exact leaf/issuer before it can be
    // served. `staple_source` is only `Some` when the data plane serves a
    // single certificate, so the response and the chain below are the pair the
    // client will actually see. Acceptance goes through the shared
    // `crate::tls::ocsp_recheck` helper, which is also the only way a staple
    // becomes trackable — that is what keeps a certificate source from being
    // added without enrolment (issue #4773, refs #4792).
    let accepted_staple = staple_source
        .map(|staple| {
            crate::tls::ocsp_recheck::accept_stapled_response(
                &staple.bytes,
                &cert_chain,
                StapleTarget::GatewayCertificate(input.identity.as_str()),
                staple.configured_source_id.clone(),
                staple.display_source_id.clone(),
                revocation_expiry_warning_days,
            )
        })
        .transpose()?;

    let mut certified_key =
        CertifiedKey::from_der(cert_chain, key, tls_policy.crypto_provider.as_ref()).map_err(
            |error| {
                anyhow::anyhow!(
                    "Gateway certificate {} cert and key do not form a valid pair: {error}",
                    input.identity
                )
            },
        )?;
    if let Some(staple) = staple_source {
        certified_key.ocsp = Some(staple.bytes.clone());
    }

    Ok(LoadedCertificate {
        certified_key: Arc::new(certified_key),
        leaf,
        cert_source_id: cert_material.display_source_id,
        key_source_id: key_material.display_source_id,
        accepted_staple,
    })
}

/// Add one normalized name without allowing derived aliases to grow the index
/// past its fixed bound. Returns `false` only when this would be a new entry at
/// capacity; duplicate names append bounded signature-compatible candidates in
/// deterministic input order.
fn index_sni_name(
    exact: &mut HashMap<String, Vec<Arc<CertifiedKey>>>,
    wildcard: &mut HashMap<String, Vec<Arc<CertifiedKey>>>,
    name: String,
    certified_key: &Arc<CertifiedKey>,
    identity: &str,
    indexed_names: &mut usize,
) -> bool {
    let wildcard_parent = name
        .strip_prefix("*.")
        .filter(|parent| !parent.is_empty())
        .map(str::to_string);
    let (map, key) = match wildcard_parent {
        Some(parent) => (wildcard, parent),
        None => (exact, name),
    };
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(entry) => {
            if !entry
                .get()
                .iter()
                .any(|existing| Arc::ptr_eq(existing, certified_key))
            {
                debug!(
                    server_name = %entry.key(),
                    certificate = identity,
                    "Gateway certificate added as another signature-compatible candidate for this SNI name"
                );
                entry.into_mut().push(certified_key.clone());
            }
            true
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            if *indexed_names >= MAX_SNI_INDEX_ENTRIES {
                return false;
            }
            entry.insert(vec![certified_key.clone()]);
            *indexed_names += 1;
            true
        }
    }
}

/// Canonicalize a listener hostname or certificate SAN for rustls lookup.
/// Gateway translation already emits this shape, but the runtime also accepts
/// native/ConfigSync snapshots and therefore defends the boundary itself.
fn normalize_indexable_sni_name(name: &str) -> Option<String> {
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    is_indexable_sni_name(&normalized).then_some(normalized)
}

/// DNS SANs of a leaf certificate, ASCII-lowercased.
///
/// A certificate that cannot be parsed here is not an error: it already passed
/// `CertifiedKey::from_der`, so it is usable — it simply contributes no
/// SAN-derived names and stays reachable by listener hostname or fallback.
fn leaf_dns_sans(leaf: &CertificateDer<'_>) -> Vec<String> {
    let Ok((_, certificate)) = X509Certificate::from_der(leaf.as_ref()) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for general_name in &san.general_names {
                if let GeneralName::DNSName(value) = general_name {
                    names.push(value.to_ascii_lowercase());
                }
            }
        }
    }
    names
}

/// Whether a name is safe to put in the SNI index.
///
/// Rejects the bare `*` catch-all (that is the fallback slot's job, not a
/// wildcard entry), empty labels, over-long names, and anything outside the
/// LDH + `*.` shape a ClientHello `server_name` can carry — a name rustls would
/// never present cannot be matched and would only take up index space.
fn is_indexable_sni_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || name == "*" {
        return false;
    }
    let candidate = name.strip_prefix("*.").unwrap_or(name);
    if candidate.is_empty() {
        return false;
    }
    candidate.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_certified_key(
        algorithm: &'static rcgen::SignatureAlgorithm,
        dns_name: &str,
    ) -> Arc<CertifiedKey> {
        let key_pair = rcgen::KeyPair::generate_for(algorithm).expect("test key pair");
        let params = rcgen::CertificateParams::new(vec![dns_name.to_string()])
            .expect("test certificate parameters");
        let certificate = params.self_signed(&key_pair).expect("test certificate");
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("test private key DER");
        let provider = rustls::crypto::ring::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(private_key)
            .expect("test signing key");
        Arc::new(CertifiedKey::new(
            vec![certificate.der().clone()],
            signing_key,
        ))
    }

    #[test]
    fn indexable_sni_names_reject_unusable_shapes() {
        assert!(is_indexable_sni_name("api.example.com"));
        assert!(is_indexable_sni_name("*.example.com"));
        assert!(!is_indexable_sni_name("*"));
        assert!(!is_indexable_sni_name(""));
        assert!(!is_indexable_sni_name("a..b"));
        assert!(!is_indexable_sni_name("a_b.example.com"));
        assert!(!is_indexable_sni_name("-api.example.com"));
        assert!(!is_indexable_sni_name("api-.example.com"));
        assert!(!is_indexable_sni_name(&"a".repeat(254)));
    }

    #[test]
    fn one_sni_keeps_and_selects_signature_compatible_certificate_candidates() {
        let ecdsa = test_certified_key(&rcgen::PKCS_ECDSA_P256_SHA256, "api.example.com");
        let ed25519 = test_certified_key(&rcgen::PKCS_ED25519, "api.example.com");
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        let mut indexed_names = 0;
        assert!(index_sni_name(
            &mut exact,
            &mut wildcard,
            "api.example.com".to_string(),
            &ecdsa,
            "ferrum/edge/https",
            &mut indexed_names,
        ));
        assert!(index_sni_name(
            &mut exact,
            &mut wildcard,
            "api.example.com".to_string(),
            &ed25519,
            "ferrum/edge/https",
            &mut indexed_names,
        ));

        let candidates = exact.get("api.example.com").expect("SNI candidates");
        assert_eq!(indexed_names, 1, "the bound counts names, not algorithms");
        assert_eq!(candidates.len(), 2);
        let selected =
            select_compatible_certified_key(candidates, &[rustls::SignatureScheme::ED25519])
                .expect("Ed25519 candidate");
        assert!(Arc::ptr_eq(&selected, &ed25519));
        assert!(
            select_compatible_certified_key(
                candidates,
                &[rustls::SignatureScheme::RSA_PKCS1_SHA256],
            )
            .is_none(),
            "an SNI with no compatible key must fail instead of falling back"
        );
    }

    #[test]
    fn declared_listener_names_cannot_fall_through_to_unrelated_san_candidates() {
        let declared = test_certified_key(&rcgen::PKCS_ECDSA_P256_SHA256, "claimed.example.com");
        let san_alias = test_certified_key(&rcgen::PKCS_ED25519, "alias.example.com");
        let index = SniIndex {
            declared_exact: HashMap::from([(
                "claimed.example.com".to_string(),
                vec![declared.clone()],
            )]),
            declared_wildcard: HashMap::from([("example.net".to_string(), vec![declared.clone()])]),
            san_exact: HashMap::from([
                ("claimed.example.com".to_string(), vec![san_alias.clone()]),
                ("api.example.net".to_string(), vec![san_alias.clone()]),
                ("unclaimed.example.org".to_string(), vec![san_alias.clone()]),
            ]),
            san_wildcard: HashMap::new(),
            fallback: vec![san_alias.clone()],
        };

        let exact_claim = index
            .candidates("claimed.example.com")
            .expect("declared exact candidates");
        assert_eq!(exact_claim.len(), 1);
        assert!(Arc::ptr_eq(&exact_claim[0], &declared));

        let wildcard_claim = index
            .candidates("api.example.net")
            .expect("declared wildcard candidates");
        assert_eq!(wildcard_claim.len(), 1);
        assert!(Arc::ptr_eq(&wildcard_claim[0], &declared));

        let unclaimed_alias = index
            .candidates("unclaimed.example.org")
            .expect("unclaimed SAN alias candidates");
        assert_eq!(unclaimed_alias.len(), 1);
        assert!(Arc::ptr_eq(&unclaimed_alias[0], &san_alias));
    }
}
