//! Frontend client-trust (CRL / client-CA) generations and established-transport
//! retirement (issue #3857).
//!
//! # The problem this module owns
//!
//! Frontend TLS live reload rebuilds the verifier material used for **new
//! handshakes**. An already-established TLS transport keeps the verifier
//! generation it negotiated, so after an operator publishes a new CRL or removes
//! a CA from the client-CA bundle, the holder of a pre-reload connection could
//! keep opening new H2/H3 streams and new H1 keep-alive requests, and keep an
//! active WebSocket / TCP+TLS / DTLS session alive, under the *withdrawn* trust
//! decision. Certificate **expiry** is a different control and is enforced
//! elsewhere; this module is about an operator explicitly withdrawing authority.
//!
//! # Model
//!
//! Every frontend listener family that terminates client-certificate
//! authentication belongs to exactly one [`ClientTrustScope`] — a fixed,
//! compile-time set.
//!
//! A scope is **armed only when the exact accepted candidate that listener
//! family installed actually performs verified client-certificate
//! authentication**. A listener with no client-CA source, or with verification
//! explicitly disabled, can never hold a credential an operator could withdraw:
//! arming it would publish an empty baseline, export retirement metrics for a
//! protection with nothing to protect, and make [`capture`] return `Some` on
//! every accept — which is what made TCP+TLS decline the kTLS fast path on
//! listeners that do no client authentication at all. Certificate/key-only
//! rotation is unaffected and simply reloads without a trust generation.
//!
//! An armed scope owns one [`ClientTrustDomain`]:
//!
//! - `generation` — monotonically advancing, bumped **only** after a validated,
//!   accepted candidate that *semantically* differs from the last accepted one.
//!   A malformed or unloadable candidate never reaches this module (the caller's
//!   rebuild fails first) and is recorded as `rejected`, retaining the last-good
//!   verifier, generation, material and sessions.
//! - `withdrawal_generation` — the generation at which authority was last
//!   *narrowed* (a trust anchor disappeared, or a new revocation appeared). This
//!   is the fence: a client-certificate-authenticated transport whose captured
//!   generation is strictly below it is retired and may admit no further work.
//!
//! An additive change (a CA added, a revocation removed, a CRL re-issued with the
//! same revocation set, a server cert/key rotation) advances `generation` only
//! when it is semantically different at all, and never moves
//! `withdrawal_generation` — so unaffected sessions are not churned.
//!
//! # Ordering, and why it fails closed
//!
//! rustls surfaces that install [`bind_live_handshake_verifier`] (proxy H1/H2
//! and TCP+TLS, admin HTTPS, H3/QUIC) each own exactly one
//! [`ClientTrustScope`] and publish an accepted candidate through **one**
//! [`publish_accepted_rustls_candidate`] transaction for that singular scope,
//! and only after every fallible build/validation step has succeeded. That
//! transaction holds the scope publication lock continuously across:
//!
//! **(1)** store the candidate's inner rustls verifier, **(2)** run the
//! already-validated, infallible config exposure/adoption (slot swap /
//! `Endpoint::set_server_config`), **(3)** store that same candidate's
//! material, bump `generation`, **(4)** store `withdrawal_generation` when
//! authority narrowed, **(5)** sweep registered sessions.
//!
//! Installing the stricter verifier slightly before its config is conservative:
//! a handshake that still holds a stale config consults the live object and
//! refuses withdrawn credentials. A handshake that loads the new config before
//! the generation advances also consults that live object, so it cannot admit a
//! credential V2 withdrew while `active()` still saw global V1. Holding the
//! lock across those steps is what keeps concurrent V2/V3 publications from
//! cross-wiring verifier V3 with config/material V2 (or the converse). Do
//! **not** expose a config outside this transaction, and do **not** enter it
//! before a fallible step that could reject the candidate. A refused candidate
//! never enters the transaction and is recorded with
//! [`record_rejected_candidate`], retaining last-good material.
//!
//! Admission is the mirror image: a listener [`capture`]s the generation
//! **before** it loads the config it will hand to the handshake. Because the
//! publisher writes the config before the generation, a reader that observes the
//! new generation provably observed the new config; a reader that observes the
//! old generation may have picked up either config. So the captured generation is
//! always *at or older than* the material actually used — the conservative
//! direction. The cost is that a connection handshaking exactly across a
//! withdrawal can be retired despite already using the new material; the benefit
//! is that one can never escape the fence.
//!
//! One path does not achieve that ordering by capture placement: the TCP+TLS
//! accept loop snapshots the frontend TLS slot for a connection before
//! `handle_tcp_connection_inner` reads the generation, so it can hold a
//! post-withdrawal generation beside a pre-withdrawal `ServerConfig`. It is
//! covered instead by the post-handshake re-verification described next —
//! because the verifier is installed before the generation advances, a
//! connection observing generation G meets a verifier at or newer than G. There
//! [`armed_handshake_der_chain_still_trusted`] is load-bearing rather than
//! defence in depth, and the call site says so.
//!
//! rustls bakes the `ClientCertVerifier` into each `ServerConfig` snapshot, so
//! swapping a slot or calling `Endpoint::set_server_config` does not rewrite a
//! TlsAcceptor / QUIC endpoint config already in hand. Every rustls listener
//! therefore installs [`bind_live_handshake_verifier`]: handshake-time
//! `verify_client_cert` reads the live published verifier, even when the
//! `ServerConfig` itself was built under a withdrawn generation. Certificate
//! Request CA-name hints are generation-neutral (an empty list, so rustls
//! omits or does not constrain `certificate_authorities`); advertising the
//! snapshot inner verifier's names would let a client that honors those hints
//! withhold a certificate issued by a CA added after this `ServerConfig` was
//! built. A second, independent fail-closed check re-runs the peer chain
//! against [`armed_handshake_still_trusted`] after TLS so a missing peer chain
//! (session resumption does not re-verify) cannot be served either. The
//! wrapper is installed only at `with_client_cert_verifier` time;
//! [`AcceptedClientTrust::verifier`](super::AcceptedClientTrust) and
//! [`publish_accepted_rustls_candidate`] keep the inner WebPki object so the
//! live slot never points at the wrapper itself.
//!
//! DTLS has no rustls live handshake verifier. It keeps the distinct
//! config-before-generation order: the DTLS generation is published into every
//! active `DtlsServer` first, then [`publish_accepted_material`] advances the
//! trust generation with `verifier = None`.
//!
//! The registration race is closed the same way, without a lock: a session is
//! inserted into the domain first and then re-checks the fence. A publication
//! that swept before the insert is caught by the re-check; one that swept after
//! sees the entry. A retired session can never be repopulated, because
//! [`ClientTrustSession::retire`] latches and [`ClientTrustSession::is_retired`]
//! is what every admission gate consults.
//!
//! # Scope of retirement
//!
//! Retirement is deliberately **conservative within a scope**: every
//! client-certificate-authenticated transport in the changed scope is retired,
//! rather than only those whose chain or serial is provably affected. Deciding
//! per-connection impact would require re-running path building against the
//! retained chain for every live transport at publish time, and getting it wrong
//! fails *open*. Precision is instead applied where it is safe — in the
//! **semantic diff** ([`ClientTrustMaterial::withdrawal_relative_to`]), which
//! refuses to retire anything at all unless authority actually narrowed.
//!
//! # Redaction
//!
//! Nothing here records or labels a serial, subject, issuer name, fingerprint,
//! key identifier, SPKI digest, certificate path, or any secret material. The
//! material comparison keys are SHA-256 digests held in memory only; metric
//! labels are the closed [`ClientTrustScope`] and
//! [`ClientTrustRetirementReason`] vocabularies.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};

use crate::fips::approved::Sha256;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
use x509_parser::prelude::{FromDer, ParsedExtension, SubjectPublicKeyInfo, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

/// Compiled-in close / error reason when a handshake's peer no longer satisfies
/// the live verifier. Never interpolate a serial, subject, issuer, path, or
/// digest into this string — it is what goes on the wire and into logs.
pub const TRUST_WITHDRAWN_REASON: &str = "client certificate trust withdrawn";

/// The closed set of frontend listener families that terminate client
/// certificates and therefore own a client-trust generation.
///
/// `scope` is a compile-time closed metric dimension: a per-listener or
/// per-certificate label would be unbounded cardinality and would leak
/// deployment topology into a scrape. Trust-specific dimensions (`scope`,
/// `outcome`, `reason`) stay on closed vocabularies; the rendered registry
/// also appends the standard configured `namespace` label.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ClientTrustScope {
    /// Proxy HTTPS / HTTP-2 listeners **and** TCP+TLS stream listeners. Both
    /// terminate with the same startup-loaded proxy frontend `ServerConfig`
    /// (`FERRUM_FRONTEND_TLS_*` + `FERRUM_TLS_CRL_FILE_PATH`), so they are one
    /// trust domain.
    ProxyFrontend,
    /// The QUIC / HTTP-3 listener. Separate from [`Self::ProxyFrontend`] even
    /// though the same operator sources feed both, because the H3 endpoint
    /// applies a reload asynchronously (`Endpoint::set_server_config` after the
    /// revision watch fires). Publishing its generation from the H3 listener
    /// itself is what keeps "captured generation ≤ material actually used" true
    /// there — and the material it publishes is the identity carried by the
    /// exact accepted candidate it installed, never `ProxyFrontend`'s latest.
    ProxyH3,
    /// The admin HTTPS listener (`FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`).
    ///
    /// Both admin accept loops — the static `ServerConfig` one and the
    /// hot-swappable slot one — capture this scope's generation before they
    /// select the config for a handshake, register the connection when rustls
    /// authenticated a peer client certificate, hold the guard for the whole
    /// admin connection, refuse a request buffered on a retired connection
    /// before it enters admin routing, and end that connection through hyper's
    /// own graceful shutdown.
    AdminHttps,
    /// Frontend UDP + DTLS listeners (`FERRUM_DTLS_*`).
    FrontendDtls,
}

impl ClientTrustScope {
    /// Every scope, in index order.
    pub const ALL: [ClientTrustScope; 4] = [
        ClientTrustScope::ProxyFrontend,
        ClientTrustScope::ProxyH3,
        ClientTrustScope::AdminHttps,
        ClientTrustScope::FrontendDtls,
    ];

    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustScope::ProxyFrontend => "proxy_frontend",
            ClientTrustScope::ProxyH3 => "proxy_h3",
            ClientTrustScope::AdminHttps => "admin_https",
            ClientTrustScope::FrontendDtls => "frontend_dtls",
        }
    }

    const fn index(self) -> usize {
        match self {
            ClientTrustScope::ProxyFrontend => 0,
            ClientTrustScope::ProxyH3 => 1,
            ClientTrustScope::AdminHttps => 2,
            ClientTrustScope::FrontendDtls => 3,
        }
    }
}

/// Closed set of reasons an established transport is retired.
///
/// Ordered by precedence: a candidate that both withdraws a CA and adds a
/// revocation reports [`Self::ClientCaWithdrawn`], the broader change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientTrustRetirementReason {
    /// A trust anchor present in the last accepted client-CA bundle is absent
    /// from the accepted candidate.
    ClientCaWithdrawn,
    /// The accepted candidate revokes at least one (signer-key, serial) pair
    /// that the last accepted CRL set did not.
    CrlChanged,
}

impl ClientTrustRetirementReason {
    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustRetirementReason::ClientCaWithdrawn => "client_ca_withdrawn",
            ClientTrustRetirementReason::CrlChanged => "crl_changed",
        }
    }

    const fn index(self) -> usize {
        match self {
            ClientTrustRetirementReason::ClientCaWithdrawn => 0,
            ClientTrustRetirementReason::CrlChanged => 1,
        }
    }

    const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(ClientTrustRetirementReason::ClientCaWithdrawn),
            1 => Some(ClientTrustRetirementReason::CrlChanged),
            _ => None,
        }
    }
}

const REASON_COUNT: usize = 2;
const SCOPE_COUNT: usize = ClientTrustScope::ALL.len();
/// Sentinel stored in `last_withdrawal_reason` before any withdrawal.
const NO_REASON: u8 = u8::MAX;

/// Outcome of one publication attempt, for logs and metrics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientTrustPublicationOutcome {
    /// The scope had no accepted material yet; this candidate became the
    /// baseline. Never retires anything.
    Armed,
    /// The candidate is byte-for-byte semantically equal to the last accepted
    /// material. The generation does **not** advance and no session is touched.
    Unchanged,
    /// The candidate is semantically different but does not narrow authority
    /// (a CA was added, a revocation disappeared, a CRL was re-issued with new
    /// validity dates over the same revocation set). The generation advances;
    /// no session is retired.
    Advanced,
    /// The candidate narrows authority. The generation advances, the fence
    /// moves, and every client-certificate-authenticated session below the new
    /// generation is retired.
    Withdrawn,
}

impl ClientTrustPublicationOutcome {
    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustPublicationOutcome::Armed => "armed",
            ClientTrustPublicationOutcome::Unchanged => "unchanged",
            ClientTrustPublicationOutcome::Advanced => "advanced",
            ClientTrustPublicationOutcome::Withdrawn => "withdrawn",
        }
    }
}

/// Result of [`publish_accepted_material`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClientTrustPublication {
    /// The scope that was published into.
    pub scope: ClientTrustScope,
    /// The generation in force after the publication.
    pub generation: u64,
    /// What the publication did.
    pub outcome: ClientTrustPublicationOutcome,
    /// Why sessions were retired, when they were.
    pub reason: Option<ClientTrustRetirementReason>,
    /// How many established transports this publication retired.
    pub retired_sessions: usize,
}

impl ClientTrustPublication {
    /// Whether this publication narrowed authority and moved the admission
    /// fence. Callers log and alert on exactly this condition.
    pub fn withdrew(&self) -> bool {
        self.outcome == ClientTrustPublicationOutcome::Withdrawn
    }
}

/// The semantic identity of one accepted frontend client-trust snapshot.
///
/// Two snapshots compare equal exactly when they grant the same authority to the
/// same principals. Deliberately **not** a byte hash of the source material: a
/// CRL is normally re-issued on a schedule with a fresh `thisUpdate` /
/// `nextUpdate` / `crlNumber` and an unchanged revocation set, and treating that
/// as a change would advance the generation (and, with a naive fence, retire
/// every live session) on every routine re-issue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTrustMaterial {
    /// SHA-256 over each client-CA trust anchor's DER, deduplicated and sorted.
    /// Anchor *order* in the bundle is not authority, so the set is the identity.
    anchors: BTreeSet<[u8; 32]>,
    /// SHA-256 over `issuer-key identity || 0x00 || serial DER` for every
    /// revoked entry across every parsed CRL. The issuer-key identity is a
    /// domain-tagged digest of the uniquely verified signer SPKI when that
    /// key is in the accepted client-CA bundle. When the signer is not in the
    /// bundle, the complete signed CRL is included in the conservative issuer
    /// identity because issuer DN and Authority Key Identifier are both
    /// attacker-selectable and cannot prove key identity on their own. Serial
    /// numbers are unique only under one issuing key: two CA keys can share a
    /// subject DN, AKI, and leaf serial, so scoping by any of those fields would
    /// let a revocation under the second key collide with the first and suppress
    /// `CrlChanged`.
    revocations: BTreeSet<[u8; 32]>,
}

/// Domain tag mixed into a revocation identity derived from a verified signer
/// SubjectPublicKeyInfo. Distinct from [`ISSUER_DOMAIN_UNVERIFIED_CRL`] so an
/// unverified CRL digest cannot collide with a raw SPKI.
const ISSUER_DOMAIN_SPKI: &[u8] = b"spki";
/// Domain tag mixed into a conservative per-CRL identity when the signer is
/// not in the accepted anchor bundle and its SPKI therefore cannot be verified
/// here. Reissues conservatively produce a new identity and retire established
/// sessions; that availability cost avoids trusting attacker-selectable issuer
/// names or Authority Key Identifiers as cryptographic key identities.
const ISSUER_DOMAIN_UNVERIFIED_CRL: &[u8] = b"unverified-crl";

/// A CRL that this module could not parse.
///
/// Surfaced to the caller so an unusable candidate is recorded as `rejected` and
/// the last accepted generation, verifier and sessions are all retained. The
/// error carries no bytes, no path, and no certificate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTrustMaterialError;

impl std::fmt::Display for ClientTrustMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("frontend client-trust material could not be parsed")
    }
}

impl std::error::Error for ClientTrustMaterialError {}

impl ClientTrustMaterial {
    /// Build the semantic identity from an already-validated candidate.
    ///
    /// `client_ca_pem` is the client-CA bundle exactly as handed to the verifier
    /// builder (`None` when the listener does no client authentication);
    /// `crls` is the accepted CRL list. Both must come from the **same** accepted
    /// generation as the `ServerConfig` the caller is about to publish, or the
    /// fence would describe material that was never served.
    pub fn from_parts(
        client_ca_pem: Option<&[u8]>,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Self, ClientTrustMaterialError> {
        let mut anchors = BTreeSet::new();
        let mut anchor_ders = Vec::new();
        if let Some(pem) = client_ca_pem {
            let mut reader = pem;
            let mut parsed_any = false;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|_| ClientTrustMaterialError)?;
                // PEM framing only proves the block was base64-decodable.
                // `rustls_pemfile::certs` does not require those bytes to be a
                // complete X.509 certificate, so hashing here would invent a
                // trust-anchor identity the verifier cannot accept. Parse
                // errors and trailing/unconsumed DER fail the whole candidate
                // closed; a valid block is never kept while a later one is
                // skipped.
                let (remaining, _) = X509Certificate::from_der(cert.as_ref())
                    .map_err(|_| ClientTrustMaterialError)?;
                if !remaining.is_empty() {
                    return Err(ClientTrustMaterialError);
                }
                parsed_any = true;
                let der = cert.as_ref().to_vec();
                anchors.insert(digest_of(&[&der]));
                anchor_ders.push(der);
            }
            // `rustls_pemfile::certs` skips PEM sections it cannot recognize.
            // A configured client-CA source containing only malformed material
            // can therefore yield an empty successful iterator rather than an
            // item-level parse error. Treating that as an empty trust set would
            // summarize and publish material the verifier rejected. `Some`
            // means client authentication was configured, so at least one
            // complete X.509 certificate is mandatory.
            if !parsed_any {
                return Err(ClientTrustMaterialError);
            }
        }

        let mut parsed_anchors = Vec::with_capacity(anchor_ders.len());
        for der in &anchor_ders {
            let (remaining, cert) =
                X509Certificate::from_der(der).map_err(|_| ClientTrustMaterialError)?;
            if !remaining.is_empty() {
                return Err(ClientTrustMaterialError);
            }
            parsed_anchors.push(cert);
        }
        let unique_signers = unique_signer_spkis(&parsed_anchors);

        let mut revocations = BTreeSet::new();
        for crl in crls {
            let (remaining, parsed) = CertificateRevocationList::from_der(crl.as_ref())
                .map_err(|_| ClientTrustMaterialError)?;
            if !remaining.is_empty() {
                return Err(ClientTrustMaterialError);
            }
            let issuer_key = crl_signer_key_identity(&parsed, &unique_signers)?;
            for revoked in parsed.iter_revoked_certificates() {
                revocations.insert(digest_of(&[
                    issuer_key.as_slice(),
                    &[0x00],
                    revoked.raw_serial(),
                ]));
            }
        }

        Ok(Self {
            anchors,
            revocations,
        })
    }

    /// Build a distinguishable identity for pairing tests. **Test seam only.**
    ///
    /// Production material always comes from [`Self::from_parts`] over the exact
    /// client-CA bytes and CRLs behind a verifier. This digest is never a
    /// certificate fingerprint that could leak into logs or metrics.
    ///
    /// Compiled out of every shipping profile; see
    /// [`reset_for_test`](crate::tls::client_trust::reset_for_test) for the gate
    /// and why it is drawn there.
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    #[allow(dead_code)] // External test seam only.
    pub fn from_test_digest(digest: [u8; 32]) -> Self {
        let mut anchors = BTreeSet::new();
        anchors.insert(digest);
        Self {
            anchors,
            revocations: BTreeSet::new(),
        }
    }

    /// Decide whether moving from `previous` to `self` **narrows** the authority
    /// an already-authenticated peer holds.
    ///
    /// Returns `None` for every widening or lateral change, which is what keeps
    /// an additive CA rotation (new CA appended, overlapping with the old) and a
    /// routine CRL re-issue from churning live sessions.
    ///
    /// # Retirement is a superset of enforcement, and stays that way
    ///
    /// `revocations` hashes **every** entry in every configured CRL. It cannot
    /// do otherwise: a CRL entry is an issuer key plus a serial number and
    /// carries nothing that distinguishes an end-entity serial from a CA serial,
    /// so `from_parts` cannot narrow the set without the revoked certificates
    /// themselves.
    ///
    /// Since issue #4298 the verifier those CRLs are installed on checks every
    /// non-trust-anchor certificate in the built chain (`tls::crl_policy`), so
    /// publishing a CRL that revokes an **intermediate CA** now both retires the
    /// scope's sessions and refuses the reconnect — the retirement and the
    /// enforcement finally agree. The set is still a superset, because an entry
    /// naming a serial no chain presents retires sessions nothing would have
    /// rejected. That direction is the fail-closed one: it can only end sessions
    /// that would have survived, never keep one alive that should have ended.
    /// Documented for operators in `docs/frontend_tls.md`.
    pub fn withdrawal_relative_to(
        &self,
        previous: &ClientTrustMaterial,
    ) -> Option<ClientTrustRetirementReason> {
        // A trust anchor that used to be accepted and no longer is invalidates
        // every chain that terminated at it. Checked first: it is the broader
        // withdrawal, and a bundle rotation commonly lands together with a CRL
        // update.
        if !previous.anchors.is_subset(&self.anchors) {
            return Some(ClientTrustRetirementReason::ClientCaWithdrawn);
        }
        // A revocation that is present now and was not before is a withdrawal of
        // exactly one credential. Removing a revocation, or re-issuing the same
        // set under new validity dates, is not.
        if !self.revocations.is_subset(&previous.revocations) {
            return Some(ClientTrustRetirementReason::CrlChanged);
        }
        None
    }
}

fn digest_of(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// Deduplicate accepted client-CA anchors by SubjectPublicKeyInfo bytes so a
/// bundle that repeats the same key (two certificates, one key) is one signer.
fn unique_signer_spkis<'a>(certs: &'a [X509Certificate<'a>]) -> Vec<SubjectPublicKeyInfo<'a>> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for cert in certs {
        let spki = cert.public_key();
        if seen.insert(digest_of(&[spki.raw])) {
            unique.push(spki.clone());
        }
    }
    unique
}

/// Stable identity of the key that signed `crl`.
///
/// Prefers the digest of a uniquely verified signer SPKI from the accepted
/// client-CA bundle. Matching the CRL issuer DN or Authority Key Identifier is
/// not enough: two CA keys can deliberately share both. When no bundle key
/// verifies, include the complete signed CRL in a distinct conservative identity
/// domain. An absent AKI does not prevent that byte identity; a present malformed
/// or duplicate AKI is still refused. That makes routine outside-bundle reissues
/// retire sessions, but prevents a second signing key
/// with colliding metadata from suppressing `CrlChanged`. Anything else fails
/// closed — never fall back to issuer DN or AKI alone.
fn crl_signer_key_identity(
    crl: &CertificateRevocationList<'_>,
    unique_signers: &[SubjectPublicKeyInfo<'_>],
) -> Result<[u8; 32], ClientTrustMaterialError> {
    let mut verified: Option<[u8; 32]> = None;
    for spki in unique_signers {
        if crl.verify_signature(spki).is_err() {
            continue;
        }
        let id = digest_of(&[ISSUER_DOMAIN_SPKI, spki.raw]);
        match verified {
            None => verified = Some(id),
            Some(existing) if existing == id => {}
            Some(_) => return Err(ClientTrustMaterialError),
        }
    }
    if let Some(id) = verified {
        return Ok(id);
    }
    conservative_unverified_crl_identity(crl)
}

fn conservative_unverified_crl_identity(
    crl: &CertificateRevocationList<'_>,
) -> Result<[u8; 32], ClientTrustMaterialError> {
    let mut key_id: Option<&[u8]> = None;
    for ext in crl.extensions() {
        if ext.oid != OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER {
            continue;
        }
        match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                if key_id.is_some() {
                    // Two AKI extensions: the identifier is not unambiguous.
                    return Err(ClientTrustMaterialError);
                }
                let Some(identifier) = aki.key_identifier.as_ref() else {
                    return Err(ClientTrustMaterialError);
                };
                if identifier.0.is_empty() {
                    return Err(ClientTrustMaterialError);
                }
                key_id = Some(identifier.0);
            }
            _ => return Err(ClientTrustMaterialError),
        }
    }
    // The complete signed DER already distinguishes outside-bundle CRLs.
    // Absence of AKI therefore needs no invented key identity. Preserve the
    // existing digest for valid AKIs and all validation of present extensions.
    let key_id = key_id.unwrap_or_default();
    Ok(digest_of(&[
        ISSUER_DOMAIN_UNVERIFIED_CRL,
        crl.issuer().as_raw(),
        key_id,
        crl.as_raw(),
    ]))
}

/// Per-scope state. One instance per [`ClientTrustScope`], created once.
struct ClientTrustDomain {
    scope: ClientTrustScope,
    /// `true` once a baseline has been accepted. Until then [`capture`] returns
    /// `None` and listeners pay nothing at all — which is the default
    /// configuration, where `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` is off and
    /// no generation can ever advance.
    armed: AtomicBool,
    /// Monotonic accepted-material generation. Starts at `0` (unarmed).
    generation: AtomicU64,
    /// Generation at which authority was last narrowed; the admission fence.
    withdrawal_generation: AtomicU64,
    /// Reason index for the last withdrawal, or [`NO_REASON`].
    last_withdrawal_reason: AtomicU8,
    /// Last accepted semantic material.
    material: ArcSwap<Option<ClientTrustMaterial>>,
    /// Live rustls client-certificate verifier for this scope. Stored as the
    /// first step of [`publish_accepted_rustls_candidate`], before the matching
    /// `ServerConfig` is exposed and before the generation advances, under the
    /// same publication lock. Handshake paths re-check the peer against this
    /// object after TLS so a stale `ServerConfig` / QUIC accepter snapshot
    /// cannot admit a credential the published generation withdrew. `None` for
    /// DTLS and for tests that publish material without a verifier.
    live_verifier: ArcSwap<Option<Arc<dyn ClientCertVerifier>>>,
    /// Live client-certificate-authenticated transports, keyed by an internal
    /// session id. Stored as `Weak` so a long-lived clone (an upgraded
    /// WebSocket, a per-request fence handle) that outlives the HTTP
    /// connection guard remains sweepable. Only ever touched at connection
    /// setup/teardown and at publication — never on the request path.
    sessions: DashMap<u64, Weak<ClientTrustSessionInner>>,
    next_session_id: AtomicU64,
    /// Serializes one accepted-candidate transaction so two concurrent
    /// publishers cannot interleave verifier install, config exposure, and
    /// material/generation/fence. Publications are rare (operator-driven
    /// reloads) and never happen on a data path. The lock is a `std` mutex and
    /// must not be held across `.await`.
    publish_lock: std::sync::Mutex<()>,
    /// Fixed-cardinality counters.
    publications: [AtomicU64; 4],
    retirements: [AtomicU64; REASON_COUNT],
    rejected_candidates: AtomicU64,
    fenced: AtomicU64,
}

impl ClientTrustDomain {
    fn new(scope: ClientTrustScope) -> Self {
        Self {
            scope,
            armed: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            withdrawal_generation: AtomicU64::new(0),
            last_withdrawal_reason: AtomicU8::new(NO_REASON),
            material: ArcSwap::from_pointee(None),
            live_verifier: ArcSwap::from_pointee(None),
            sessions: DashMap::new(),
            next_session_id: AtomicU64::new(1),
            publish_lock: std::sync::Mutex::new(()),
            publications: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            retirements: [AtomicU64::new(0), AtomicU64::new(0)],
            rejected_candidates: AtomicU64::new(0),
            fenced: AtomicU64::new(0),
        }
    }

    fn record_publication(&self, outcome: ClientTrustPublicationOutcome) {
        let index = match outcome {
            ClientTrustPublicationOutcome::Armed => 0,
            ClientTrustPublicationOutcome::Unchanged => 1,
            ClientTrustPublicationOutcome::Advanced => 2,
            ClientTrustPublicationOutcome::Withdrawn => 3,
        };
        self.publications[index].fetch_add(1, Ordering::Relaxed);
    }

    /// Retire every registered session strictly below `fence`.
    ///
    /// Upgrades are collected before any `Inner` can drop so a last-handle
    /// teardown cannot `remove` from this map while `retain` is iterating it.
    fn sweep(&self, fence: u64, reason: ClientTrustRetirementReason) -> usize {
        let mut live = Vec::new();
        self.sessions.retain(|_, weak| match weak.upgrade() {
            Some(inner) => {
                live.push(ClientTrustSession { inner });
                true
            }
            None => false,
        });
        let mut retired = 0usize;
        for session in &live {
            if session.generation() < fence && session.retire(reason) {
                retired += 1;
            }
        }
        retired
    }
}

fn domains() -> &'static [ClientTrustDomain; SCOPE_COUNT] {
    static DOMAINS: OnceLock<[ClientTrustDomain; SCOPE_COUNT]> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        [
            ClientTrustDomain::new(ClientTrustScope::ProxyFrontend),
            ClientTrustDomain::new(ClientTrustScope::ProxyH3),
            ClientTrustDomain::new(ClientTrustScope::AdminHttps),
            ClientTrustDomain::new(ClientTrustScope::FrontendDtls),
        ]
    })
}

fn domain(scope: ClientTrustScope) -> &'static ClientTrustDomain {
    &domains()[scope.index()]
}

/// Publish one validated, accepted client-trust snapshot into `scope`.
///
/// This is the DTLS / material-only path: no rustls live verifier is installed.
/// Callers must already have exposed the corresponding config (DTLS publishes
/// into every active `DtlsServer` first). Rustls surfaces must use
/// [`publish_accepted_rustls_candidate`] so verifier, config, and generation
/// cannot be published on separate lock acquisitions. There is no rustls
/// convenience that omits the exposure callback.
pub fn publish_accepted_material(
    scope: ClientTrustScope,
    material: ClientTrustMaterial,
) -> ClientTrustPublication {
    let domain = domain(scope);
    let _publish_guard = lock_publish(domain);
    publish_locked(domain, material)
}

fn lock_publish(domain: &ClientTrustDomain) -> std::sync::MutexGuard<'_, ()> {
    // Poisoning cannot make the state unsafe (every field is an atomic or an
    // `ArcSwap`), and refusing to publish on a poisoned lock would leave the
    // fence permanently behind the served material — the fail-open direction.
    domain
        .publish_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn store_live_verifier(domain: &ClientTrustDomain, verifier: Arc<dyn ClientCertVerifier>) {
    let current = domain.live_verifier.load_full();
    if current
        .as_ref()
        .as_ref()
        .is_some_and(|installed| Arc::ptr_eq(installed, &verifier))
    {
        return;
    }
    domain.live_verifier.store(Arc::new(Some(verifier)));
}

/// One rustls accepted-candidate transaction for `scope`.
///
/// Holds the scope publication lock continuously across: install the accepted
/// live verifier, run `expose_config` (already-validated, infallible config
/// exposure/adoption), publish this candidate's material/generation/fence,
/// and sweep. All fallible load/build/validation must complete before this
/// call. `expose_config` must not `.await`. This is the only rustls
/// publication entry point; there is no overload that installs a verifier
/// without an explicit exposure callback.
///
/// DTLS has no rustls live verifier and must not call this. Use
/// [`publish_accepted_material`] after the DTLS config is already live.
pub fn publish_accepted_rustls_candidate(
    scope: ClientTrustScope,
    material: ClientTrustMaterial,
    verifier: Arc<dyn ClientCertVerifier>,
    expose_config: impl FnOnce(),
) -> ClientTrustPublication {
    let domain = domain(scope);
    let _publish_guard = lock_publish(domain);
    store_live_verifier(domain, verifier);
    expose_config();
    publish_locked(domain, material)
}

fn publish_locked(
    domain: &ClientTrustDomain,
    material: ClientTrustMaterial,
) -> ClientTrustPublication {
    let scope = domain.scope;
    let previous = domain.material.load_full();
    let Some(previous_material) = previous.as_ref().as_ref() else {
        // First accepted snapshot for this scope: the baseline. Nothing was
        // authorized under an older generation, so nothing is retired.
        domain.material.store(Arc::new(Some(material)));
        let generation = domain.generation.fetch_add(1, Ordering::AcqRel) + 1;
        domain.armed.store(true, Ordering::Release);
        domain.record_publication(ClientTrustPublicationOutcome::Armed);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Armed,
            reason: None,
            retired_sessions: 0,
        };
    };

    if *previous_material == material {
        let generation = domain.generation.load(Ordering::Acquire);
        domain.record_publication(ClientTrustPublicationOutcome::Unchanged);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Unchanged,
            reason: None,
            retired_sessions: 0,
        };
    }

    let reason = material.withdrawal_relative_to(previous_material);
    domain.material.store(Arc::new(Some(material)));
    let generation = domain.generation.fetch_add(1, Ordering::AcqRel) + 1;

    let Some(reason) = reason else {
        domain.record_publication(ClientTrustPublicationOutcome::Advanced);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Advanced,
            reason: None,
            retired_sessions: 0,
        };
    };

    // Move the fence BEFORE sweeping. A session registering concurrently either
    // lands in the map in time to be swept, or observes this store in its own
    // post-insert re-check. Neither can escape, and neither can be retired
    // twice.
    domain
        .last_withdrawal_reason
        .store(reason.index() as u8, Ordering::Release);
    domain
        .withdrawal_generation
        .store(generation, Ordering::Release);
    let retired = domain.sweep(generation, reason);
    domain.retirements[reason.index()].fetch_add(retired as u64, Ordering::Relaxed);
    domain.record_publication(ClientTrustPublicationOutcome::Withdrawn);

    ClientTrustPublication {
        scope,
        generation,
        outcome: ClientTrustPublicationOutcome::Withdrawn,
        reason: Some(reason),
        retired_sessions: retired,
    }
}

/// The last accepted semantic material for `scope`, when the scope is armed.
///
/// Introspection only. A publisher must **never** take its material from here:
/// the whole point of the model is that every scope publishes the identity of
/// the material it itself installed. The HTTP/3 listener used to republish
/// `ProxyFrontend`'s latest material into [`ClientTrustScope::ProxyH3`] after
/// `Endpoint::set_server_config`, which advanced the H3 generation to describe
/// CRLs and anchors that endpoint was not yet enforcing — a revoked client
/// could be retired and then reconnect successfully. It now publishes the
/// identity carried by the exact candidate it adopted.
// Introspection surface for external tests; the bin target re-declares the
// module tree, so an item used only from `tests/` is dead there.
#[allow(dead_code)]
pub fn current_material(scope: ClientTrustScope) -> Option<ClientTrustMaterial> {
    domain(scope).material.load_full().as_ref().clone()
}

/// Re-check a handshake's peer certificate chain against the live verifier
/// this scope last published.
///
/// Returns `true` when the chain is empty (anonymous) or when this scope has
/// no rustls verifier (DTLS, material-only tests). Returns `false` when the
/// published verifier refuses the peer. Armed rustls admission uses
/// [`armed_handshake_still_trusted`], which fails closed on a missing chain.
// Introspection / test seam; production admission uses `armed_handshake_*`.
#[allow(dead_code)]
pub fn live_peer_still_trusted(
    scope: ClientTrustScope,
    certificates: &[CertificateDer<'_>],
) -> bool {
    let Some((end_entity, intermediates)) = certificates.split_first() else {
        return true;
    };
    let Some(verifier) = domain(scope).live_verifier.load_full().as_ref().clone() else {
        return true;
    };
    verifier
        .verify_client_cert(end_entity, intermediates, UnixTime::now())
        .is_ok()
}

/// [`live_peer_still_trusted`] for a chain held as raw DER buffers.
#[allow(dead_code)]
pub fn live_peer_der_chain_still_trusted(scope: ClientTrustScope, chain: &[Vec<u8>]) -> bool {
    let certificates: Vec<CertificateDer<'_>> = chain
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    live_peer_still_trusted(scope, &certificates)
}

/// Fail-closed reconnect fence for an armed rustls handshake.
///
/// A missing or empty peer chain is untrusted: TLS session tickets do not
/// re-run client-certificate verification, and an armed listener must not
/// serve a reconnect that cannot be checked against the live verifier. A
/// missing live verifier is likewise untrusted — publication stores the
/// verifier before the generation becomes observable.
pub fn armed_handshake_still_trusted(
    scope: ClientTrustScope,
    certificates: Option<&[CertificateDer<'_>]>,
) -> bool {
    let Some(certificates) = certificates.filter(|certs| !certs.is_empty()) else {
        return false;
    };
    let Some(verifier) = domain(scope).live_verifier.load_full().as_ref().clone() else {
        return false;
    };
    let Some((end_entity, intermediates)) = certificates.split_first() else {
        return false;
    };
    verifier
        .verify_client_cert(end_entity, intermediates, UnixTime::now())
        .is_ok()
}

/// [`armed_handshake_still_trusted`] for a chain held as raw DER buffers.
pub fn armed_handshake_der_chain_still_trusted(
    scope: ClientTrustScope,
    chain: Option<&[Vec<u8>]>,
) -> bool {
    let Some(chain) = chain.filter(|certs| !certs.is_empty()) else {
        return false;
    };
    let certificates: Vec<CertificateDer<'_>> = chain
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    armed_handshake_still_trusted(scope, Some(&certificates))
}

/// Wrap `inner` so handshake-time rustls verification consults the live
/// published verifier for `scope`.
///
/// rustls stores the `ClientCertVerifier` inside each `ServerConfig`. A
/// TlsAcceptor or QUIC endpoint that still holds a snapshot built under a
/// withdrawn generation would otherwise keep admitting the withdrawn
/// credential. The wrapper's CertificateRequest hints are generation-neutral
/// (empty), so a client that honors `certificate_authorities` can still
/// present a certificate issued by a CA added after this snapshot was built;
/// the presented chain is then verified only by the currently published
/// fail-closed verifier. The wrapper is installed **only** at
/// `with_client_cert_verifier` time;
/// [`AcceptedClientTrust::verifier`](super::AcceptedClientTrust) and
/// [`publish_accepted_rustls_candidate`] keep the inner WebPki object so the
/// live slot never points at the wrapper itself.
pub fn bind_live_handshake_verifier(
    scope: ClientTrustScope,
    inner: Arc<dyn ClientCertVerifier>,
) -> Arc<dyn ClientCertVerifier> {
    Arc::new(LiveHandshakeVerifier { scope, inner })
}

/// Handshake-time rustls verifier that reads the live published verifier for
/// `scope` on every `verify_client_cert`. CertificateRequest CA-name hints are
/// empty so they cannot pin a snapshot generation. Debug omits the inner
/// verifier so a `ServerConfig` dump cannot leak trust material.
struct LiveHandshakeVerifier {
    scope: ClientTrustScope,
    inner: Arc<dyn ClientCertVerifier>,
}

impl LiveHandshakeVerifier {
    fn active(&self) -> Arc<dyn ClientCertVerifier> {
        domain(self.scope)
            .live_verifier
            .load_full()
            .as_ref()
            .clone()
            .unwrap_or_else(|| self.inner.clone())
    }
}

impl std::fmt::Debug for LiveHandshakeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveHandshakeVerifier")
            .field("scope", &self.scope.label())
            .finish()
    }
}

impl ClientCertVerifier for LiveHandshakeVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // rustls requires a borrow from `&self`. Forwarding the snapshot
        // inner verifier's CA names would advertise a stale CertificateRequest
        // constraint: a client that honors `certificate_authorities` can then
        // withhold a certificate issued by a CA added after this ServerConfig
        // was built, even though `verify_client_cert` consults the live
        // verifier. An empty list is generation-neutral and does not broaden
        // trust: TLS 1.3 omits the extension (`authority_names: None`), TLS
        // 1.2 sends empty `canames`, and rustls documents that the client
        // should then present any certificate it has. The presented chain is
        // still verified only through the currently published fail-closed
        // verifier.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.active()
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.active().verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.active().verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.active().supported_verify_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

/// Record that a reload candidate for `scope` was refused.
///
/// The last accepted verifier, generation, material and every live session are
/// retained; this only makes the refusal observable.
pub fn record_rejected_candidate(scope: ClientTrustScope) {
    domain(scope)
        .rejected_candidates
        .fetch_add(1, Ordering::Relaxed);
}

/// The generation currently in force for `scope`, or `None` when the scope has
/// never accepted material (the default, live-reload-disabled configuration).
///
/// **Call this before loading the TLS configuration** the handshake will use.
#[inline]
pub fn capture(scope: ClientTrustScope) -> Option<ClientTrustAdmission> {
    let domain = domain(scope);
    if !domain.armed.load(Ordering::Acquire) {
        return None;
    }
    Some(ClientTrustAdmission {
        scope,
        generation: domain.generation.load(Ordering::Acquire),
    })
}

/// A captured generation, carried from the accept path to the point where the
/// handshake outcome is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTrustAdmission {
    scope: ClientTrustScope,
    generation: u64,
}

impl ClientTrustAdmission {
    /// The scope this admission was captured from.
    pub fn scope(self) -> ClientTrustScope {
        self.scope
    }

    /// The captured generation.
    #[allow(dead_code)]
    pub fn generation(self) -> u64 {
        self.generation
    }

    /// Register an established transport that authenticated with a client
    /// certificate.
    ///
    /// Returns `None` when `client_cert_authenticated` is false — a transport
    /// that presented no gateway-verified client certificate holds no trust
    /// decision that a CRL or client-CA withdrawal can revoke, so it is neither
    /// tracked nor retired.
    ///
    /// The returned guard is one strong handle. Clone the inner
    /// [`ClientTrustSession`] for per-request and per-session consumers; those
    /// clones keep the transport in the retirement domain until the last one
    /// drops, which is what lets an upgraded WebSocket outlive
    /// `serve_connection_with_upgrades` and still be swept.
    pub fn register(self, client_cert_authenticated: bool) -> Option<ClientTrustSessionGuard> {
        if !client_cert_authenticated {
            return None;
        }
        let domain = domain(self.scope);
        let id = domain.next_session_id.fetch_add(1, Ordering::Relaxed);
        let session = ClientTrustSession {
            inner: Arc::new(ClientTrustSessionInner {
                id,
                scope: self.scope,
                generation: self.generation,
                token: CancellationToken::new(),
                retired: AtomicBool::new(false),
            }),
        };
        domain.sessions.insert(id, Arc::downgrade(&session.inner));
        // Publish-then-recheck: a withdrawal that swept before this insert is
        // caught here, so a connection being registered across a publication
        // cannot escape the fence or repopulate the domain after it.
        if self.generation < domain.withdrawal_generation.load(Ordering::Acquire) {
            let reason = ClientTrustRetirementReason::from_index(
                domain.last_withdrawal_reason.load(Ordering::Acquire),
            )
            .unwrap_or(ClientTrustRetirementReason::ClientCaWithdrawn);
            if session.retire(reason) {
                domain.retirements[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
        Some(ClientTrustSessionGuard { session })
    }
}

struct ClientTrustSessionInner {
    id: u64,
    scope: ClientTrustScope,
    generation: u64,
    token: CancellationToken,
    retired: AtomicBool,
}

impl Drop for ClientTrustSessionInner {
    fn drop(&mut self) {
        let ptr = std::ptr::from_mut(self).cast_const();
        domain(self.scope)
            .sessions
            .remove_if(&self.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
    }
}

/// A handle to one registered, client-certificate-authenticated transport.
///
/// Cheap to clone (one `Arc` bump). Clones are handed to per-request admission
/// gates and to long-lived session relays. The last handle to drop removes the
/// domain entry, so a clone that outlives the HTTP connection guard — an
/// upgraded WebSocket — is still visible to a later sweep.
#[derive(Clone)]
pub struct ClientTrustSession {
    inner: Arc<ClientTrustSessionInner>,
}

impl std::fmt::Debug for ClientTrustSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTrustSession")
            .field("scope", &self.inner.scope.label())
            .field("generation", &self.inner.generation)
            .field("retired", &self.is_retired())
            .finish()
    }
}

impl ClientTrustSession {
    /// The scope this transport was admitted under.
    #[allow(dead_code)] // External test / introspection surface.
    pub fn scope(&self) -> ClientTrustScope {
        self.inner.scope
    }

    /// The generation captured before the handshake that established this
    /// transport.
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// Whether this transport's trust decision has been withdrawn.
    ///
    /// One relaxed atomic read of connection-local state — no lock, no shared
    /// counter, no allocation. This is the per-request / per-stream fence.
    #[inline]
    pub fn is_retired(&self) -> bool {
        self.inner.token.is_cancelled()
    }

    /// Resolves once this transport is retired. Cancel-safe; usable directly as
    /// a `tokio::select!` arm alongside the connection's serve future.
    pub fn retired(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.inner.token.cancelled()
    }

    /// An owned cancellation handle, for wrappers that must hold the future
    /// across polls (see [`TrustFencedStream`]).
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// Latch this transport as retired. Returns `true` for the caller that won
    /// the latch, so accounting fires exactly once no matter how many
    /// publications or re-checks observe the same session.
    ///
    /// The token is cancelled BEFORE the latch is taken. `is_retired()` reads
    /// the token, and every fence in the codebase reads `is_retired()` — so
    /// latching first would leave a window in which a second observer (the
    /// post-insert re-check in `register`, or the stream-relay gate) loses the
    /// `swap` race, sees a not-yet-cancelled token, and admits one more step on
    /// an already-retired session. Cancelling first makes the observable
    /// "retired" edge strictly precede the exactly-once accounting edge, and
    /// the `swap` still keeps the accounting exactly once.
    fn retire(&self, _reason: ClientTrustRetirementReason) -> bool {
        self.inner.token.cancel();
        !self.inner.retired.swap(true, Ordering::AcqRel)
    }

    /// Record that this transport refused a request / stream at the admission
    /// fence. Fixed-cardinality, scope-labelled only.
    #[inline]
    pub fn record_fenced(&self) {
        domain(self.inner.scope)
            .fenced
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// One strong handle to a registered session. Dropping it does not by itself
/// deregister the transport: an upgraded WebSocket (and any other clone)
/// keeps the session sweepable until the last handle is gone.
pub struct ClientTrustSessionGuard {
    session: ClientTrustSession,
}

impl ClientTrustSessionGuard {
    /// The registered session handle. Clone it for request-path consumers.
    pub fn session(&self) -> &ClientTrustSession {
        &self.session
    }
}

/// Wrap a client-side byte stream so a trust withdrawal surfaces as an ordinary
/// transport failure.
///
/// Used by the TCP+TLS stream relay and the WebSocket relay, where there is no
/// request boundary to fence and the correct behaviour is to end the session.
/// Routing every termination through an `io::Error` means byte counters,
/// first-failure attribution, disconnect hooks, permits, and the stream summary
/// all complete exactly once through the paths those relays already have — no
/// second teardown path is introduced.
///
/// The error is a compiled-in literal and carries no certificate field.
pub struct TrustFencedStream<S> {
    inner: S,
    /// `None` when the transport carries no withdrawable trust decision (no
    /// client certificate, or an unarmed scope). The wrapper then costs one
    /// `Option` branch per poll and registers no waker at all, so a deployment
    /// that never enables frontend TLS live reload pays nothing measurable.
    retired: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
    fired: bool,
}

/// The single client-visible / log-visible string for a fenced stream.
pub const TRUST_FENCED_STREAM_MESSAGE: &str = "frontend client trust withdrawn";

impl<S> TrustFencedStream<S> {
    /// Wrap `inner`, terminating it once `session` is retired. Passing `None`
    /// makes the wrapper a transparent pass-through.
    pub fn new(inner: S, session: Option<&ClientTrustSession>) -> Self {
        Self {
            inner,
            retired: session
                .map(|session| Box::pin(session.cancellation_token().cancelled_owned())),
            fired: false,
        }
    }

    /// Whether this wrapper is actually fencing anything.
    #[allow(dead_code)] // External test / introspection surface.
    pub fn is_fencing(&self) -> bool {
        self.retired.is_some()
    }

    /// Whether the fence — rather than the wrapped stream — produced the last
    /// error this wrapper returned.
    ///
    /// A caller that wraps one bounded write (the TCP+TLS inspected-prefix
    /// forward) needs to tell a withdrawal apart from a genuine backend I/O
    /// failure: the first is a client-side, health-neutral authorization
    /// decision, the second is backend evidence. Reading the latch is exact,
    /// where re-reading the session afterwards would misattribute a backend
    /// failure that merely coincided with a withdrawal.
    #[inline]
    pub fn fence_fired(&self) -> bool {
        self.fired
    }

    fn poll_fence(&mut self, cx: &mut Context<'_>) -> Option<std::io::Error> {
        let retired = self.retired.as_mut()?;
        if self.fired {
            return Some(fenced_error());
        }
        if retired.as_mut().poll(cx).is_ready() {
            self.fired = true;
            return Some(fenced_error());
        }
        None
    }
}

fn fenced_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        TRUST_FENCED_STREAM_MESSAGE,
    )
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for TrustFencedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TrustFencedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Shutdown must stay available after the fence fires so the relay can
        // still half-close the peer cleanly rather than leaking the socket.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Non-secret observability snapshot of one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTrustScopeSnapshot {
    /// The scope this row describes.
    pub scope: ClientTrustScope,
    /// Whether the scope has ever accepted material.
    pub armed: bool,
    /// The generation currently in force.
    pub generation: u64,
    /// The generation at which authority was last narrowed (`0` = never).
    pub withdrawal_generation: u64,
    /// Live registered client-certificate-authenticated transports.
    pub tracked_sessions: usize,
    /// Publications by outcome: armed, unchanged, advanced, withdrawn.
    pub publications: [u64; 4],
    /// Retired transports by reason index.
    pub retirements: [u64; REASON_COUNT],
    /// Reload candidates refused for this scope.
    pub rejected_candidates: u64,
    /// Requests / streams refused at the admission fence.
    pub fenced: u64,
}

/// Snapshot every scope. Cheap; used by `/metrics`, `/metrics/runtime` and tests.
pub fn snapshot() -> Vec<ClientTrustScopeSnapshot> {
    domains()
        .iter()
        .map(|domain| ClientTrustScopeSnapshot {
            scope: domain.scope,
            armed: domain.armed.load(Ordering::Acquire),
            generation: domain.generation.load(Ordering::Acquire),
            withdrawal_generation: domain.withdrawal_generation.load(Ordering::Acquire),
            tracked_sessions: domain
                .sessions
                .iter()
                .filter(|entry| entry.value().strong_count() > 0)
                .count(),
            publications: [
                domain.publications[0].load(Ordering::Relaxed),
                domain.publications[1].load(Ordering::Relaxed),
                domain.publications[2].load(Ordering::Relaxed),
                domain.publications[3].load(Ordering::Relaxed),
            ],
            retirements: [
                domain.retirements[0].load(Ordering::Relaxed),
                domain.retirements[1].load(Ordering::Relaxed),
            ],
            rejected_candidates: domain.rejected_candidates.load(Ordering::Relaxed),
            fenced: domain.fenced.load(Ordering::Relaxed),
        })
        .collect()
}

/// Render the bounded frontend client-trust families.
///
/// Emits nothing at all when no scope has ever accepted material, so a
/// deployment without frontend client-certificate live reload pays no scrape
/// bytes. Trust-specific dimensions (`scope`, `outcome`, `reason`) use closed
/// compile-time vocabularies. `ns_label` is the standard configured registry
/// `namespace` fragment, not a trust-specific dimension.
pub fn render_prometheus(output: &mut String, ns_label: &str) {
    let rows = snapshot();
    if !rows.iter().any(|row| row.armed) {
        return;
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_generation Monotonic frontend client-CA/CRL trust generation currently in force for a listener scope.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_generation gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_generation{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.generation
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_withdrawal_generation Generation at which frontend client-certificate authority was last narrowed for a listener scope (0 = never).\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_withdrawal_generation gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_withdrawal_generation{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.withdrawal_generation
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_tracked_connections Established client-certificate-authenticated frontend transports currently tracked for retirement.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_tracked_connections gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_tracked_connections{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.tracked_sessions
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_publications_total Accepted frontend client-trust reload publications by bounded outcome.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_publications_total counter\n");
    const OUTCOMES: [ClientTrustPublicationOutcome; 4] = [
        ClientTrustPublicationOutcome::Armed,
        ClientTrustPublicationOutcome::Unchanged,
        ClientTrustPublicationOutcome::Advanced,
        ClientTrustPublicationOutcome::Withdrawn,
    ];
    for row in rows.iter().filter(|row| row.armed) {
        for (index, outcome) in OUTCOMES.iter().enumerate() {
            output.push_str(&format!(
                "ferrum_frontend_client_trust_publications_total{{scope=\"{}\",outcome=\"{}\"{}}} {}\n",
                row.scope.label(),
                outcome.label(),
                ns_label,
                row.publications[index]
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_rejected_candidates_total Frontend client-trust reload candidates refused; the last accepted generation and its sessions are retained.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_rejected_candidates_total counter\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_rejected_candidates_total{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.rejected_candidates
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_retired_connections_total Established frontend transports retired because their client-certificate trust decision was withdrawn.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_retired_connections_total counter\n");
    const REASONS: [ClientTrustRetirementReason; REASON_COUNT] = [
        ClientTrustRetirementReason::ClientCaWithdrawn,
        ClientTrustRetirementReason::CrlChanged,
    ];
    for row in rows.iter().filter(|row| row.armed) {
        for (index, reason) in REASONS.iter().enumerate() {
            output.push_str(&format!(
                "ferrum_frontend_client_trust_retired_connections_total{{scope=\"{}\",reason=\"{}\"{}}} {}\n",
                row.scope.label(),
                reason.label(),
                ns_label,
                row.retirements[index]
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_fenced_total Requests or streams refused before routing because the transport's client-certificate trust was withdrawn.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_fenced_total counter\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_fenced_total{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.fenced
        ));
    }
}

/// Reset every domain. **Test seam only** — the registry is process-global, so
/// external test binaries need a way to isolate cases.
///
/// # Why this is compiled out of shipping artifacts
///
/// This is the one trust seam that fails **open**: a single call clears
/// `armed`, `withdrawal_generation`, `live_verifier`, and the session map, so
/// every later connection captures `None` and no withdrawal can ever bite
/// again. `custom_plugins/` compiles into this same crate and could otherwise
/// reach it, so it must not exist in a shipped binary.
///
/// `cfg(any(test, debug_assertions))` is that boundary: the `test` and `dev`
/// profiles both enable `debug-assertions`, so `cargo test`, `cargo clippy
/// --tests`, and the `pr-build` functional-test binary all keep the seam, while
/// `release`, `ci-release`, and `max-perf` — every profile any artifact ships
/// from — compile it out entirely. A cargo feature would be the stronger gate,
/// but activating one for test targets requires either a self dev-dependency
/// (an unverifiable `Cargo.lock` edit against CI's `cargo fetch --locked`) or
/// `--features` on the test invocations, which live in Cross-frozen workflow
/// jobs. See [`force_withdrawal_fence_for_test`] and
/// [`arm_at_generation_for_test`], which carry the same gate.
#[cfg(any(test, debug_assertions))]
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn reset_for_test() {
    for domain in domains().iter() {
        let _guard = domain
            .publish_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        domain.sessions.clear();
        domain.armed.store(false, Ordering::Release);
        domain.generation.store(0, Ordering::Release);
        domain.withdrawal_generation.store(0, Ordering::Release);
        domain
            .last_withdrawal_reason
            .store(NO_REASON, Ordering::Release);
        domain.material.store(Arc::new(None));
        domain.live_verifier.store(Arc::new(None));
        domain.next_session_id.store(1, Ordering::Release);
        for counter in domain.publications.iter() {
            counter.store(0, Ordering::Relaxed);
        }
        for counter in domain.retirements.iter() {
            counter.store(0, Ordering::Relaxed);
        }
        domain.rejected_candidates.store(0, Ordering::Relaxed);
        domain.fenced.store(0, Ordering::Relaxed);
    }
}

/// Force the fence for `scope` to `generation` without publishing material.
/// **Test seam only** — used to exercise the register-across-publication race
/// deterministically.
///
/// Compiled out of every shipping profile; see [`reset_for_test`] for the gate
/// and why it is drawn there.
#[cfg(any(test, debug_assertions))]
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn force_withdrawal_fence_for_test(
    scope: ClientTrustScope,
    generation: u64,
    reason: ClientTrustRetirementReason,
) {
    let domain = domain(scope);
    domain.armed.store(true, Ordering::Release);
    domain
        .last_withdrawal_reason
        .store(reason.index() as u8, Ordering::Release);
    domain
        .withdrawal_generation
        .store(generation, Ordering::Release);
}

/// Arm `scope` at `generation` without publishing material. **Test seam only.**
///
/// Compiled out of every shipping profile; see [`reset_for_test`] for the gate
/// and why it is drawn there.
#[cfg(any(test, debug_assertions))]
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn arm_at_generation_for_test(scope: ClientTrustScope, generation: u64) {
    let domain = domain(scope);
    domain.generation.store(generation, Ordering::Release);
    domain.armed.store(true, Ordering::Release);
}
