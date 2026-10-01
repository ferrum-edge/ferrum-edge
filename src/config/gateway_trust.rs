//! Namespace-keyed gateway trust bundles as a first-class configuration
//! resource (issue #3727).
//!
//! Before this module the only authority for `GatewayConfig.trust_bundles` was
//! a file-sourced document: every SQL/MongoDB backend could persist proxies,
//! consumers, upstreams and plugin configs but had no storage shape for the
//! gateway-to-mesh trust roots the control plane distributes to its data
//! planes. Database-mode CP replicas could therefore not commit a root
//! rotation or an emergency revocation, and a namespace-scoped ConfigSync
//! stream had to clear the unpartitioned trust field outright rather than
//! publish the subscriber's own trust state.
//!
//! [`GatewayTrustBundleRecord`] is that missing resource. It is deliberately a
//! thin, namespace-keyed envelope around the existing serializable
//! [`TrustBundleSet`] domain type rather than a parallel representation: the
//! bytes that reach a data plane through the `trust_bundles_json` side channel
//! are exactly the bytes an operator wrote, so there is no second schema that
//! can drift from the one mesh validation already understands.
//!
//! Invariants enforced here (all of them *before* persistence and again before
//! publication):
//!
//! - One record per namespace. The resource is a singleton so a namespace's
//!   projected trust state is never ambiguous; SQL enforces it with the
//!   `namespace` primary key and MongoDB with `_id = namespace`.
//! - `trust_domain` is the bundle identity and must equal
//!   `bundle.local.trust_domain`, so the stored identity column can never
//!   disagree with the material it names.
//! - Bounded material: authority counts, per-authority size, and total encoded
//!   size are capped so a hostile or accidental write cannot push an unbounded
//!   blob through the change log and into every subscriber's snapshot. Count
//!   and cheap encoded/raw size bounds fail closed before any allocating or
//!   deep semantic parser (`TrustDomain::new`, `validate_mesh_config`, X.509
//!   DER, JWT public keys, runtime conversion) walks the over-limit
//!   collections or material.
//! - `updated_by` is the verified admin JWT subject, never a client-supplied
//!   value, and is capped at [`MAX_AUDIT_ACTOR_CHARS`] so every backend rejects
//!   an overlong actor before persistence. Attribution is never truncated.
//! - Usable material, not just well-formed wrappers: every `x509_authorities`
//!   entry must be valid base64 **and** parse as an X.509 certificate that
//!   consumes the complete DER entry (no accepted trailing bytes); every
//!   `jwt_authorities` entry must carry a non-empty unique `key_id` and a PEM
//!   block the JWT-SVID authority parser can actually turn into a usable
//!   public key.
//! - No duplicate trust domains across `local` + `federated`.
//!
//! Nothing in this module logs, formats, or returns trust material. Errors name
//! the offending field and index only.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::identity::TrustDomain;
use crate::modes::mesh::config::{MAX_MESH_REMOTE_CLUSTERS, TrustBundleSet};

/// Maximum number of X.509 authorities in any single bundle (local or one
/// federated entry). Root rotation needs an overlap of two or three; the cap is
/// generous enough for staged rollouts and small enough that a snapshot stays
/// bounded.
pub const MAX_X509_AUTHORITIES_PER_BUNDLE: usize = 16;

/// Maximum number of JWT authorities in any single bundle.
pub const MAX_JWT_AUTHORITIES_PER_BUNDLE: usize = 16;

/// Maximum number of federated bundles in one record.
///
/// This is DERIVED from [`MAX_MESH_REMOTE_CLUSTERS`], not chosen independently,
/// because the two bound the same inventory from opposite ends: mesh
/// multi-cluster already accepts up to `MAX_MESH_REMOTE_CLUSTERS` remote
/// clusters, and a federated deployment carries one federated trust domain per
/// remote cluster. A smaller number here would make a documented, already
/// admissible remote-cluster inventory unrepresentable as trust — a cluster
/// count past the cap would reject an entire mesh generation or suppress a CP
/// broadcast — so the two constants are tied together and cannot drift.
///
/// The count bound is not the resource bound. See
/// [`MAX_TRUST_BUNDLE_JSON_BYTES`] for how counts and total encoded size
/// compose: the count cap makes the documented inventory *representable*, the
/// total-byte cap is what actually bounds propagation and deep-parse cost.
pub const MAX_FEDERATED_BUNDLES: usize = MAX_MESH_REMOTE_CLUSTERS;

/// Maximum DER size of one X.509 authority, in bytes.
pub const MAX_X509_AUTHORITY_DER_BYTES: usize = 16 * 1024;

/// Maximum size of one JWT authority PEM public key, in bytes.
pub const MAX_JWT_AUTHORITY_PEM_BYTES: usize = 16 * 1024;

/// Maximum length of a JWT authority `key_id`.
pub const MAX_JWT_AUTHORITY_KEY_ID_BYTES: usize = 256;

/// Maximum serialized size of the whole `bundle` value. This is the value that
/// is stored in one column/field, replicated through the change log, and
/// serialized into every `trust_bundles_json` side channel, so it is the bound
/// that actually matters for propagation cost.
///
/// # How the bounds compose
///
/// The three families are checked in a fixed order and are deliberately NOT
/// redundant:
///
/// 1. **Counts** ([`MAX_FEDERATED_BUNDLES`],
///    [`MAX_X509_AUTHORITIES_PER_BUNDLE`], [`MAX_JWT_AUTHORITIES_PER_BUNDLE`])
///    make the documented inventory representable and stop an unbounded
///    collection walk before it starts.
/// 2. **Per-entry sizes** ([`MAX_X509_AUTHORITY_DER_BYTES`],
///    [`MAX_JWT_AUTHORITY_PEM_BYTES`], [`MAX_JWT_AUTHORITY_KEY_ID_BYTES`]) cap
///    one authority, so a single entry cannot be a blob.
/// 3. **This total** caps the whole document. It is the BINDING resource bound:
///    the counts multiply out to far more material than this allows
///    (`(1 + 256)` bundles × 16 X.509 authorities × 16 KiB is ~64 MiB), and the
///    total is what a full inventory is actually measured against.
///
/// The cheap raw-material sum is evaluated first and short-circuits before any
/// deep parser runs, so the maximum material a hostile document can push
/// through base64/DER/PEM decoding is this value, not the product of the counts.
///
/// The chosen value admits the documented worst realistic federation: the full
/// `MAX_FEDERATED_BUNDLES` remote trust domains plus the local one, each
/// carrying a rotation-overlap PAIR of ordinary ECDSA P-256 roots (~600 base64
/// bytes each, so ~330 KiB with JSON framing), or one RSA-4096 root each. It
/// deliberately does NOT admit every trust domain simultaneously holding the
/// per-bundle authority maximum: that document would be replicated through the
/// change log and into every subscriber snapshot on every rotation, and the
/// CP/DP `ConfigUpdate` carries it alongside the full configuration inside one
/// gRPC message.
pub const MAX_TRUST_BUNDLE_JSON_BYTES: usize = 512 * 1024;

/// Maximum length of the resource id.
pub const MAX_TRUST_BUNDLE_ID_BYTES: usize = 255;

/// Maximum Unicode scalar-value length of a server-assigned audit actor
/// (`updated_by`).
///
/// Matches MySQL `VARCHAR(255)` under utf8mb4 (255 characters, not 255 UTF-8
/// bytes) and OpenAPI `maxLength: 255`. PostgreSQL/SQLite cannot persist an
/// overlong JWT subject that MySQL would reject. Attribution is never
/// truncated: an overlong subject fails admission instead.
pub const MAX_AUDIT_ACTOR_CHARS: usize = 255;

/// Authoritative, namespace-keyed gateway trust-bundle resource.
///
/// `revision` is assigned by the BACKEND from a durable monotonic source (the
/// SQL `config_changes.sequence` / MongoDB config-change sequence counter), not
/// by the caller and not by a per-record counter that restarts at 1. A client
/// echoes the revision it read back on update; a mismatch is a 409, which is how
/// a concurrent rotation from a second admin replica is detected rather than
/// silently overwritten.
///
/// Sourcing the revision from the change sequence is what closes the ABA hole a
/// per-record counter leaves open. With a counter that restarts at 1 for every
/// incarnation, a client could read revision 1, a second actor could DELETE the
/// namespace singleton and recreate it (revision 1 again), and the first
/// client's later `PUT` with expected revision 1 would compare-and-set
/// successfully against a *different* trust incarnation and overwrite it. The
/// namespace admission lease serializes individual writes, but nothing
/// serializes the gap between a client's `GET` and its later `PUT`, so only a
/// revision that can never be reused fixes it. Every trust mutation — including
/// the delete — advances the shared change sequence, so a recreated record is
/// always strictly newer than the incarnation it replaced and the stale
/// expectation can only conflict or report not-found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GatewayTrustBundleRecord {
    /// Stable resource identity. Defaults to the namespace when a client omits
    /// it, which keeps the singleton addressable without forcing operators to
    /// invent a name.
    #[serde(default)]
    pub id: String,
    #[serde(default = "crate::config::types::default_namespace")]
    pub namespace: String,
    /// Bundle identity. Must equal `bundle.local.trust_domain`.
    #[serde(default)]
    pub trust_domain: String,
    /// The admitted trust material, in the same shape mesh config uses.
    #[serde(deserialize_with = "crate::util::json_object::deserialize_object")]
    pub bundle: TrustBundleSet,
    /// Monotonic revision. Backend-assigned on every physical write from the
    /// durable change sequence — never carried over from a request body, a
    /// backup payload, or a previous incarnation — and supplied by the client on
    /// update as the expected current value (`0` = no expectation).
    #[serde(default)]
    pub revision: u64,
    /// Audit actor that last wrote the record. Never a credential — the admin
    /// JWT subject only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

impl GatewayTrustBundleRecord {
    /// Build a record from an already-validated bundle. Used by loaders and
    /// tests; admin writes go through the CRUD admission path.
    ///
    /// `revision` is left UNASSIGNED (`0`). A caller-authored revision is never
    /// persisted: the store stamps the backend-assigned value inside the write
    /// transaction, so no construction site can seed a value that a later
    /// incarnation could repeat.
    // Reached only from external and inline test suites: production records are
    // deserialized by the stores or built through the CRUD admission path, so
    // this constructor reads as dead code in the `ferrum-edge` bin target,
    // which recompiles this module without any test caller.
    #[allow(dead_code)]
    pub fn new(namespace: &str, id: &str, bundle: TrustBundleSet) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            trust_domain: bundle.local.trust_domain.to_string(),
            namespace: namespace.to_string(),
            bundle,
            revision: 0,
            updated_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Trim-only normalization. Deliberately derives NOTHING from
    /// `self.namespace`: on the admin path the body's namespace is still
    /// whatever the client sent at this point, and the server-selected
    /// `X-Ferrum-Namespace` value is applied afterwards.
    pub fn trim_fields(&mut self) {
        self.id = self.id.trim().to_string();
        self.trust_domain = self.trust_domain.trim().to_string();
    }

    /// The id a namespace's singleton record defaults to when the writer omits
    /// one. Derived from the SERVER-selected namespace by every caller — never
    /// from a request body — so a hostile body cannot steer either the stored
    /// namespace or the stored id.
    pub fn default_singleton_id(namespace: &str) -> String {
        namespace.to_string()
    }

    /// Idempotent admission normalization for entrypoints that have already
    /// forced the authenticated target namespace onto the record (restore,
    /// import, loaders).
    ///
    /// Trims, then defaults `id` to the (already server-owned) namespace. A
    /// client that sends a *conflicting* `trust_domain` is rejected by
    /// [`Self::validate_fields`] rather than silently corrected — see the
    /// mismatch check there.
    pub fn normalize_fields(&mut self) {
        self.trim_fields();
        if self.id.is_empty() {
            self.id = Self::default_singleton_id(&self.namespace);
        }
    }

    /// Full syntactic + semantic admission validation.
    ///
    /// Structural count and cheap encoded/raw size bounds are enforced first
    /// and fail closed. If any of those bounds fail, this returns only the
    /// material-free field, count, and size diagnostics and does not invoke
    /// [`TrustDomain::new`], [`crate::modes::mesh::config::validate_mesh_config`],
    /// X.509 DER parsing, JWT public-key parsing, or runtime conversion. That
    /// is deliberate hostile-input behavior: enumerating unrelated semantic
    /// errors would require cloning or decoding the over-limit material. The
    /// restore endpoint accepts bodies far larger than
    /// [`MAX_TRUST_BUNDLE_JSON_BYTES`], so allocating or deep parsers must not
    /// run against an over-limit record. Cheap empty, identity-mismatch, and
    /// audit-actor diagnostics may still be collected because they do not
    /// clone or parse the bounded material.
    ///
    /// Once the record is within those bounds, the exact serialized
    /// [`MAX_TRUST_BUNDLE_JSON_BYTES`] contract is checked (including JSON
    /// escaping overhead) with a counting writer so the check does not
    /// allocate the document. Every remaining semantic problem is then
    /// collected so an operator repairing a bad rotation sees the whole list.
    /// No message ever contains trust material — only field names, indices,
    /// and sizes.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.id.is_empty() {
            errors.push("gateway trust bundle id is required".to_string());
        } else if self.id.len() > MAX_TRUST_BUNDLE_ID_BYTES {
            errors.push(format!(
                "gateway trust bundle id exceeds {MAX_TRUST_BUNDLE_ID_BYTES} bytes"
            ));
        }
        if self.namespace.trim().is_empty() {
            errors.push("gateway trust bundle namespace is required".to_string());
        }

        // Identity: the stored trust domain names the material it carries.
        let local_domain = self.bundle.local.trust_domain.as_str();
        if self.trust_domain.is_empty() {
            errors.push("gateway trust bundle trust_domain is required".to_string());
        } else if self.trust_domain != local_domain {
            errors.push(
                "gateway trust bundle trust_domain does not match bundle.local.trust_domain"
                    .to_string(),
            );
        }
        if self
            .updated_by
            .as_ref()
            .is_some_and(|actor| actor.chars().count() > MAX_AUDIT_ACTOR_CHARS)
        {
            errors.push(format!(
                "gateway trust bundle updated_by exceeds {MAX_AUDIT_ACTOR_CHARS} characters"
            ));
        }

        if let Err(bundle_errors) = validate_trust_bundle_set(&self.bundle) {
            errors.extend(bundle_errors);
        }

        finish_validation(errors)
    }

    /// Redacted, fixed-shape summary for logs, metrics, and admin status.
    ///
    /// Deliberately carries no PEM/DER bytes, no key material, and no
    /// unbounded identifiers — only the trust domain (which is already public
    /// configuration), counts, and the revision.
    pub fn summary(&self) -> GatewayTrustBundleSummary {
        GatewayTrustBundleSummary {
            namespace: self.namespace.clone(),
            trust_domain: self.trust_domain.clone(),
            revision: self.revision,
            x509_authority_count: self.bundle.local.x509_authorities.len(),
            jwt_authority_count: self.bundle.local.jwt_authorities.len(),
            federated_count: self.bundle.federated.len(),
            updated_at: self.updated_at,
        }
    }
}

/// Validate the authoritative gateway trust document at every trust boundary.
///
/// Admin/database admission, CP wire publication, DP wire admission, and mesh
/// federation staging all call this ONE validator. Structural and exact JSON
/// bounds run before the deep parsers, and every diagnostic is material-free.
/// Keeping this contract here prevents a side channel from accepting material
/// that persistence would reject (or vice versa).
pub fn validate_trust_bundle_set(bundle: &TrustBundleSet) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    collect_structural_limit_errors(bundle, &mut errors);
    if !errors.is_empty() {
        return finish_validation(errors);
    }

    match serialized_bundle_len(bundle) {
        Ok(encoded_len) if encoded_len > MAX_TRUST_BUNDLE_JSON_BYTES => {
            errors.push(format!(
                "gateway trust bundle encodes to {encoded_len} bytes; the maximum is {MAX_TRUST_BUNDLE_JSON_BYTES}"
            ));
            return finish_validation(errors);
        }
        Ok(_) => {}
        Err(_) => {
            errors.push("gateway trust bundle could not be serialized".to_string());
            return finish_validation(errors);
        }
    }

    let local_domain = bundle.local.trust_domain.as_str();
    if TrustDomain::new(local_domain.to_string()).is_err() {
        errors.push(
            "gateway trust bundle bundle.local.trust_domain is not a valid SPIFFE trust domain"
                .to_string(),
        );
    }

    errors.extend(crate::modes::mesh::config::validate_mesh_config(
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        Some(bundle),
    ));

    validate_single_bundle(&bundle.local, "bundle.local", &mut errors);
    for (index, federated) in bundle.federated.iter().enumerate() {
        validate_single_bundle(
            federated,
            &format!("bundle.federated[{index}]"),
            &mut errors,
        );
    }

    if bundle
        .federated
        .iter()
        .any(|federated| federated.trust_domain.as_str() == local_domain)
    {
        errors.push(
            "gateway trust bundle federated entry repeats the local trust domain".to_string(),
        );
    }

    if bundle.to_runtime().is_err() {
        errors.push("gateway trust bundle contains undecodable trust material".to_string());
    }

    finish_validation(errors)
}

fn finish_validation(mut errors: Vec<String>) -> Result<(), Vec<String>> {
    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort();
        errors.dedup();
        Err(errors)
    }
}

/// STANDARD base64 length of `decoded_bytes` of DER, including padding.
const fn max_standard_base64_len(decoded_bytes: usize) -> usize {
    4 * decoded_bytes.div_ceil(3)
}

fn x509_encoded_exceeds_der_limit(encoded: &str) -> bool {
    encoded.len() > max_standard_base64_len(MAX_X509_AUTHORITY_DER_BYTES)
}

/// Counts, per-entry encoded/raw sizes, and a cheap whole-bundle lower bound.
///
/// Over-limit collections are not walked for per-entry checks. A failed
/// structural bound is the caller's signal to skip every deep parser.
fn collect_structural_limit_errors(
    bundle: &crate::modes::mesh::config::TrustBundleSet,
    errors: &mut Vec<String>,
) {
    let federated_over = bundle.federated.len() > MAX_FEDERATED_BUNDLES;
    if federated_over {
        errors.push(format!(
            "gateway trust bundle declares {} federated bundles; the maximum is {MAX_FEDERATED_BUNDLES}",
            bundle.federated.len()
        ));
    }

    collect_bundle_count_and_encoded_size_errors(&bundle.local, "bundle.local", errors);

    if federated_over {
        return;
    }

    for (index, federated) in bundle.federated.iter().enumerate() {
        collect_bundle_count_and_encoded_size_errors(
            federated,
            &format!("bundle.federated[{index}]"),
            errors,
        );
    }

    if !errors.is_empty() {
        return;
    }

    let raw = bundle_raw_material_bytes(bundle);
    if raw > MAX_TRUST_BUNDLE_JSON_BYTES {
        errors.push(format!(
            "gateway trust bundle raw material is {raw} bytes; the maximum is {MAX_TRUST_BUNDLE_JSON_BYTES}"
        ));
    }
}

fn collect_bundle_count_and_encoded_size_errors(
    bundle: &crate::modes::mesh::config::TrustBundle,
    label: &str,
    errors: &mut Vec<String>,
) {
    let x509_over = bundle.x509_authorities.len() > MAX_X509_AUTHORITIES_PER_BUNDLE;
    if x509_over {
        errors.push(format!(
            "{label} declares {} x509 authorities; the maximum is {MAX_X509_AUTHORITIES_PER_BUNDLE}",
            bundle.x509_authorities.len()
        ));
    }
    let jwt_over = bundle.jwt_authorities.len() > MAX_JWT_AUTHORITIES_PER_BUNDLE;
    if jwt_over {
        errors.push(format!(
            "{label} declares {} jwt authorities; the maximum is {MAX_JWT_AUTHORITIES_PER_BUNDLE}",
            bundle.jwt_authorities.len()
        ));
    }

    if !x509_over {
        for (index, encoded) in bundle.x509_authorities.iter().enumerate() {
            if x509_encoded_exceeds_der_limit(encoded) {
                errors.push(format!(
                    "{label}.x509_authorities[{index}] encoded value cannot decode within {MAX_X509_AUTHORITY_DER_BYTES} bytes"
                ));
            }
        }
    }

    if !jwt_over {
        for (index, authority) in bundle.jwt_authorities.iter().enumerate() {
            if authority.key_id.len() > MAX_JWT_AUTHORITY_KEY_ID_BYTES {
                errors.push(format!(
                    "{label}.jwt_authorities[{index}] key_id exceeds {MAX_JWT_AUTHORITY_KEY_ID_BYTES} bytes"
                ));
            }
            if authority.public_key_pem.len() > MAX_JWT_AUTHORITY_PEM_BYTES {
                errors.push(format!(
                    "{label}.jwt_authorities[{index}] public_key_pem exceeds {MAX_JWT_AUTHORITY_PEM_BYTES} bytes"
                ));
            }
        }
    }
}

fn bundle_raw_material_bytes(bundle: &crate::modes::mesh::config::TrustBundleSet) -> usize {
    let mut total = trust_bundle_raw_material_bytes(&bundle.local);
    for federated in &bundle.federated {
        total = total.saturating_add(trust_bundle_raw_material_bytes(federated));
    }
    total
}

fn trust_bundle_raw_material_bytes(bundle: &crate::modes::mesh::config::TrustBundle) -> usize {
    let mut total = bundle.trust_domain.as_str().len();
    for encoded in &bundle.x509_authorities {
        total = total.saturating_add(encoded.len());
    }
    for authority in &bundle.jwt_authorities {
        total = total
            .saturating_add(authority.key_id.len())
            .saturating_add(authority.public_key_pem.len());
    }
    total
}

/// Exact serialized length, including JSON escaping, without retaining the document.
fn serialized_bundle_len(
    bundle: &crate::modes::mesh::config::TrustBundleSet,
) -> Result<usize, serde_json::Error> {
    let mut counter = JsonSizeCounter { bytes: 0 };
    serde_json::to_writer(&mut counter, bundle)?;
    Ok(counter.bytes)
}

struct JsonSizeCounter {
    bytes: usize,
}

impl std::io::Write for JsonSizeCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deep, allocating validation of ONE bundle.
///
/// Count bounds are deliberately NOT re-emitted here.
/// [`collect_structural_limit_errors`] owns them and
/// [`validate_trust_bundle_set`] returns before this function on any structural
/// failure, so an over-limit collection can never reach these parsers and a
/// duplicated diagnostic could only ever be dead work. The skip-deep-parse
/// property is therefore a property of the caller's early return, and the two
/// guards below keep it locally true for any future caller: an over-limit
/// collection is left unwalked rather than silently deep-parsed.
fn validate_single_bundle(
    bundle: &crate::modes::mesh::config::TrustBundle,
    label: &str,
    errors: &mut Vec<String>,
) {
    if bundle.x509_authorities.len() <= MAX_X509_AUTHORITIES_PER_BUNDLE {
        validate_x509_authorities(bundle, label, errors);
    }
    if bundle.jwt_authorities.len() <= MAX_JWT_AUTHORITIES_PER_BUNDLE {
        validate_jwt_authorities(bundle, label, errors);
    }
}

fn validate_x509_authorities(
    bundle: &crate::modes::mesh::config::TrustBundle,
    label: &str,
    errors: &mut Vec<String>,
) {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    for (index, encoded) in bundle.x509_authorities.iter().enumerate() {
        if x509_encoded_exceeds_der_limit(encoded) {
            errors.push(format!(
                "{label}.x509_authorities[{index}] encoded value cannot decode within {MAX_X509_AUTHORITY_DER_BYTES} bytes"
            ));
            continue;
        }
        let der = match engine.decode(encoded.as_bytes()) {
            Ok(der) => der,
            Err(_) => {
                // `validate_mesh_config` already reported the base64 failure
                // with its index; do not duplicate the message here.
                continue;
            }
        };
        if der.len() > MAX_X509_AUTHORITY_DER_BYTES {
            errors.push(format!(
                "{label}.x509_authorities[{index}] is {} bytes; the maximum is {MAX_X509_AUTHORITY_DER_BYTES}",
                der.len()
            ));
            continue;
        }
        // The certificate must consume the COMPLETE entry. A parser that
        // stops early would admit an authority whose stored bytes carry
        // appended material an operator (or a differently-strict verifier)
        // would read as part of the document.
        match X509Certificate::from_der(&der) {
            Ok(([], _)) => {}
            Ok(_) => errors.push(format!(
                "{label}.x509_authorities[{index}] carries trailing bytes after its X.509 certificate"
            )),
            Err(_) => errors.push(format!(
                "{label}.x509_authorities[{index}] is not a parseable X.509 certificate"
            )),
        }
    }
}

fn validate_jwt_authorities(
    bundle: &crate::modes::mesh::config::TrustBundle,
    label: &str,
    errors: &mut Vec<String>,
) {
    let mut seen_key_ids = HashSet::new();
    for (index, authority) in bundle.jwt_authorities.iter().enumerate() {
        if authority.key_id.trim().is_empty() {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] has an empty key_id"
            ));
        } else if authority.key_id.len() > MAX_JWT_AUTHORITY_KEY_ID_BYTES {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] key_id exceeds {MAX_JWT_AUTHORITY_KEY_ID_BYTES} bytes"
            ));
        } else if !seen_key_ids.insert(authority.key_id.as_str()) {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] repeats a key_id already declared in this bundle"
            ));
        }
        if authority.public_key_pem.len() > MAX_JWT_AUTHORITY_PEM_BYTES {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] public_key_pem exceeds {MAX_JWT_AUTHORITY_PEM_BYTES} bytes"
            ));
        } else if !is_usable_public_key_pem(&authority.public_key_pem) {
            errors.push(format!(
                "{label}.jwt_authorities[{index}] public_key_pem is not a usable PEM public key"
            ));
        }
    }
}

/// Prove the purported public key is one the JWT-SVID stack can actually use.
///
/// This reuses the existing JWT/JWKS authority parser
/// ([`is_usable_public_key_material`](crate::identity::jwt_svid::jwks::is_usable_public_key_material)),
/// which decodes the SPKI DER (or the SPIFFE-federation JWK form) completely
/// and refuses a key type or curve point the validator could not verify with. A
/// structural starts_with/ends_with check would admit a PRIVATE KEY paste
/// wrapped in the right header, a truncated body, or a key type the mesh cannot
/// use — material that persists and publishes to every subscriber but can never
/// validate.
///
/// The parser's error is discarded on purpose: its text is already
/// material-free, but this module's contract is that admission messages name
/// only the field and index.
fn is_usable_public_key_pem(pem: &str) -> bool {
    crate::identity::jwt_svid::jwks::is_usable_public_key_material(pem)
}

/// Fixed-cardinality, material-free description of one namespace's trust state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayTrustBundleSummary {
    pub namespace: String,
    pub trust_domain: String,
    pub revision: u64,
    pub x509_authority_count: usize,
    pub jwt_authority_count: usize,
    pub federated_count: usize,
    pub updated_at: DateTime<Utc>,
}

/// Material-free identity of the trust state that actually reached the live
/// configuration swap for one namespace.
///
/// This is deliberately separate from the current database row. An admin write
/// is only a candidate until the poller reloads, validates, and publishes it;
/// an invalid out-of-band row may never publish at all. Status must therefore
/// report this snapshot instead of pairing a database revision with an
/// unrelated process-wide publication counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishedGatewayTrustState {
    pub generation: String,
    pub bundle: GatewayTrustBundleSummary,
}

// ─── Authoritative drift detection ──────────────────────────────────────────
//
// Why a reader-side check exists at all.
//
// Every backend except standalone MongoDB commits a trust document mutation
// and its `config_changes` poll signal in ONE transaction, so a poller that
// consumed a sequence has, by construction, already been able to read the
// document that sequence describes. Standalone MongoDB has no multi-document
// transaction, and NO ordering of the two writes closes the hole on its own:
//
// - Signal first, document second. A live poller can read the signal at
//   sequence N, escalate to a full reload that still reads the OLD document,
//   advance its cursor past N, and only then does the document commit. There
//   is no later signal, so that running poller never learns about the
//   mutation until it restarts or an unrelated change forces another reload.
// - Document first, signal second. A crash between the two commits a mutation
//   with no signal at all, which is the same invisibility with a wider window.
// - Both (signal, document, signal). The crash boundary between the document
//   commit and the trailing signal reproduces the first case exactly: the
//   leading signal may already have been consumed, and the trailing one never
//   lands.
//
// So the WRITE side cannot prove visibility on this topology, and this module
// deliberately does not claim it does. The READ side can: the stored document
// is authoritative, and comparing its material-free identity against the trust
// state the running configuration was actually built from detects every one of
// the cases above with no dependence on signals, ordering, or process
// survival. That comparison is what [`detect_gateway_trust_drift`] performs,
// on the cold poll path only, and only for backends that report their trust
// writes are not atomic with the change log.

/// Material-free identity of one namespace's stored trust document.
///
/// Deliberately carries no bundle material: it is read with a field projection
/// so PEM/DER bytes never cross the store boundary for a drift check, and it
/// can be logged in full. `revision` is the backend-assigned durable change
/// sequence, which every physical write (including a delete-then-recreate)
/// advances, so identity equality is exactly "the same committed trust
/// incarnation".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayTrustBundleIdentity {
    pub id: String,
    pub trust_domain: String,
    pub revision: u64,
}

impl GatewayTrustBundleIdentity {
    /// The identity of an already-loaded record.
    pub fn of(record: &GatewayTrustBundleRecord) -> Self {
        Self {
            id: record.id.clone(),
            trust_domain: record.trust_domain.clone(),
            revision: record.revision,
        }
    }
}

/// Whether the trust state a running configuration was built from disagrees
/// with what the store currently holds for that namespace.
///
/// Both directions matter and are distinct outcomes upstream, so both are
/// drift here:
///
/// - `held = None`, `stored = Some(_)` — a create or a rotation whose signal
///   was consumed before the document landed.
/// - `held = Some(_)`, `stored = None` — a **revocation** whose delete landed
///   after its signal was consumed. This is the security-critical direction:
///   without it a data plane keeps validating with roots an operator revoked.
/// - Both `Some(_)` with different identities — a rotation, including one that
///   deleted and recreated the namespace singleton.
pub fn gateway_trust_state_drifted(
    held: Option<&GatewayTrustBundleRecord>,
    stored: Option<&GatewayTrustBundleIdentity>,
) -> bool {
    match (held, stored) {
        (None, None) => false,
        (Some(held), Some(stored)) => GatewayTrustBundleIdentity::of(held) != *stored,
        _ => true,
    }
}

/// The minimal store surface authoritative drift detection needs.
///
/// Deliberately narrower than `DatabaseBackend`: the check must be provable
/// against a deterministic fake that can interleave a consumed signal with a
/// later document commit, and it must be impossible for this path to reach any
/// mutating or material-bearing store method. `dyn DatabaseBackend` implements
/// it directly (see `db_backend.rs`); a blanket implementation is deliberately
/// avoided so an external test crate can still implement this trait for its own
/// simulator.
#[allow(clippy::double_must_use)] // async-trait adds a bare #[must_use]
#[async_trait::async_trait]
pub trait GatewayTrustDriftSource: Send + Sync {
    /// `true` when a trust document mutation and its `config_changes` signal
    /// commit as one atomic unit, which makes the signal alone sufficient and
    /// this whole check unnecessary. SQL and replica-set MongoDB report `true`;
    /// standalone MongoDB reports `false`.
    fn gateway_trust_writes_are_atomic_with_change_log(&self) -> bool;

    /// Read the namespace's stored trust identity from the authoritative
    /// primary, without decoding trust material.
    async fn gateway_trust_bundle_identity(
        &self,
        namespace: &str,
    ) -> Result<Option<GatewayTrustBundleIdentity>, anyhow::Error>;
}

/// Cold-path authoritative drift sweep for one poll tick.
///
/// Returns the namespaces whose stored trust document no longer matches the
/// trust state `held` was built from; the caller escalates those to a full
/// reload, which is the only path that republishes trust from one authoritative
/// read.
///
/// Cost and safety properties this deliberately preserves:
///
/// - **Zero cost on transactional backends.** A source whose trust writes are
///   atomic with the change log returns immediately, so SQL and replica-set
///   MongoDB add no query and keep their existing signal-driven behaviour.
/// - **Bounded.** At most ONE projected single-document read per polled
///   namespace per tick, and the projection excludes the bundle, so neither the
///   query count nor the bytes read scale with trust material.
/// - **Namespace isolation.** Every read is predicated on its own namespace and
///   compared only against that namespace's held record; one tenant's drift can
///   never be inferred from, or attributed to, another's.
/// - **Last known good.** A read failure is reported and skipped, never
///   converted into a reload or a withdrawal — an unreadable stored document
///   could not be published by a full reload either, so forcing one would only
///   spin while the running configuration is already the last known good state.
/// - **Redaction.** Drift and read-failure logs carry only the namespace and
///   fixed-cardinality classifications; store/driver errors are never rendered.
pub async fn detect_gateway_trust_drift<S: GatewayTrustDriftSource + ?Sized>(
    source: &S,
    namespaces: &[String],
    held: &crate::config::types::GatewayConfig,
) -> Vec<String> {
    if source.gateway_trust_writes_are_atomic_with_change_log() {
        return Vec::new();
    }
    let mut drifted = Vec::new();
    for namespace in namespaces {
        let stored = match source.gateway_trust_bundle_identity(namespace).await {
            Ok(stored) => stored,
            Err(_error) => {
                tracing::warn!(
                    namespace = %namespace,
                    failure_class = "identity_read_failed",
                    detail_withheld = true,
                    "Gateway trust drift check could not read the stored trust identity; \
                     keeping the running trust state and retrying on the next poll"
                );
                continue;
            }
        };
        let held_record = held.gateway_trust_bundle_for(namespace);
        if gateway_trust_state_drifted(held_record, stored.as_ref()) {
            tracing::info!(
                namespace = %namespace,
                published_revision = held_record.map(|record| record.revision).unwrap_or(0),
                stored_revision = stored.as_ref().map(|stored| stored.revision).unwrap_or(0),
                "Stored gateway trust bundle differs from the published trust state on a \
                 backend whose trust writes are not atomic with the change log; escalating to \
                 an authoritative full reload"
            );
            drifted.push(namespace.clone());
        }
    }
    drifted
}

/// Publication semantics for one namespace's gateway trust state.
///
/// This is the CP-side mirror of the DP's `GatewayTrustBundleUpdate` and the
/// reason the side channel can express a rotation, a revocation, and "nothing
/// to say" without any of the three being inferable from the other two.
///
/// `Clear`, `Replace`, and the snapshot/delta helpers below are public library
/// and integration-test seams. The `ferrum-edge` bin target recompiles this
/// module privately and only constructs [`Self::Unchanged`] on the ordinary
/// resource-delta path; production full-snapshot encoding stays in
/// `CpGrpcServer::filter_config_and_trust_for_scope` / `trust_bundles_json` so
/// deep validation, ambiguity refusal, and fail-closed skip behavior are not
/// duplicated here. `#[allow(dead_code)]` is therefore scoped to this enum and
/// its impl, not the module.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum GatewayTrustPublication<'a> {
    /// Emit nothing: the subscriber keeps whatever it already applied. Encoded
    /// as an empty `trust_bundles_json`.
    Unchanged,
    /// Withdraw previously delivered trust material. Encoded as JSON `null`.
    Clear,
    /// Install this material, replacing whatever was applied before. Encoded as
    /// the serialized `TrustBundleSet`.
    Replace(&'a TrustBundleSet),
}

#[allow(dead_code)]
impl<'a> GatewayTrustPublication<'a> {
    /// Resolve the publication for a full snapshot, where the CP always states
    /// the complete current state so a reconnecting DP can reconstruct it.
    pub fn for_snapshot(record: Option<&'a GatewayTrustBundleRecord>) -> Self {
        match record {
            Some(record) => Self::Replace(&record.bundle),
            None => Self::Clear,
        }
    }

    /// Resolve the publication for a delta, where "no trust change in this
    /// poll" must be distinguishable from "trust was revoked".
    ///
    /// `previous` is the state the CP last published for the namespace and
    /// `current` is the state it just committed. Equality is on the complete
    /// record identity + material, so a revision bump with identical material
    /// still republishes (cheap, and keeps a lagging replica convergent) while
    /// an untouched namespace emits nothing at all.
    pub fn for_delta(
        previous: Option<&GatewayTrustBundleRecord>,
        current: Option<&'a GatewayTrustBundleRecord>,
    ) -> Self {
        match (previous, current) {
            (None, None) => Self::Unchanged,
            (Some(_), None) => Self::Clear,
            (None, Some(current)) => Self::Replace(&current.bundle),
            (Some(previous), Some(current)) => {
                if previous.revision == current.revision && previous.bundle == current.bundle {
                    Self::Unchanged
                } else {
                    Self::Replace(&current.bundle)
                }
            }
        }
    }

    /// Encode to the `trust_bundles_json` wire value.
    ///
    /// A serialization failure is returned to the caller. A bundle that passed
    /// admission should always serialize, but the transport must still choose
    /// the protocol-appropriate fail-closed response if that invariant breaks.
    pub fn to_side_channel_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Unchanged => Ok(String::new()),
            Self::Clear => Ok("null".to_string()),
            Self::Replace(bundle) => serde_json::to_string(bundle),
        }
    }
}

/// Resolve the single authoritative trust source for a namespace.
///
/// Precedence is deliberately not "database wins, quietly": a deployment that
/// carries BOTH a database record and a file/overlay-sourced
/// `GatewayConfig.trust_bundles` has two authorities that can disagree per
/// replica, which is exactly the divergence issue #3727 exists to remove. In
/// that case production modes fail closed and keep the last known good state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAuthorityResolution {
    /// The database record is authoritative (or there is nothing to publish).
    Database,
    /// No database record; the file-sourced value stands.
    File,
    /// Both authorities present — ambiguous, refuse.
    Ambiguous,
}

/// Classify the trust authorities visible for one namespace.
pub fn resolve_trust_authority(
    database_record: Option<&GatewayTrustBundleRecord>,
    file_sourced: Option<&TrustBundleSet>,
) -> TrustAuthorityResolution {
    match (database_record, file_sourced) {
        (Some(_), Some(_)) => TrustAuthorityResolution::Ambiguous,
        (Some(_), None) => TrustAuthorityResolution::Database,
        (None, Some(_)) => TrustAuthorityResolution::File,
        (None, None) => TrustAuthorityResolution::Database,
    }
}

/// What one namespace-scoped publication should say about trust.
///
/// This is the candidate/publication boundary for trust: it is resolved from
/// the authorities visible BEFORE any namespace partitioning clears the
/// unpartitioned slot, so a database record plus a file/overlay value is still
/// recognizable as two authorities rather than looking database-only.
#[derive(Debug, Clone, PartialEq)]
pub enum NamespaceTrustProjection {
    /// Install this material.
    Replace(TrustBundleSet),
    /// Withdraw previously delivered material.
    Clear,
    /// Say nothing: the subscriber keeps the last trust generation it accepted.
    ///
    /// This is the ambiguous-authority outcome. Converting ambiguity into a
    /// `Clear` would revoke a working generation on every replica the moment a
    /// leftover file value appeared next to a database record — an outage
    /// caused by a configuration smell. Issue #3727 asks for the ambiguity to
    /// be *rejected* while last-known-good is retained, which is exactly this.
    KeepPrevious,
}

/// Resolve the publication for one namespace from the authorities visible
/// before partitioning.
///
/// `file_sourced_admissible` is false on scopes that require a namespace claim
/// (multi-namespace control planes): an unpartitioned value must never reach a
/// namespace-scoped stream there, so a file-only deployment withdraws rather
/// than publishing material it cannot attribute to the subscriber.
pub fn project_namespace_trust(
    database_record: Option<&GatewayTrustBundleRecord>,
    file_sourced: Option<&TrustBundleSet>,
    file_sourced_admissible: bool,
) -> NamespaceTrustProjection {
    match resolve_trust_authority(database_record, file_sourced) {
        TrustAuthorityResolution::Ambiguous => NamespaceTrustProjection::KeepPrevious,
        TrustAuthorityResolution::Database => match database_record {
            Some(record) => NamespaceTrustProjection::Replace(record.bundle.clone()),
            None => NamespaceTrustProjection::Clear,
        },
        TrustAuthorityResolution::File => match (file_sourced, file_sourced_admissible) {
            (Some(bundle), true) => NamespaceTrustProjection::Replace(bundle.clone()),
            _ => NamespaceTrustProjection::Clear,
        },
    }
}

/// Operator-facing message for the ambiguous-authority refusal. Names no paths,
/// no material, and no namespace-derived secrets.
pub const AMBIGUOUS_TRUST_AUTHORITY_MESSAGE: &str = "namespace declares both a database gateway trust-bundle resource and a file-sourced \
     trust_bundles value; resolve to a single authority before the control plane can publish";

// ─── Observability ──────────────────────────────────────────────────────────
//
// Fixed cardinality by construction: these are process-wide counters with NO
// labels. A per-namespace label would be unbounded on a cluster-wide CP, and
// namespace names are tenant-identifying, so the namespace-scoped view lives on
// the authenticated admin status surface instead. Nothing here can carry PEM /
// JWKS bytes, secret or provider URIs, or an unbounded identifier — only
// counters, a revision number, and a bounded reason enum.

static PUBLISHED_GENERATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOAD_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static AMBIGUOUS_AUTHORITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static LAST_PUBLISHED_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);
static LAST_FAILURE_REASON: AtomicU8 = AtomicU8::new(0);
static PUBLISHED_NAMESPACE_STATES: LazyLock<ArcSwap<HashMap<String, PublishedGatewayTrustState>>> =
    LazyLock::new(|| ArcSwap::from_pointee(HashMap::new()));

/// Bounded reason for the most recent trust-load failure. Deliberately an enum,
/// not a message: a free-form reason could echo stored material into `/metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTrustFailureReason {
    None,
    /// Stored material failed admission validation (size, syntax, identity).
    InvalidMaterial,
    /// The stored row/document could not be decoded at all.
    Undecodable,
    /// Two authorities were visible at once, so the publication was REFUSED.
    /// Trust is not withdrawn: the side channel says nothing and every
    /// subscriber keeps the last generation it accepted
    /// ([`NamespaceTrustProjection::KeepPrevious`]).
    AmbiguousAuthority,
}

impl GatewayTrustFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InvalidMaterial => "invalid_material",
            Self::Undecodable => "undecodable",
            Self::AmbiguousAuthority => "ambiguous_authority",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::InvalidMaterial => 1,
            Self::Undecodable => 2,
            Self::AmbiguousAuthority => 3,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::InvalidMaterial,
            2 => Self::Undecodable,
            3 => Self::AmbiguousAuthority,
            _ => Self::None,
        }
    }
}

/// Whether a publication carried EVERY namespace the loader was asked to
/// refresh, or only the ones that survived.
///
/// A multi-namespace control-plane reload is per-namespace isolated (#2983): a
/// namespace whose trust candidate is refused keeps its last-known-good
/// generation while the namespaces that loaded cleanly are still committed and
/// broadcast. That partial publication must not read as recovery on the
/// gateway-trust status surface — the refused candidate is still refused — so
/// the scope is carried explicitly to the publication boundary instead of being
/// inferred from the accepted records (which say nothing about the namespace
/// that never got there).
///
/// This mirrors `settle_full_reload_rejection_state`'s rule for the generic
/// `config_rejected` signal: only a reload that refreshed every polled
/// namespace may clear a standing failure. It carries no namespace name and no
/// material — it is a two-valued flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPublicationScope {
    /// Every namespace in scope was re-read and accepted. A standing
    /// gateway-trust failure is genuinely resolved by this publication.
    Complete,
    /// At least one namespace was rejected or could not be refreshed, and is
    /// serving last-known-good. Accepted namespaces still publish and still
    /// count; any standing bounded failure reason is preserved until a
    /// complete publication proves it resolved.
    Partial,
}

/// Record a trust generation that reached the ACTUAL publication boundary —
/// the `ArcSwap` store that makes a configuration generation live.
///
/// Deliberately not called from inside a per-namespace database load: a load
/// still has validation, overlay composition, the atomic swap, and broadcast
/// ahead of it, so counting there would report generations that were never
/// published. Publications that carry no database trust record at all are not
/// counted either — this counter answers "did a stored trust generation go
/// live", not "did any config swap happen".
///
/// It is also not counted per subscriber: the call site is the swap, not a
/// stream, so a data plane reconnecting and receiving the same generation again
/// never inflates the counter.
///
/// `file_sourced` is the publication's unpartitioned `GatewayConfig.trust_bundles`
/// slot, and it is what keeps the counter honest about the ambiguity refusal.
/// The per-namespace projection that refuses an ambiguous authority runs later,
/// during broadcast, so counting here without consulting it would report a
/// successful trust publication for a generation whose every database record
/// was about to be refused. That slot is a SINGLE unpartitioned value compared
/// against every namespace's record by [`resolve_trust_authority`], so the
/// outcome is all-or-nothing: when it is `Some`, every database record in this
/// generation is ambiguous and nothing distributable is published (the
/// refusal's own counter and bounded reason are recorded here at the same
/// publication boundary); when it is `None`, no
/// record is ambiguous and a mixed generation — some namespaces accepted, some
/// refused — cannot arise. Multi-namespace generations therefore still count
/// exactly once, as one generation reaching the swap.
///
/// There is deliberately no process-wide "published revision": revisions are
/// per namespace and a last-writer-wins process atomic would be actively
/// misleading on a multi-namespace control plane. The per-namespace revision is
/// on the authenticated `GET /gateway-trust/status` view instead.
pub fn record_trust_generation_published(
    records: &[GatewayTrustBundleRecord],
    file_sourced: Option<&TrustBundleSet>,
    now_unix_seconds: u64,
) {
    record_trust_generation_published_scoped(
        records,
        file_sourced,
        now_unix_seconds,
        TrustPublicationScope::Complete,
    );
}

/// [`record_trust_generation_published`] for a publication that may have
/// covered only part of its namespace scope.
///
/// `scope` decides one thing and one thing only: whether this publication is
/// allowed to clear the standing bounded failure reason. Everything else —
/// the published namespace view, the generation counter, the timestamp, the
/// ambiguity refusal accounting — is identical, so an accepted namespace is
/// never denied its successful generation accounting because a *different*
/// namespace was refused. No rejection counter is touched here either: the
/// refusal already counted itself at the load that refused it, and counting it
/// again per publication would inflate `load_rejections_total` once per poll
/// cycle for as long as the bad material stayed stored.
pub fn record_trust_generation_published_scoped(
    records: &[GatewayTrustBundleRecord],
    file_sourced: Option<&TrustBundleSet>,
    now_unix_seconds: u64,
    scope: TrustPublicationScope,
) {
    // A publication that left a rejected namespace on last-known-good has not
    // resolved that namespace's refusal, so the standing reason survives until
    // a complete publication proves it did.
    let resolves_standing_failure = matches!(scope, TrustPublicationScope::Complete);
    if file_sourced.is_some() {
        // Every CURRENT database record is ambiguous and keeps its prior live
        // state. A namespace whose database record was revoked is no longer
        // ambiguous, though: its projection resolves to the file-only/clear
        // outcome, so it must not keep advertising the removed database
        // revision. Retain only prior states that still have a current record;
        // do not insert newly ambiguous records that never published.
        let current_namespaces: HashSet<&str> = records
            .iter()
            .map(|record| record.namespace.as_str())
            .collect();
        // Read-modify-write through `rcu`, never load → clone → store. This
        // branch RETAINS part of the map, so a plain load/store pair would drop
        // a namespace another publisher committed between the two — a lost
        // update on published trust state. `rcu` re-runs the closure until the
        // compare-and-swap wins, and returns exactly the map this call
        // replaced, so `revoked_database_state` is decided from the value that
        // was actually superseded rather than from a racing snapshot.
        let previous = PUBLISHED_NAMESPACE_STATES.rcu(|current| {
            let mut retained = current.as_ref().clone();
            retained.retain(|namespace, _| current_namespaces.contains(namespace.as_str()));
            Arc::new(retained)
        });
        let revoked_database_state = records.is_empty() && !previous.is_empty();
        if !records.is_empty() {
            // Count the refused generation exactly once at the live swap. The
            // later per-namespace projection can run zero times (no active
            // subscriber) or many times (reconnects); neither may suppress or
            // inflate process-level publication observability.
            record_ambiguous_authority();
        } else {
            // File-only/empty state is a valid, unambiguous publication. It
            // does not count as a database trust generation, but it does
            // resolve any standing load/authority failure — provided it covered
            // every namespace in scope.
            if resolves_standing_failure {
                LAST_FAILURE_REASON
                    .store(GatewayTrustFailureReason::None.code(), Ordering::Relaxed);
            }
            if revoked_database_state {
                LAST_PUBLISHED_UNIX_SECONDS.store(now_unix_seconds, Ordering::Relaxed);
            }
        }
        return;
    }

    // Replace the complete namespace view at the same publication boundary as
    // the live GatewayConfig swap. This also records explicit revocation: an
    // empty accepted generation clears every previously published database
    // record even though it deliberately does not increment the
    // database-record publication counter below.
    let published: HashMap<String, PublishedGatewayTrustState> = records
        .iter()
        .map(|record| {
            (
                record.namespace.clone(),
                PublishedGatewayTrustState {
                    generation: trust_generation_fingerprint(std::slice::from_ref(record)),
                    bundle: record.summary(),
                },
            )
        })
        .collect();
    // One atomic exchange, not a load followed by a store: `records` is the
    // COMPLETE accepted view, so the new value does not depend on the old one,
    // but the revocation test does. Swapping returns the map this call actually
    // replaced, so a concurrent publication cannot make one publisher observe
    // the other's map and mis-decide `revoked_database_state`.
    let previous = PUBLISHED_NAMESPACE_STATES.swap(Arc::new(published));
    let revoked_database_state = records.is_empty() && !previous.is_empty();
    // An accepted explicit revocation is still a successful trust publication:
    // clear the standing failure even though an empty database generation does
    // not advance the record-bearing generation counter or timestamp. A
    // PARTIAL publication does not clear it: a namespace whose trust candidate
    // was refused is still serving last-known-good, and letting the namespaces
    // that did load report the failure away is exactly the false recovery this
    // scope exists to prevent.
    if resolves_standing_failure {
        LAST_FAILURE_REASON.store(GatewayTrustFailureReason::None.code(), Ordering::Relaxed);
    }

    if records.is_empty() {
        if revoked_database_state {
            LAST_PUBLISHED_UNIX_SECONDS.store(now_unix_seconds, Ordering::Relaxed);
        }
        return;
    }
    PUBLISHED_GENERATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_PUBLISHED_UNIX_SECONDS.store(now_unix_seconds, Ordering::Relaxed);
}

/// Return the material-free state that actually reached the live configuration
/// swap for `namespace`.
pub fn published_namespace_state(namespace: &str) -> Option<PublishedGatewayTrustState> {
    PUBLISHED_NAMESPACE_STATES.load().get(namespace).cloned()
}

/// Generation identity for the currently published namespace state.
///
/// The empty-state fingerprint is stable and changes on both a first
/// publication and an explicit revocation, which lets two control-plane
/// replicas compare the complete live state without treating absence as an
/// unknown value.
pub fn published_namespace_generation(namespace: &str) -> String {
    published_namespace_state(namespace)
        .map(|state| state.generation)
        .unwrap_or_else(|| trust_generation_fingerprint(&[]))
}

/// Stable fingerprint of a trust generation.
///
/// Covers exactly the fields that decide what a subscriber will validate with —
/// namespace, id, trust domain, revision, and the canonical encoding of the
/// material — so two control-plane replicas that reconstructed the same
/// committed state produce the same string, and any rotation or revocation
/// produces a different one. Used for configuration identity/equivalence and
/// surfaced on the authenticated status view; it is a digest, so it carries no
/// material.
pub fn trust_generation_fingerprint(records: &[GatewayTrustBundleRecord]) -> String {
    // SHA-2 goes through the FIPS-approved wrapper, never the RustCrypto crate
    // directly (which is dev-only in this workspace).
    use crate::fips::approved::Sha256;

    let mut ordered: Vec<&GatewayTrustBundleRecord> = records.iter().collect();
    ordered.sort_by(|a, b| a.namespace.cmp(&b.namespace).then_with(|| a.id.cmp(&b.id)));

    let mut hasher = Sha256::new();
    for record in ordered {
        hasher.update(record.namespace.as_bytes());
        hasher.update([0]);
        hasher.update(record.id.as_bytes());
        hasher.update([0]);
        hasher.update(record.trust_domain.as_bytes());
        hasher.update([0]);
        hasher.update(record.revision.to_be_bytes());
        hasher.update([0]);
        match serde_json::to_vec(&record.bundle) {
            Ok(encoded) => hasher.update(encoded),
            // A bundle that cannot serialize never passed admission; fold in a
            // distinct marker rather than silently hashing nothing.
            Err(_) => hasher.update(b"unserializable"),
        }
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

/// Record a candidate that was refused before the live swap. The previous valid
/// generation stays active, so the published-generation counter and timestamp
/// are deliberately untouched.
pub fn record_trust_load_rejection(reason: GatewayTrustFailureReason) {
    LOAD_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(reason.code(), Ordering::Relaxed);
}

/// Record a publication that found two authorities and was therefore refused.
///
/// Nothing is withdrawn by this outcome: the projection is
/// [`NamespaceTrustProjection::KeepPrevious`], the side channel is empty, and
/// subscribers retain the last trust generation they accepted. The counter and
/// the bounded failure reason exist precisely so a refusal that changes nothing
/// on the wire is still visible to an operator.
pub fn record_ambiguous_authority() {
    AMBIGUOUS_AUTHORITY_TOTAL.fetch_add(1, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(
        GatewayTrustFailureReason::AmbiguousAuthority.code(),
        Ordering::Relaxed,
    );
}

/// Process-wide, label-free snapshot for `/metrics` and admin status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayTrustObservabilitySnapshot {
    /// Trust generations that reached the live-configuration swap.
    pub published_generations_total: u64,
    pub load_rejections_total: u64,
    pub ambiguous_authority_total: u64,
    /// Unix seconds of the most recently published generation; `0` when none.
    pub last_published_unix_seconds: u64,
    /// Bounded reason for the most recent failure.
    pub last_failure_reason: &'static str,
}

pub fn observability_snapshot() -> GatewayTrustObservabilitySnapshot {
    GatewayTrustObservabilitySnapshot {
        published_generations_total: PUBLISHED_GENERATIONS_TOTAL.load(Ordering::Relaxed),
        load_rejections_total: LOAD_REJECTIONS_TOTAL.load(Ordering::Relaxed),
        ambiguous_authority_total: AMBIGUOUS_AUTHORITY_TOTAL.load(Ordering::Relaxed),
        last_published_unix_seconds: LAST_PUBLISHED_UNIX_SECONDS.load(Ordering::Relaxed),
        last_failure_reason: GatewayTrustFailureReason::from_code(
            LAST_FAILURE_REASON.load(Ordering::Relaxed),
        )
        .as_str(),
    }
}

/// Reset every counter. Test-support only — the production paths are monotonic
/// within a process.
// Test-support by definition; the bin target has no caller.
#[allow(dead_code)]
pub fn reset_observability_for_tests() {
    PUBLISHED_GENERATIONS_TOTAL.store(0, Ordering::Relaxed);
    LOAD_REJECTIONS_TOTAL.store(0, Ordering::Relaxed);
    AMBIGUOUS_AUTHORITY_TOTAL.store(0, Ordering::Relaxed);
    LAST_PUBLISHED_UNIX_SECONDS.store(0, Ordering::Relaxed);
    LAST_FAILURE_REASON.store(0, Ordering::Relaxed);
    PUBLISHED_NAMESPACE_STATES.store(Arc::new(HashMap::new()));
}
