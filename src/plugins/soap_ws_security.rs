//! SOAP WS-Security Plugin
//!
//! Validates WS-Security headers in SOAP envelopes at the proxy layer.
//! Supports UsernameToken authentication (PasswordText and PasswordDigest),
//! X.509 certificate signature verification, SAML assertion validation
//! (XMLDSIG signature verification against trusted IdP signing certificates
//! plus issuer / NotBefore / NotOnOrAfter / Audience checks and an enveloped-
//! signature transform over the assertion), timestamp freshness checks, and
//! nonce replay protection.
//!
//! ## Phases and identity
//!
//! Priority 1500 places this plugin in the AuthN band after HMAC auth. A
//! configuration that establishes a principal — UsernameToken, X.509, or SAML —
//! runs in the **`authenticate`** phase against a body buffered before
//! authentication, and publishes `RequestContext::authenticated_identity` plus a
//! namespace-correct `identified_consumer`. That is what lets `access_control`,
//! consumer-scoped `rate_limiting`, logging, retries, and chargeback all see one
//! authoritative SOAP identity; previously validation ran in `before_proxy`,
//! after both central authentication *and* authorization had already decided,
//! so ACL saw no consumer and consumer rate limits charged the source IP.
//!
//! A timestamp-only policy proves freshness and nothing about the caller. It has
//! no principal to publish, must not join the authentication chain, and keeps
//! validating in `before_proxy`. The two phases are selected by configuration
//! and are mutually exclusive, so a message is never validated twice.
//!
//! Because authentication now precedes the shared buffered-body normalization
//! phase, composing an identity-establishing policy with `compression`'s
//! `decompress_request` is refused at admission (see [`validate_composition`]),
//! and `on_final_request_body_with_context` refuses to dispatch any message
//! whose bytes changed after validation.
//!
//! ## Governed representations
//!
//! Media types are parsed structurally — `type/subtype` plus parameters — never
//! substring-matched. `content_type.mode` defaults to `strict`, under which
//! every request on the proxy is a governed SOAP request and a missing,
//! mislabelled, or unsupported representation is rejected before backend
//! dispatch; `mixed_route` is the explicit opt-out for proxies that serve mixed
//! traffic. SOAP 1.1 (`text/xml`), SOAP 1.2 (`application/soap+xml`),
//! `application/xml`, `application/xop+xml`, and MTOM/XOP `multipart/related`
//! are supported; MTOM validates the root part's envelope and refuses a root
//! part that is mislabelled or re-encoded. Package framing is a strict MIME
//! contract — see [`extract_mtom_root_part`] — because the parser is what
//! decides which bytes are the envelope.
//!
//! An `x509_signature` policy claims *integrity* over the message the backend
//! executes. Ferrum implements no WS-Security attachment-signature transform,
//! so for a XOP representation the digest it verifies covers the `xop:Include`
//! element and not the attachment octets that element stands for. An enabled
//! `x509_signature` therefore refuses both MTOM `multipart/related` and bare
//! `application/xop+xml` with `415`. `username_token` and `saml` keep accepting
//! them: those mechanisms authenticate *who sent the message* and never claimed
//! coverage of attachment octets.
//!
//! `reject_missing_security_header: false` is the opt-out for a governed
//! message that genuinely carries no `wsse:Security` header. It is not an
//! opt-out from *parsing*: once a representation is governed, malformed XML,
//! unsupported or ambiguous envelope structure, and parsing-budget failures
//! reject unconditionally, because a gateway/backend parser disagreement that
//! became a pass-through would skip every check for a message the backend still
//! executes.
//!
//! ## Configuration admission (strict, fail-closed)
//!
//! The root object and every nested fixed-shape object (`timestamp`,
//! `username_token`, each `credentials` entry, `x509_signature`, `saml`,
//! `nonce`) reject unknown keys and wrong-typed values — including explicit
//! JSON `null` — before any default applies. Omission selects the documented
//! default; `{"username_token":{"enabled":null}}`, `{"saml":{"audience":null}}`,
//! `{"nonce":null}`, and similar inputs are errors rather than weaker policy.
//! Silently defaulting a malformed value used to be able to disable
//! UsernameToken/SAML/X.509 policy, drop SAML audience binding, or reset a
//! freshness/replay window while startup, Admin validation, CP/DP propagation,
//! and reload all reported success — the `FailClosed` registration in
//! `src/plugins/mod.rs` never saw an error, so no last-known-good generation
//! was retained. There is no `nonce_replay_protection` alias: `nonce.*` is the
//! only canonical shape and the alias is rejected as an unknown key.
//!
//! Every duration and cache control has an enforced inclusive range. Upper
//! bounds sit far below `chrono::TimeDelta`'s representable range and parsed
//! WS-Security / SAML instants are clamped to a four-digit year, so no admitted
//! configuration and no hostile `Created` / `Expires` / `NotBefore` /
//! `NotOnOrAfter` value can overflow duration or `DateTime` arithmetic and panic
//! a request task. Durations are converted once at admission.
//!
//! ## Nonce replay cache bounds
//!
//! Replay state is bounded on three independent axes — per-nonce encoded
//! length, retained entries, and total retained key payload bytes — and a nonce
//! is only retained *after* its PasswordDigest verifies. The encoded-length
//! ceiling is checked before Base64 decoding. A `BTreeMap` age index makes
//! expiry reclamation O(log n) per examined entry without scanning the lookup
//! map. Each index handle shares the lookup map's one immutable nonce-string
//! allocation.
//!
//! **A claimed nonce is never evicted while it is still inside its retention
//! window.** The only entries capacity maintenance may reclaim are ones proven
//! expired against the fixed [`NONCE_CLAIM_RETENTION_SECONDS`] horizon (see
//! below), so the replay window a client was promised is always honoured —
//! including across a reload to any other admissible generation. When entry or
//! byte capacity is still exhausted after that bounded reclamation, the claim is
//! rejected and the nonce is *not* admitted; replay protection degrades into
//! refusal, never into silent unprotection.
//! Maintenance examines at most `NONCE_MAX_MAINTENANCE_ENTRIES` oldest entries
//! per request, which keeps the work per request constant while the two hard
//! caps keep memory bounded.
//!
//! Entry/byte admission, expiry reclamation, and accounting share one narrow
//! mutex held only for security-state updates so concurrent PasswordDigest
//! claims cannot overshoot either hard cap (including same-key races); length
//! checks and all credential/XML/base64/crypto work stay outside that critical
//! section. Diagnostics use fixed-cardinality failure classes and never include
//! the nonce.
//!
//! ## PasswordDigest freshness, binding, and replay scope
//!
//! A PasswordDigest token carries two independent instants: its own
//! `wsu:Created` (bound into `Base64(SHA-1(nonce + created + password))`) and
//! the outer `wsu:Timestamp/wsu:Created`. Validating only the outer one leaves a
//! captured token digest-valid forever, so an attacker who waits out the replay
//! TTL can resubmit the unchanged UsernameToken beside a freshly minted outer
//! Timestamp. Both are therefore validated, and they are bound to each other:
//! the inner instant has its own bounded freshness window
//! (`username_token.created_max_age_seconds` ± `created_clock_skew_seconds`) and
//! must agree with the outer instant within
//! `username_token.created_max_timestamp_divergence_seconds`. The outer
//! Timestamp is validated on every request in which it appears — not only when
//! `timestamp.require` is set — so the value the inner instant binds to is
//! always an independently validated one, and with
//! `username_token.require_timestamp_binding` (default) the outer element
//! cannot simply be omitted to drop the binding.
//!
//! ## The claim must outlive the token
//!
//! Binding the two instants is necessary but not sufficient. The inner window
//! accepts an unchanged token at any server instant in
//! `[Created - skew, Created + max_age + skew]`, so from the *earliest* moment
//! it can be claimed (submitted `skew` early, which the future tolerance
//! admits) the same bytes stay acceptable for `max_age + 2 * skew` seconds.
//! While `nonce.cache_ttl_seconds` was an independent knob it could be — and by
//! default was — shorter than that: a token claimed at the earliest moment lost
//! its claim after 300s and stayed acceptable for another 600s, which is the
//! "acceptance again after replay TTL" the advisory describes. Binding the
//! outer Timestamp does not help, because a captured token needs no forged
//! element at all once its claim is gone.
//!
//! Coupling retention to *this generation's* window is not enough either, and
//! that is the residual this module closes. Replay state outlives the
//! generation that wrote it, so a claim has to survive every window a *future*
//! admitted generation may open, not only the one in force when it was made.
//! A per-generation retention fails that in both scopes:
//!
//! - **Process.** Once an entry passes the shorter retention it is expired: it
//!   can be reclaimed by capacity maintenance, or re-admitted in place as a
//!   refresh. A later generation that widens `created_max_age_seconds` /
//!   `created_clock_skew_seconds` makes the captured token acceptable again,
//!   and nothing can resurrect the claim that was already dropped. A monotone
//!   high-water mark only helps while a longer generation is concurrently
//!   alive; it cannot protect an entry that is already gone.
//! - **Shared.** `SET NX EX` cannot extend a key it did not create, so keys
//!   written under an old TTL still expire early no matter what a new
//!   generation declares. "Raise the TTL, drain, then widen" is operator
//!   procedure, not enforcement.
//!
//! Retention is therefore **not configurable at all**. Every PasswordDigest
//! nonce claim — process and shared alike — is retained for the fixed global
//! horizon [`NONCE_CLAIM_RETENTION_SECONDS`], which is
//! `MAX_UT_CREATED_MAX_AGE_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS + 1` (93 601 s
//! ≈ 26 h): the widest span over which *any* admissible configuration can ever
//! accept an unchanged token, plus one second for whole-second truncation.
//! Because the horizon is the maximum over the whole admissible schema rather
//! than over the configured values, no later reload — however wide, however
//! long after the old retention would have elapsed — can outlive a claim.
//! There is no rollout ordering to get right, no drain window, and no reliance
//! on an old generation still being alive. `nonce.cache_ttl_seconds` was
//! removed rather than redefined: a key that can no longer shorten retention
//! would only misdescribe the contract.
//!
//! The cost is bounded and paid in capacity, not in security: claims live ~26 h,
//! so `nonce.max_cache_size` / `nonce.max_total_cache_bytes` must be sized for
//! peak authenticated PasswordDigest rate × 93 601 s under `process` scope.
//! Under-provisioning surfaces as fail-closed `401`s (see the eviction rule
//! above), never as a silent replay window; `shared` scope moves that cost into
//! Redis.
//!
//! Replay state itself is scoped by an explicit operator declaration,
//! `nonce.replay_scope`, which has no default because a gateway cannot observe
//! its own replica count:
//!
//! - `process` registers state under a stable `{namespace}|{plugin-config-id}`
//!   key in a process-global registry, so a reload generation inherits the
//!   previous generation's claims instead of starting empty. Every generation
//!   expires entries against the same fixed horizon, so no generation — retired,
//!   narrowed, or widened — can expire, refresh, or under-protect another's
//!   claim. It is explicitly **not** cross-replica protection, and declaring it
//!   asserts a single-replica deployment.
//! - `shared` requires `sync_mode: "redis"` and claims each nonce with one
//!   atomic Redis `SET NX EX`, so exactly one request across all replicas wins a
//!   nonce inside its TTL. Every replica and every generation writes the same
//!   fixed TTL, so `SET NX`'s inability to rewrite an existing key's expiry is
//!   harmless: the key it declines to touch already carries the full horizon.
//!   The Redis key is `SHA-256(nonce)` in hex — never the nonce, which is a
//!   digest input bound to the shared secret and would otherwise reach
//!   `MONITOR`, `SLOWLOG`, and the Redis client's error logs — and the stored
//!   value is a fixed non-secret marker.
//!
//! A shared-backend outage fails closed exactly like local exhaustion. There is
//! no fallback to process-local state: a per-replica fallback would silently
//! reinstate the cross-replica bypass the shared backend exists to close.
//!
//! ## Request body character encoding
//!
//! Matching SOAP media types are buffered as raw bytes
//! (`ctx.request_body_bytes`). Before XML/WS-Security validation the plugin
//! decodes UTF-8 and UTF-16 (LE/BE) deterministically from the BOM and/or
//! `Content-Type` charset, rejects charset/BOM/XML-declaration conflicts and
//! malformed sequences fail-closed, and leaves the original wire bytes
//! unchanged for the backend. BOM-less, charset-less payloads whose leading
//! bytes are unmistakably UTF-16 XML (`3c 00` / `00 3c`) are rejected rather
//! than interpreted as UTF-8. Unsupported XML charsets are rejected with
//! HTTP 415. Encoding diagnostics never log request bodies or credentials.
//!
//! ## XMLDSIG canonicalization (shared by X.509 and SAML signature paths)
//!
//! Both the WS-Security X.509 signature path and the SAML assertion signature
//! path apply Exclusive XML Canonicalization (`xml-exc-c14n#`) to
//! `<SignedInfo>` and to each referenced node before cryptographic verification.
//! `InclusiveNamespaces PrefixList` parameters are honored. Only the
//! enveloped-signature and exclusive-c14n Reference transforms are supported;
//! unknown algorithms and transform chains are rejected rather than falling
//! back to wire-byte hashing.
//!
//! ## Signature ordering and work bounds
//!
//! Both signature paths settle **trust first**: the presented certificate's
//! SHA-256 fingerprint must match configured trust material and
//! `SignatureValue` must verify over the canonicalized `SignedInfo` before a
//! single attacker-selected `<Reference>` is resolved, canonicalized, or
//! digested. Trust is a fixed-size comparison and `SignedInfo` is a small
//! bounded subtree, so an untrusted or forged signature costs constant work no
//! matter how the References are shaped. Duplicate Reference URIs are rejected,
//! the reference ceiling is 8, one bounded id index is built per message instead
//! of one full-envelope scan per Reference, and every canonicalization is
//! charged against an aggregate per-message byte budget derived from the body
//! length.
//!
//! ## Structural binding (namespaces, coverage, XSW)
//!
//! Every structural selection is namespace-qualified and positional: exactly one
//! SOAP `Envelope` in a known envelope namespace, at most one `Header` and
//! exactly one `Body` as its direct children in that same namespace, and exactly
//! one `wsse:Security` header targeting this receiver (absent/`next`/
//! `ultimateReceiver` role) as a direct child of that `Header`. A second
//! namespace-correct `Envelope`/`Header`/`Body` anywhere in the document, or a
//! `wsse:Security` outside the `Header`, is rejected — those are the wrapping
//! shapes that make the gateway and the backend resolve different elements.
//!
//! X.509 success additionally requires a Reference that resolves **uniquely to
//! the backend-visible `Body`**, so a trusted signature over only the Timestamp
//! can no longer authorize a rewritten operation, and a required signed
//! Timestamp rejects a message that carries none (contradictory configuration is
//! refused at admission). Reference ids must be unique under both the
//! entity-decoded DOM view and a raw start-tag scan covering the broader id
//! spellings (`wsu:Id`, prefixed `Id`, bare `Id`, `xml:id`, `ID`, `id`) a
//! tolerant backend might resolve. The SAML path requires a single
//! `<Assertion>` inside the Security header and exactly one Reference targeting
//! its own id.
//!
//! ## SAML bearer semantics
//!
//! A signed assertion is a reusable bearer value whose outer WS-Security
//! Timestamp is not covered by its signature. Accepting one therefore requires a
//! mandatory bounded `Conditions` window, the configured service `Audience`, a
//! supported `SubjectConfirmation` naming the configured `Recipient` with its
//! own bounded `NotOnOrAfter`, and a single-use claim on the assertion id in the
//! declared `nonce.replay_scope` — `process` (single-replica by declaration) or
//! `shared` (atomic Redis `SET NX EX` across replicas). `OneTimeUse` needs no
//! special case because every accepted assertion is claimed exactly once.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Datelike, Utc};
use ring::digest;
use ring::signature as ring_sig;
use roxmltree::{Document, Node, NodeId, ParsingOptions};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;
use tracing::{debug, warn};
use x509_parser::prelude::*;

use crate::tls::source::{CertSource, MaterialKind, SecretString, load_material_blocking};
use crate::util::unknown_keys::reject_unknown_keys;

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_attempt::AuthenticationAttempt;
use super::utils::auth_flow;
use super::utils::auth_flow::constant_time_eq;
use super::utils::cert_hash::sha256_hex_lower;
use super::utils::http_client::PluginHttpClient;
use super::utils::redis_rate_limiter::{
    REDIS_PLUGIN_CONFIG_KEYS, RedisConfig, RedisRateLimitClient,
};
use super::{Plugin, PluginResult, RequestContext};

// ── Namespace URIs ──────────────────────────────────────────────────────────

const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const PASSWORD_TEXT_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const XMLDSIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const XMLDSIG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const XMLDSIG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLDSIG_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const XMLDSIG_ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const XML_EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const WSU_NAMESPACE_URI: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const WSSE_NAMESPACE_URI: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const XMLDSIG_NAMESPACE_URI: &str = "http://www.w3.org/2000/09/xmldsig#";
const SOAP11_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12_ENVELOPE_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
const SOAP11_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
const SOAP12_ROLE_NEXT: &str = "http://www.w3.org/2003/05/soap-envelope/role/next";
const SOAP12_ROLE_ULTIMATE_RECEIVER: &str =
    "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver";
const SAML2_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML2_CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const SAML2_CM_HOLDER_OF_KEY: &str = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

/// Upper bound on the number of `<Reference>` elements processed in a single
/// `<SignedInfo>`.
///
/// References are only resolved *after* the certificate is trusted and
/// `SignatureValue` verifies over `SignedInfo`, so this no longer bounds
/// unauthenticated work — but it still bounds authenticated work, and the
/// profiles Ferrum supports (Timestamp + Body + a small number of headers)
/// never approach it. The previous ceiling of 64 was chosen when references
/// were resolved before authentication and was the multiplier in the
/// `O(references × body)` amplification GHSA-9g4v-h9hm-846r describes.
const MAX_SIGNED_REFERENCES: usize = 8;

/// Bounds for attacker-controlled XML work before signature trust exists.
/// Legitimate SOAP and SAML signatures stay far below these ceilings.
const MAX_XML_NODES: u32 = 65_536;
const MAX_CANONICALIZATION_DEPTH: usize = 256;
const MAX_INCLUSIVE_NAMESPACE_PREFIXES: usize = 64;
const MAX_INCLUSIVE_PREFIX_LIST_BYTES: usize = 4_096;

/// Floor for the per-request canonicalization work budget (see
/// [`WorkBudget::for_envelope`]). Small envelopes still get enough room to
/// canonicalize `SignedInfo` plus the elements a real signature covers.
const MIN_CANONICALIZATION_BUDGET_BYTES: usize = 65_536;

/// Aggregate canonicalized/scanned-byte budget multiplier, applied to the
/// decoded envelope length. Every `exclusive_canonicalize` call charges both
/// the source subtree it walks and the canonical bytes it emits, so one request
/// can never drive more than a small constant multiple of its own body through
/// canonicalization regardless of how its References are shaped.
const CANONICALIZATION_BUDGET_MULTIPLIER: usize = 2;

/// Bounds for MTOM/XOP (`multipart/related`) unpacking. The gateway only ever
/// walks part *headers* looking for the SOAP root part; attachment payloads are
/// skipped, never decoded, and never validated as XML.
const MAX_MULTIPART_PARTS: usize = 64;
const MAX_MULTIPART_PART_HEADER_BYTES: usize = 8_192;
const MAX_MULTIPART_BOUNDARY_BYTES: usize = 70;
/// Header lines admitted per MIME part. A part header block is bounded by both
/// this count and [`MAX_MULTIPART_PART_HEADER_BYTES`] so neither a few enormous
/// lines nor very many tiny ones can drive unbounded work.
const MAX_MULTIPART_PART_HEADERS: usize = 32;
/// Delimiter-line candidates examined across one package. Every candidate that
/// is rejected as payload advances the scan by at least `2 + boundary.len()`
/// bytes, so this is a belt-and-braces ceiling on an adversarial package that
/// embeds boundary-shaped bytes throughout its attachments.
const MAX_MULTIPART_DELIMITER_CANDIDATES: usize = 4_096;

// ── Configuration admission bounds ──────────────────────────────────────────

/// Inclusive bounds for every operator-supplied duration and cache control.
///
/// Upper bounds sit far below `chrono::TimeDelta`'s `i64::MAX / 1000` second
/// ceiling, so no admitted configuration can make duration construction or
/// `DateTime` arithmetic overflow on the request path. Lower bounds reject the
/// degenerate values that silently disable a defense (a zero freshness window
/// or a zero-entry replay cache).
const MIN_TIMESTAMP_MAX_AGE_SECONDS: u64 = 1;
const MAX_TIMESTAMP_MAX_AGE_SECONDS: u64 = 86_400;
/// Zero skew is allowed: it is strictly *stricter* than the default, unlike a
/// zero freshness window which would accept nothing or a zero cache which
/// would accept every replay.
const MIN_CLOCK_SKEW_SECONDS: u64 = 0;
const MAX_CLOCK_SKEW_SECONDS: u64 = 3_600;
/// Fixed retention for every PasswordDigest nonce claim, in seconds, on both
/// the process and the shared (Redis) path. 93 601 s ≈ 26 h.
///
/// This is the **global maximum admissible acceptance horizon**: the widest
/// span over which any configuration the schema admits can accept an unchanged
/// UsernameToken, computed from the schema ceilings rather than from the values
/// one generation happens to have configured, plus one second so the exact
/// boundary instant is still inside the claim under whole-second truncation.
///
/// It is deliberately not operator-tunable and not derived per generation.
/// Replay state outlives the generation that wrote it, and a later admitted
/// generation may widen `created_max_age_seconds` / `created_clock_skew_seconds`
/// *after* a shorter per-generation retention has already elapsed — at which
/// point the claim is gone and cannot be resurrected in either scope (a process
/// entry may already have been reclaimed or refreshed; a Redis key's TTL cannot
/// be extended by the `SET NX` that finds it present). Retaining every claim
/// for the schema-wide maximum removes the ordering dependency entirely: no
/// admissible future window can outlive a claim, so no reload sequence can
/// reopen the replay window. The price is bounded — see
/// [`MAX_NONCE_MAX_CACHE_SIZE`] and the sizing note in `docs/plugins.md`.
const NONCE_CLAIM_RETENTION_SECONDS: u64 =
    MAX_UT_CREATED_MAX_AGE_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS + 1;

/// The fixed horizon must dominate [`minimum_replay_retention_seconds`] for
/// every configuration the schema admits. Both factors are schema ceilings, so
/// this is provable at compile time rather than asserted in prose.
const _: () = assert!(
    NONCE_CLAIM_RETENTION_SECONDS > MAX_UT_CREATED_MAX_AGE_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS
);

/// The same fixed horizon retains SAML assertion-id claims. An assertion is
/// acceptable at server time `t` only while
/// `NotBefore - skew <= t <= NotOnOrAfter + skew`, and admission caps
/// `NotOnOrAfter - NotBefore` at `max_assertion_lifetime_seconds`, so the widest
/// span any admissible SAML policy can accept one unchanged assertion over is
/// `MAX_SAML_ASSERTION_LIFETIME_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS`. Proving
/// dominance here means no reload — however wide — can reopen an assertion
/// replay window, exactly as for PasswordDigest nonces.
const _: () = assert!(
    NONCE_CLAIM_RETENTION_SECONDS
        > MAX_SAML_ASSERTION_LIFETIME_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS
);

/// Bounds for the SAML assertion validity window (`NotOnOrAfter - NotBefore`).
///
/// GHSA-f44p-hfqr-cvcc: an assertion with absent or unbounded `Conditions` is
/// an indefinite bearer credential. Both instants are now mandatory and their
/// span is capped, so a captured assertion has a provably short life even
/// before assertion-id replay protection is consulted.
const DEFAULT_SAML_ASSERTION_LIFETIME_SECONDS: u64 = 300;
const MIN_SAML_ASSERTION_LIFETIME_SECONDS: u64 = 1;
const MAX_SAML_ASSERTION_LIFETIME_SECONDS: u64 = 86_400;

/// Default retained-entry ceiling for `replay_scope: process`.
///
/// Claims live for the fixed [`NONCE_CLAIM_RETENTION_SECONDS`] horizon, so the
/// steady-state entry count is (peak authenticated PasswordDigest rate) ×
/// 93 601 s, not × a few minutes. The default is sized so an ordinary
/// PasswordDigest workload does not run into the fail-closed saturation
/// rejection; it is a *ceiling*, and the maps start empty and grow with real
/// traffic, so a deployment that never uses PasswordDigest pays nothing for it.
const DEFAULT_NONCE_MAX_CACHE_SIZE: u64 = 100_000;
const MIN_NONCE_MAX_CACHE_SIZE: u64 = 1;
const MAX_NONCE_MAX_CACHE_SIZE: u64 = 1_000_000;

/// Bounds for the UsernameToken `wsu:Created` freshness window.
///
/// This is the *inner* token instant that is bound into the PasswordDigest
/// (`Base64(SHA-1(nonce + created + password))`). It is a distinct value from
/// the outer `wsu:Timestamp/wsu:Created`, so it needs its own bounded window:
/// without one, a captured UsernameToken stays digest-valid forever and only
/// the replay cache's TTL limits how long it can be resubmitted alongside a
/// freshly generated outer Timestamp. Zero is rejected for the same reason it
/// is rejected for the outer window — it would accept nothing or, read the
/// other way, configure no window at all.
const DEFAULT_UT_CREATED_MAX_AGE_SECONDS: u64 = 300;
const MIN_UT_CREATED_MAX_AGE_SECONDS: u64 = 1;
const MAX_UT_CREATED_MAX_AGE_SECONDS: u64 = 86_400;
const DEFAULT_UT_CREATED_CLOCK_SKEW_SECONDS: u64 = 300;

/// Maximum permitted divergence between the UsernameToken `Created` and the
/// independently validated outer `wsu:Timestamp/wsu:Created`.
///
/// This is the binding that makes the two instants one coherent claim: an
/// attacker who mints a fresh outer Timestamp for a captured UsernameToken now
/// has to move the inner instant too, which invalidates the captured digest.
/// Zero is permitted (strictly stricter — the two instants must be identical).
const DEFAULT_UT_TIMESTAMP_DIVERGENCE_SECONDS: u64 = 60;
const MIN_UT_TIMESTAMP_DIVERGENCE_SECONDS: u64 = 0;
const MAX_UT_TIMESTAMP_DIVERGENCE_SECONDS: u64 = 3_600;

/// Upper bound on distinct process-global replay scopes retained for the life of
/// the process. Scope keys are stable `{namespace}|{plugin-config-id}` pairs, so
/// reload generations reuse an existing scope and only genuine plugin-config
/// churn adds one. The cap keeps an unbounded operator-driven key space from
/// becoming a retention leak; exceeding it fails plugin admission closed rather
/// than silently dropping replay history.
const MAX_NONCE_REPLAY_SCOPES: usize = 1_024;

/// Fixed, non-secret record written by a shared (Redis) nonce claim.
///
/// The value carries no credential material: the claim is proven by the key's
/// existence, and the key itself is a SHA-256 digest of the nonce so neither the
/// nonce nor anything derived from the shared secret can reach a Redis keyspace,
/// a `MONITOR` stream, or the Redis client's error logging.
const SHARED_NONCE_CLAIM_RECORD: &[u8] = b"ferrum-edge/soap-ws-security/nonce-claim/v1";

/// Client-visible replay rejections. Fixed strings: the nonce and the assertion
/// id are credential-adjacent values and are never echoed.
const REPLAY_DETECTED_MESSAGE: &str = "WS-Security: nonce replay detected";
const SAML_REPLAY_DETECTED_MESSAGE: &str = "WS-Security: SAML assertion has already been used";

/// Claim-kind prefixes for the one process-global replay map. PasswordDigest
/// nonces are attacker-chosen strings and SAML claim keys are SHA-256 hex, so
/// namespacing them keeps a chosen nonce from ever burning an assertion claim
/// (or the reverse).
const NONCE_PROCESS_CLAIM_PREFIX: &str = "n|";
const SAML_PROCESS_CLAIM_PREFIX: &str = "s|";

/// Byte width of a process claim-kind prefix. Both prefixes are the same width,
/// asserted at compile time, so retained-byte accounting can charge exactly the
/// claim payload without carrying the prefix kind alongside every key.
const PROCESS_CLAIM_PREFIX_BYTES: usize = NONCE_PROCESS_CLAIM_PREFIX.len();
const _: () = assert!(SAML_PROCESS_CLAIM_PREFIX.len() == PROCESS_CLAIM_PREFIX_BYTES);

fn nonce_process_claim_key(nonce: &str) -> String {
    let mut key = String::with_capacity(nonce.len() + PROCESS_CLAIM_PREFIX_BYTES);
    key.push_str(NONCE_PROCESS_CLAIM_PREFIX);
    key.push_str(nonce);
    key
}

fn saml_process_claim_key(claim_digest: &str) -> String {
    let mut key = String::with_capacity(claim_digest.len() + PROCESS_CLAIM_PREFIX_BYTES);
    key.push_str(SAML_PROCESS_CLAIM_PREFIX);
    key.push_str(claim_digest);
    key
}

/// Bytes one retained claim key charges against `nonce.max_total_cache_bytes`.
///
/// The claim-kind prefix is gateway-internal namespacing and is deliberately
/// **not** charged. `max_total_cache_bytes` is documented as the retained nonce
/// payload; `max_encoded_length` may legitimately equal it (both admit 4096),
/// and charging the prefix would make a maximum-length nonce permanently
/// unadmissible even against a completely empty cache — a saturation answer to
/// a request that carries no replay at all, and a violation of the
/// `max_encoded_length <= max_total_cache_bytes` invariant
/// [`SoapWsSecurity::reclaim_expired_nonce_room_locked`] relies on to tell
/// genuine saturation from impossible index drift. Map/tree node and `Arc`
/// control-block overhead is likewise uncharged, so this stays consistent with
/// what the cap has always measured.
fn charged_claim_key_bytes(claim_key: &str) -> usize {
    claim_key.len().saturating_sub(PROCESS_CLAIM_PREFIX_BYTES)
}

/// WS-Security UsernameToken Profile nonces are short random values (16–32 raw
/// bytes is typical). The ceiling is enforced on the *encoded* value before
/// Base64 decoding, so an oversized nonce is never decoded or retained.
const DEFAULT_NONCE_MAX_ENCODED_LENGTH: u64 = 512;
const MIN_NONCE_MAX_ENCODED_LENGTH: u64 = 16;
const MAX_NONCE_MAX_ENCODED_LENGTH: u64 = 4_096;

/// Total retained nonce-key UTF-8 payload bytes, counted once per logical
/// nonce's shared immutable string allocation. The cache is bounded in bytes
/// as well as in entries so `max_cache_size` cannot be multiplied by the
/// per-nonce length to reach an arbitrary retained footprint. The default
/// tracks [`DEFAULT_NONCE_MAX_CACHE_SIZE`] over the fixed retention horizon;
/// deployments using unusually long nonces must raise both together.
const DEFAULT_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 4_096;
const MAX_NONCE_MAX_TOTAL_CACHE_BYTES: u64 = 1024 * 1024 * 1024;

/// Hard ceiling on exact oldest-index entries reclaimed by one request,
/// independent of `max_cache_size`. Only entries proven older than the
/// fixed claim-retention horizon are ever reclaimed; each costs O(log n)
/// tree/map work. When this budget is spent without freeing room the request
/// fails closed rather than reaching for a live entry.
const NONCE_MAX_MAINTENANCE_ENTRIES: usize = 64;

/// Representable-year window for parsed WS-Security / SAML instants.
///
/// `chrono`'s `%Y` accepts years far outside the four-digit range, and its
/// `DateTime` `Add`/`Sub` impls panic on overflow. Clamping attacker-supplied
/// instants at parse time keeps every later `instant ± skew` and instant
/// difference inside range without scattering checked arithmetic through the
/// validation paths. `xsd:dateTime` values outside this window have no
/// legitimate WS-Security use.
const MIN_PARSED_YEAR: i32 = 1970;
const MAX_PARSED_YEAR: i32 = 9999;

// ── Allowed configuration keys (exhaustive, per fixed-shape object) ─────────

const OWN_ROOT_CONFIG_KEYS: &[&str] = &[
    "reject_missing_security_header",
    "content_type",
    "timestamp",
    "username_token",
    "x509_signature",
    "saml",
    "nonce",
];

/// Root allowlist = this plugin's own keys ∪ the shared Redis connectivity keys.
///
/// `RedisConfig::from_plugin_config` deliberately does not reject unknown root
/// keys, so a plugin that closes its own root must union these in or a
/// misspelled `redis_ur1` would be an unknown-key rejection while a misspelled
/// `sync_mode` would silently select process-local replay state.
static ROOT_CONFIG_KEYS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut keys = Vec::with_capacity(OWN_ROOT_CONFIG_KEYS.len() + REDIS_PLUGIN_CONFIG_KEYS.len());
    keys.extend_from_slice(OWN_ROOT_CONFIG_KEYS);
    keys.extend_from_slice(REDIS_PLUGIN_CONFIG_KEYS);
    keys
});
const TIMESTAMP_CONFIG_KEYS: &[&str] = &[
    "require",
    "max_age_seconds",
    "require_expires",
    "clock_skew_seconds",
];
const USERNAME_TOKEN_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "password_type",
    "credentials",
    "created_max_age_seconds",
    "created_clock_skew_seconds",
    "created_max_timestamp_divergence_seconds",
    "require_timestamp_binding",
];
const CREDENTIAL_CONFIG_KEYS: &[&str] = &["username", "password"];
const CONTENT_TYPE_CONFIG_KEYS: &[&str] = &["mode", "allow_mtom"];
const X509_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "trusted_certs",
    "allowed_algorithms",
    "allowed_digest_algorithms",
    "require_signed_timestamp",
];
const SAML_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "trusted_issuers",
    "trusted_signing_certs",
    "allowed_signature_algorithms",
    "allowed_digest_algorithms",
    "audience",
    "recipient",
    "max_assertion_lifetime_seconds",
    "allowed_subject_confirmation_methods",
    "clock_skew_seconds",
];
// `cache_ttl_seconds` is deliberately absent: claim retention is the fixed
// `NONCE_CLAIM_RETENTION_SECONDS` horizon and no operator value can shorten it,
// so the key is rejected as unknown rather than accepted and ignored.
const NONCE_CONFIG_KEYS: &[&str] = &[
    "replay_scope",
    "max_cache_size",
    "max_encoded_length",
    "max_total_cache_bytes",
];

/// UTF-16→UTF-8 size is bounded by construction for well-formed input: each
/// BMP code point uses 2 wire bytes and at most 3 UTF-8 bytes (≤ 3/2×), and
/// supplementary planes use a surrogate pair (4 wire bytes → 4 UTF-8 bytes).
/// UTF-8→UTF-8 is 1:1. A post-decode `len * 3/2` cap is therefore unreachable
/// and is omitted; odd-length / invalid-surrogate sequences fail closed during
/// incremental decoding instead.

// ── Config types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordType {
    PasswordText,
    PasswordDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    RsaSha256,
    RsaSha1,
}

/// XMLDSIG digest algorithm used for `<Reference>` element hashing.
///
/// Tracked separately from `SignatureAlgorithm` so the config surface can
/// gate signature vs digest algorithms independently — overloading a single
/// "algorithms" knob to mean both signature method and reference digest is
/// confusing for operators and produces footguns (e.g. accepting SHA-1
/// digests just because rsa-sha1 is in the allow list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha1,
}

// ── Strict cold-path configuration accessors ───────────────────────────────
//
// Every fixed-shape SOAP security object is checked for unknown keys and exact
// value types *before* defaults apply. A misspelled key or a wrong-typed value
// must fail admission — silently falling back to a default is how a
// string-valued `username_token.enabled` used to disable credential
// authentication while startup, Admin validation, CP/DP propagation, and reload
// all reported success. Omission selects the documented default; an explicit
// JSON `null` is rejected so it cannot silently apply the same weaker policy.

type ConfigObject = serde_json::Map<String, Value>;

/// Present value for `key`. Omission yields `None`. Explicit JSON `null` is an
/// error so it cannot silently apply the same default as a missing field.
fn present<'a>(
    object: Option<&'a ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<&'a Value>, String> {
    match object.and_then(|map| map.get(key)) {
        None => Ok(None),
        Some(Value::Null) => Err(null_error(path, key)),
        Some(value) => Ok(Some(value)),
    }
}

/// Uniform type-mismatch diagnostic for a fixed-shape configuration field.
fn type_error(path: &str, key: &str, expected: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' must be {expected}")
}

fn null_error(path: &str, key: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' must not be null; omit the field to use the default")
}

fn range_error(path: &str, key: &str, min: u64, max: u64) -> String {
    format!("soap_ws_security: '{path}.{key}' must be an integer {min}..={max}")
}

fn required_error(path: &str, key: &str) -> String {
    format!("soap_ws_security: '{path}.{key}' is required")
}

fn duplicate_error(path: &str) -> String {
    format!("soap_ws_security: '{path}.username' duplicates an earlier entry")
}

fn enum_error(path: &str, key: &str, allowed: &str) -> String {
    format!(
        "soap_ws_security: '{path}.{key}' contains an unsupported value; accepted values: {allowed}"
    )
}

fn allowed_values<T>(variants: &[(&str, T)]) -> String {
    let names: Vec<&str> = variants.iter().map(|(name, _)| *name).collect();
    names.join(", ")
}

/// Nested object at `key`, rejecting any non-object present value (including null).
fn soap_object<'a>(
    object: Option<&'a ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<&'a ConfigObject>, String> {
    match present(object, path, key)? {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(type_error(path, key, "an object")),
    }
}

fn soap_bool(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match present(object, path, key)? {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(type_error(path, key, "a boolean, not a string or number")),
    }
}

/// Unsigned integer within an inclusive range. Rejects non-integers, negatives,
/// fractional numbers, and out-of-range values so no admitted value can
/// overflow duration arithmetic or disable a bound.
fn soap_u64_bounded(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    let value = match present(object, path, key)? {
        None => return Ok(default),
        Some(value) => value,
    };
    let Some(parsed) = value.as_u64() else {
        return Err(range_error(path, key, min, max));
    };
    if parsed < min || parsed > max {
        return Err(range_error(path, key, min, max));
    }
    Ok(parsed)
}

/// Non-empty string, rejecting any non-string present value.
fn soap_string(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<String>, String> {
    match present(object, path, key)? {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(type_error(path, key, "a non-empty string")),
        Some(_) => Err(type_error(path, key, "a string")),
    }
}

/// Array of non-empty strings. Malformed entries are rejected instead of
/// silently dropped, so a partially-bad cert / issuer list cannot narrow the
/// trust set while reporting success.
fn soap_string_array(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    let value = match present(object, path, key)? {
        None => return Ok(None),
        Some(value) => value,
    };
    let Some(array) = value.as_array() else {
        return Err(type_error(path, key, "an array of strings"));
    };
    let mut parsed = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        match entry.as_str() {
            Some(text) if !text.trim().is_empty() => parsed.push(text.to_string()),
            _ => {
                let indexed = format!("{key}[{index}]");
                return Err(type_error(path, &indexed, "a non-empty string"));
            }
        }
    }
    Ok(Some(parsed))
}

/// Enum-valued array with an explicit default. Unknown members are rejected —
/// dropping them used to be able to empty an allow-list or narrow it in ways
/// the operator never asked for.
fn soap_enum_array<T: Copy>(
    object: Option<&ConfigObject>,
    path: &str,
    key: &str,
    variants: &[(&str, T)],
    default: &[T],
) -> Result<Vec<T>, String> {
    let Some(entries) = soap_string_array(object, path, key)? else {
        return Ok(default.to_vec());
    };
    if entries.is_empty() {
        let allowed = allowed_values(variants);
        let expected = format!("a non-empty subset of: {allowed}");
        return Err(type_error(path, key, &expected));
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in &entries {
        let matched = variants
            .iter()
            .find(|(name, _)| *name == entry.as_str())
            .map(|(_, variant)| *variant);
        let Some(matched) = matched else {
            let allowed = allowed_values(variants);
            return Err(enum_error(path, key, &allowed));
        };
        parsed.push(matched);
    }
    Ok(parsed)
}

/// Saturating `u64` → `usize`. Every ceiling in this module fits `u32`, so this
/// cannot narrow on any supported target; saturating keeps the conversion
/// panic-free without an `unwrap`.
fn usize_or_max(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

const SIGNATURE_ALGORITHM_VARIANTS: &[(&str, SignatureAlgorithm)] = &[
    ("rsa-sha256", SignatureAlgorithm::RsaSha256),
    ("rsa-sha1", SignatureAlgorithm::RsaSha1),
];
const DIGEST_ALGORITHM_VARIANTS: &[(&str, DigestAlgorithm)] = &[
    ("sha256", DigestAlgorithm::Sha256),
    ("sha1", DigestAlgorithm::Sha1),
];

/// Reject unknown keys on a fixed-shape object with the shared path-qualified
/// diagnostics (including spelling suggestions).
fn reject_unknown(
    object: Option<&ConfigObject>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let Some(map) = object else {
        return Ok(());
    };
    reject_unknown_keys(map, path, allowed, "soap_ws_security: ")
}

/// Configured duration, converted once at admission so the request path never
/// performs a fallible or panicking duration construction. The bounds above
/// already guarantee success; the fallible conversion stays so a future bound
/// change cannot reintroduce a panicking `Duration::seconds` on the hot path.
fn admitted_duration(path: &str, key: &str, seconds: u64) -> Result<chrono::Duration, String> {
    let signed = i64::try_from(seconds).ok();
    let duration = signed.and_then(chrono::Duration::try_seconds);
    let message = || type_error(path, key, "a representable duration");
    duration.ok_or_else(message)
}

fn sha256_array(value: &[u8]) -> [u8; 32] {
    let hashed = digest::digest(&digest::SHA256, value);
    let mut output = [0u8; 32];
    output.copy_from_slice(hashed.as_ref());
    output
}

#[derive(Debug, Clone)]
struct Credential {
    username: String,
    password: String,
    /// Fixed-width digest used by PasswordText verification so known and
    /// unknown principals take the same comparison path even when configured
    /// secret lengths differ from the process-local dummy material.
    password_text_hash: [u8; 32],
}

/// UsernameToken authentication outcomes that must not create a username oracle.
///
/// Structural token/policy failures remain distinguishable because they do not
/// depend on whether the supplied principal exists. Credential failures
/// (unknown user, wrong PasswordText, wrong PasswordDigest) share one public
/// body and one stable telemetry class.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UsernameTokenError {
    Structural(String),
    InvalidCredentials,
}

impl UsernameTokenError {
    /// Stable operational failure class for credential rejection (no username).
    const INVALID_CREDENTIALS_CLASS: &'static str = "username_token_invalid_credentials";
    /// Stable structural failure class for malformed / policy-mismatch tokens.
    const STRUCTURAL_CLASS: &'static str = "username_token_structural";
    /// Client-visible JSON body shared by every invalid-credential outcome.
    const INVALID_CREDENTIALS_BODY: &'static str =
        r#"{"error":"WS-Security: invalid credentials"}"#;
}

struct TrustedCert {
    /// DER-encoded public key bytes for signature verification.
    public_key_der: Vec<u8>,
    /// SHA-256 fingerprint of the full DER-encoded certificate (for matching).
    fingerprint: Vec<u8>,
    /// Stable request principal published when this certificate signs a
    /// message: `x509:sha256:<lowercase-hex-fingerprint>`.
    ///
    /// Derived at admission from operator-supplied trust material, so it is
    /// bounded, allocation-free at request time, and carries no attacker-
    /// controlled or personally identifying value. Operators map it to a
    /// Consumer by registering that string as the Consumer's username/id.
    principal: String,
}

// ── Nonce cache entry ───────────────────────────────────────────────────────

type NonceAgeKey = (Instant, u64);

struct NonceEntry {
    age_key: NonceAgeKey,
}

/// PasswordDigest replay security state.
///
/// `cache` provides expected O(1) same-nonce decisions. `age_index` provides
/// O(log n) expiration and exact-oldest selection without a full-cache scan.
/// Both containers hold `Arc` handles to the same immutable nonce allocation;
/// `retained_key_bytes` counts that allocation's UTF-8 payload exactly once per
/// logical entry via [`charged_claim_key_bytes`] — the claim payload only, never
/// the internal claim-kind prefix, and never map/tree node or `Arc`
/// control-block overhead.
///
/// Entry count, age order, and retained key bytes are updated under one mutex
/// so concurrent admissions cannot overshoot either documented hard cap.
/// Checked arithmetic and structural cross-checks turn impossible drift into a
/// fail-closed outcome rather than hiding it with saturating repair.
///
/// Entries are expired against the fixed [`NONCE_CLAIM_RETENTION_SECONDS`]
/// horizon — never against a per-generation value. Replay state is
/// process-global and shared across reload generations, so a retention derived
/// from the calling generation would let a retired or freshly narrowed
/// generation expire (or refresh, which is worse) a claim another generation
/// made, and would leave a claim that already elapsed unable to cover a *later*
/// generation's widened acceptance window. A single schema-wide constant makes
/// every generation, past and future, agree by construction, with no state to
/// carry and nothing to resurrect.
struct NonceReplayState {
    cache: HashMap<Arc<str>, NonceEntry>,
    age_index: BTreeMap<NonceAgeKey, Arc<str>>,
    retained_key_bytes: usize,
    next_sequence: u64,
    last_expired_removals: usize,
}

impl NonceReplayState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            age_index: BTreeMap::new(),
            retained_key_bytes: 0,
            next_sequence: 0,
            last_expired_removals: 0,
        }
    }

    fn has_capacity(&self, incoming_bytes: usize, max_entries: usize, max_bytes: usize) -> bool {
        if self.cache.len() >= max_entries {
            return false;
        }
        self.retained_key_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|total| total <= max_bytes)
    }

    fn structurally_consistent(&self) -> bool {
        self.cache.len() == self.age_index.len()
            && (!self.cache.is_empty() || self.retained_key_bytes == 0)
    }

    /// Full cold-path proof that the ordered index and lookup map describe the
    /// same claims and byte accounting. Request admission intentionally uses
    /// the O(1) [`Self::structurally_consistent`] guard; retired-scope
    /// reclamation may afford this O(n) scan before it discards replay state.
    fn fully_structurally_consistent(&self) -> bool {
        if !self.structurally_consistent() {
            return false;
        }
        let mut retained_key_bytes = 0usize;
        for (age_key, nonce) in &self.age_index {
            if !self.age_entry_matches(age_key, nonce) {
                return false;
            }
            let Some(total) = retained_key_bytes.checked_add(charged_claim_key_bytes(nonce)) else {
                return false;
            };
            retained_key_bytes = total;
        }
        retained_key_bytes == self.retained_key_bytes
    }

    fn allocate_age_key(&mut self, now: Instant) -> Option<NonceAgeKey> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.checked_add(1)?;
        Some((now, sequence))
    }

    fn age_entry_matches(&self, age_key: &NonceAgeKey, nonce: &Arc<str>) -> bool {
        self.cache
            .get(nonce.as_ref())
            .is_some_and(|entry| entry.age_key == *age_key)
    }

    fn remove_age_entry(&mut self, age_key: &NonceAgeKey) -> Result<(), ()> {
        let Some(nonce) = self.age_index.get(age_key) else {
            return Err(());
        };
        if !self.age_entry_matches(age_key, nonce) {
            return Err(());
        }
        let Some(retained_key_bytes) = self
            .retained_key_bytes
            .checked_sub(charged_claim_key_bytes(nonce))
        else {
            return Err(());
        };

        let nonce = match self.age_index.remove(age_key) {
            Some(nonce) => nonce,
            None => return Err(()),
        };
        if self.cache.remove(nonce.as_ref()).is_none() {
            return Err(());
        }
        self.retained_key_bytes = retained_key_bytes;
        Ok(())
    }
}

// ── Replay retention contract ───────────────────────────────────────────────

/// Shortest replay retention that provably outlives an accepted PasswordDigest
/// token, in seconds, for a `created_max_age_seconds` / `created_clock_skew_seconds`
/// pair.
///
/// A PasswordDigest token's only self-contained instant is its own `wsu:Created`
/// (`C`), which is bound into the digest. `validate_username_token_created`
/// accepts the token at server time `t` exactly while
///
/// ```text
/// C - skew  <=  t  <=  C + max_age + skew
/// ```
///
/// The *earliest* moment a claim can be made is therefore `t0 = C - skew`
/// (future-skew acceptance — the token is submitted before its own `Created`
/// instant), and the *latest* moment the same unchanged token is still accepted
/// is `C + max_age + skew`. The longest span a claim must cover is the
/// difference:
///
/// ```text
/// (C + max_age + skew) - (C - skew) = max_age + 2 * skew
/// ```
///
/// Retaining for `max_age + 2 * skew + 1` seconds makes the claim strictly
/// outlive the token from *any* admissible claim instant, not only from the
/// earliest one: a claim at `t0` covers `[t0, t0 + max_age + 2*skew + 1)`, and
/// every later claim only shifts that interval forward while the token's
/// remaining life shrinks by the same amount. The `+ 1` absorbs the whole-second
/// truncation used by the process-local age comparison, so the exact boundary
/// instant is still inside the claim and boundary + 1 is outside acceptance.
///
/// This is the requirement of *one* generation. It is **not** what claims are
/// actually retained for: a claim must also survive every window a later
/// admitted generation may open, which is why retention is the schema-wide
/// [`NONCE_CLAIM_RETENTION_SECONDS`] — this function evaluated at the schema
/// ceilings. Admission still computes the per-policy value and refuses any
/// policy the fixed horizon would not cover, so the dominance relation is
/// enforced rather than merely documented (unreachable for admitted inputs,
/// which are bounded by the same ceilings, but not assumed).
///
/// Returns `None` on arithmetic overflow, which fails admission closed. Admitted
/// inputs are bounded well below that, so `None` is unreachable for any admitted
/// configuration; it is not assumed.
fn minimum_replay_retention_seconds(created_max_age: u64, created_clock_skew: u64) -> Option<u64> {
    created_clock_skew
        .checked_mul(2)
        .and_then(|skew_span| created_max_age.checked_add(skew_span))
        .and_then(|span| span.checked_add(1))
}

// ── Replay-state scope and backend ──────────────────────────────────────────

/// Operator-declared deployment scope for PasswordDigest replay state.
///
/// There is no default. A gateway cannot observe how many replicas are running,
/// so the scope is an explicit, auditable declaration: choosing `Process` is the
/// operator asserting a single-replica deployment, and choosing `Shared` is the
/// operator pointing replay state at a backend every replica can reach. Silently
/// defaulting to process-local state is exactly the posture that let a captured
/// UsernameToken be accepted once per replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceReplayScope {
    Process,
    Shared,
}

/// Where a PasswordDigest nonce claim is made.
///
/// `Process` state is registered against a stable `{namespace}|{config-id}` key
/// so a reload generation reuses the previous generation's claims instead of
/// starting from an empty cache. `Shared` state lives in Redis and is claimed
/// with one atomic `SET NX EX`, so exactly one replica — and exactly one request
/// on that replica — can win a given nonce inside its TTL.
enum NonceReplayBackend {
    Process(Arc<Mutex<NonceReplayState>>),
    Shared(Arc<RedisRateLimitClient>),
}

/// Process-global replay scopes, keyed by `{namespace}|{plugin-config-id}`.
///
/// Held by strong reference for the life of any live plugin generation that
/// joined the scope. Deleted or renamed configs leave their map entry behind
/// until cold-path pruning in [`process_replay_state`] reclaims it: a scope is
/// removed only when the registry is its sole strong owner, its state is
/// unpoisoned and structurally consistent, and every retained claim is expired
/// (or the map is empty). The key space is bounded by
/// [`MAX_NONCE_REPLAY_SCOPES`] and admission fails closed at the cap.
static NONCE_REPLAY_REGISTRY: LazyLock<Mutex<HashMap<String, Arc<Mutex<NonceReplayState>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether a retired process replay scope may be removed from the registry.
///
/// Fail-closed: poisoned or structurally inconsistent state is never reclaimed
/// (silently replacing it would reopen a replay window). Live claims are
/// detected from the age index's **newest** entry — if the newest is still
/// inside [`NONCE_CLAIM_RETENTION_SECONDS`], every older entry is live too.
fn retired_replay_scope_is_reclaimable(state: &Arc<Mutex<NonceReplayState>>, now: Instant) -> bool {
    if Arc::strong_count(state) != 1 {
        return false;
    }
    let Ok(guard) = state.lock() else {
        return false;
    };
    if !guard.fully_structurally_consistent() {
        return false;
    }
    let Some((&(inserted_at, _), _)) = guard.age_index.last_key_value() else {
        // Consistently empty: reclaimable.
        return true;
    };
    SoapWsSecurity::nonce_age_seconds(now, inserted_at) >= NONCE_CLAIM_RETENTION_SECONDS
}

/// Cold-path prune of retired process replay scopes.
///
/// Walks the bounded registry (≤ [`MAX_NONCE_REPLAY_SCOPES`]) once. Never runs
/// on the request hot path; only when resolving/creating a scope during plugin
/// construction. Does not scan nonce maps — only the ordered age index's newest
/// key is consulted per candidate.
fn prune_retired_nonce_replay_scopes(
    registry: &mut HashMap<String, Arc<Mutex<NonceReplayState>>>,
    now: Instant,
) {
    let reclaimable: Vec<String> = registry
        .iter()
        .filter(|(_, state)| retired_replay_scope_is_reclaimable(state, now))
        .map(|(key, _)| key.clone())
        .collect();
    for key in reclaimable {
        registry.remove(&key);
    }
}

/// Resolve the process-global replay state for `scope_key`.
///
/// `None` means "no stable identity" — configuration validation and direct/test
/// construction. Those get private state so a validation call can neither read,
/// mutate, nor consume a live proxy's replay history, and cannot consume a
/// registry slot.
///
/// Retention is not a parameter here: every generation joining a scope expires
/// entries against the same fixed [`NONCE_CLAIM_RETENTION_SECONDS`] horizon, so
/// there is no per-scope mark to reconcile, raise, or carry across a reload.
/// Joining an existing scope is therefore a pure lookup. Creating a *new* scope
/// first reclaims retired empty/fully-expired scopes so deleted configs cannot
/// permanently exhaust [`MAX_NONCE_REPLAY_SCOPES`].
fn process_replay_state(scope_key: Option<&str>) -> Result<Arc<Mutex<NonceReplayState>>, String> {
    let Some(scope_key) = scope_key else {
        return Ok(Arc::new(Mutex::new(NonceReplayState::new())));
    };
    let Ok(mut registry) = NONCE_REPLAY_REGISTRY.lock() else {
        return Err("soap_ws_security: replay-scope registry is unavailable".to_string());
    };
    let existing_scope = registry.get(scope_key).cloned();
    if let Some(existing) = existing_scope {
        drop(registry);
        // A poisoned scope must not be reused: it would silently answer from
        // state whose accounting invariants were never re-proved.
        if existing.lock().is_err() {
            return Err("soap_ws_security: replay scope state is unavailable".to_string());
        }
        return Ok(existing);
    }
    prune_retired_nonce_replay_scopes(&mut registry, Instant::now());
    if registry.len() >= MAX_NONCE_REPLAY_SCOPES {
        // Fixed diagnostic: the scope key embeds an operator resource id, which
        // is not secret but is also not needed to act on this.
        return Err(format!(
            "soap_ws_security: refusing to create more than {MAX_NONCE_REPLAY_SCOPES} distinct \
             PasswordDigest replay scopes in one process"
        ));
    }
    let state = Arc::new(Mutex::new(NonceReplayState::new()));
    registry.insert(scope_key.to_string(), Arc::clone(&state));
    Ok(state)
}

/// Current process-global replay-scope registry cardinality (test support).
#[allow(dead_code)]
pub(crate) fn nonce_replay_registry_len_for_tests() -> Result<usize, String> {
    let Ok(registry) = NONCE_REPLAY_REGISTRY.lock() else {
        return Err("soap_ws_security: replay-scope registry is unavailable".to_string());
    };
    Ok(registry.len())
}

/// Whether `scope_key` is still present in the process-global registry.
#[allow(dead_code)]
pub(crate) fn nonce_replay_registry_contains_for_tests(scope_key: &str) -> Result<bool, String> {
    let Ok(registry) = NONCE_REPLAY_REGISTRY.lock() else {
        return Err("soap_ws_security: replay-scope registry is unavailable".to_string());
    };
    Ok(registry.contains_key(scope_key))
}

#[allow(dead_code)]
pub(crate) const MAX_NONCE_REPLAY_SCOPES_FOR_TESTS: usize = MAX_NONCE_REPLAY_SCOPES;

#[allow(dead_code)]
pub(crate) const NONCE_CLAIM_RETENTION_SECONDS_FOR_TESTS: u64 = NONCE_CLAIM_RETENTION_SECONDS;

/// Stable process-global replay-scope identity for a plugin config.
fn nonce_replay_scope_key(namespace: &str, plugin_config_id: &str) -> String {
    let mut key = String::with_capacity(namespace.len() + plugin_config_id.len() + 1);
    key.push_str(namespace);
    key.push('|');
    key.push_str(plugin_config_id);
    key
}

/// Default Redis key prefix for shared replay claims:
/// `{namespace}:soap_ws_security:{plugin-config-id}`.
///
/// The config-id component isolates independent PasswordDigest policies inside
/// one namespace while every replica of the *same* policy keeps claiming against
/// the same keyspace — which is the whole point of the shared scope. An explicit
/// `redis_key_prefix` remains the documented opt-in for deliberately sharing a
/// keyspace across policies.
fn default_nonce_redis_key_prefix(namespace: &str, plugin_config_id: Option<&str>) -> String {
    let config_id = plugin_config_id.unwrap_or("__standalone__");
    let mut prefix = String::with_capacity(namespace.len() + config_id.len() + 20);
    prefix.push_str(namespace);
    prefix.push_str(":soap_ws_security:");
    prefix.push_str(config_id);
    prefix
}

// The binary target compiles this module without the library's `_test_support`
// facade, so this external-test observation type is intentionally unused there.
#[allow(dead_code)]
pub(crate) struct NonceReplayObservationForTests {
    pub(crate) entry_count: usize,
    pub(crate) age_index_entry_count: usize,
    pub(crate) retained_key_bytes: usize,
    pub(crate) recomputed_key_bytes: usize,
    pub(crate) shared_key_entries: usize,
    pub(crate) last_expired_removals: usize,
    pub(crate) max_maintenance_entries: usize,
    /// The fixed horizon, in seconds, entries are actually expired against.
    pub(crate) retention_seconds: u64,
}

// ── Plugin struct ───────────────────────────────────────────────────────────

pub struct SoapWsSecurity {
    // Media-type governance
    content_type_mode: ContentTypeMode,
    allow_mtom: bool,

    // Timestamp validation
    require_timestamp: bool,
    timestamp_max_age_seconds: u64,
    timestamp_require_expires: bool,
    /// Pre-converted at admission; the request path performs no fallible or
    /// panicking duration construction.
    timestamp_max_age: chrono::Duration,
    clock_skew: chrono::Duration,

    // UsernameToken
    username_token_enabled: bool,
    password_type: PasswordType,
    credentials: Vec<Credential>,
    /// Freshness window for the UsernameToken's own `wsu:Created`, the instant
    /// bound into the PasswordDigest. Pre-converted at admission.
    ut_created_max_age: chrono::Duration,
    ut_created_max_age_seconds: u64,
    ut_created_clock_skew: chrono::Duration,
    /// Maximum permitted `|UsernameToken.Created - Timestamp.Created|`.
    ut_created_max_timestamp_divergence: chrono::Duration,
    ut_created_max_timestamp_divergence_seconds: u64,
    /// When true (default), a PasswordDigest token must be accompanied by an
    /// outer `wsu:Timestamp` carrying a `Created` value to bind against.
    require_timestamp_binding: bool,
    /// Process-local padding secret used only to equalize verification work on
    /// username lookup misses. Never authenticates a principal.
    dummy_password: String,
    /// Fixed-width PasswordText verifier for `dummy_password`.
    dummy_password_text_hash: [u8; 32],

    // X.509 signature verification
    x509_enabled: bool,
    trusted_certs: Vec<TrustedCert>,
    allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    allowed_digest_algorithms: Vec<DigestAlgorithm>,
    require_signed_timestamp: bool,

    // SAML assertion validation
    saml_enabled: bool,
    saml_trusted_issuers: Vec<String>,
    /// Service-specific audience binding. Required whenever SAML is enabled:
    /// without it, an assertion minted by the same trusted IdP for a different
    /// relying party is accepted here (GHSA-f44p-hfqr-cvcc).
    saml_audience: Option<String>,
    /// Service-specific `SubjectConfirmationData/@Recipient` binding, also
    /// required whenever SAML is enabled.
    saml_recipient: Option<String>,
    saml_max_assertion_lifetime: chrono::Duration,
    saml_max_assertion_lifetime_seconds: u64,
    saml_allowed_confirmation_methods: Vec<String>,
    saml_clock_skew: chrono::Duration,
    saml_trusted_signing_certs: Vec<TrustedCert>,
    saml_allowed_signature_algorithms: Vec<SignatureAlgorithm>,
    saml_allowed_digest_algorithms: Vec<DigestAlgorithm>,

    // Nonce replay protection
    /// Where a verified PasswordDigest claims its nonce. Process-local state is
    /// shared across reload generations through the process-global registry;
    /// shared state is claimed atomically in Redis so replicas cannot each
    /// accept the same captured token.
    nonce_backend: NonceReplayBackend,
    // There is deliberately no per-instance retention field: both scopes use the
    // fixed `NONCE_CLAIM_RETENTION_SECONDS` horizon, so no generation can carry
    // a retention that another generation would have to reconcile with.
    max_nonce_cache_size: usize,
    /// Encoded-nonce ceiling, enforced before Base64 decoding and before any
    /// cache insertion.
    max_nonce_encoded_length: usize,
    /// Logical UTF-8 key payload only. Hash/tree nodes and `Arc` control blocks
    /// are excluded and bounded independently by `max_nonce_cache_size`.
    max_nonce_cache_bytes: usize,

    // General
    reject_missing_security_header: bool,
}

impl SoapWsSecurity {
    /// Construct with no gateway HTTP client and no stable plugin-config
    /// identity.
    ///
    /// Process replay state is private to the returned instance, so this form
    /// cannot be used for a production PasswordDigest deployment that needs
    /// replay history to survive a reload. Production construction goes through
    /// [`Self::new_with_http_client_and_config_id`]. See [`Self::build`] for why
    /// a `replay_scope: shared` config is still safe to construct here.
    // Called through `lib::_test_support` and external tests; the binary target
    // compiles this module without that facade and uses
    // `new_with_http_client_and_config_id` for production wiring.
    #[allow(dead_code)]
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::build(config, None, None)
    }

    pub fn new_with_http_client_and_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        Self::build(config, Some(&http_client), plugin_config_id)
    }

    /// `http_client` is `Option` on purpose: the plain `new()` path (Admin
    /// config validation and direct/test construction) must not have to build a
    /// reqwest/TLS/DNS stack it never uses.
    ///
    /// A `replay_scope: shared` config still constructs its Redis client on that
    /// path — the backend is chosen by the config, not by the caller — but the
    /// client connects lazily and validation never issues a claim, so no
    /// connection, no recovery task, and no keyspace mutation results. With no
    /// plugin-config id the default key prefix is also distinct
    /// (`__standalone__`), so a validation-constructed instance cannot collide
    /// with a live policy's keyspace unless an explicit `redis_key_prefix` makes
    /// it do so. `replay_scope: process` without an id gets private state, which
    /// is what keeps validation from reading, mutating, or consuming a live
    /// proxy's claims.
    fn build(
        config: &Value,
        http_client: Option<&PluginHttpClient>,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let namespace = match http_client {
            Some(client) => client.namespace(),
            None => crate::config::types::DEFAULT_NAMESPACE,
        };
        // Fixed/redacted diagnostic: never interpolate the configured value —
        // a non-object root can still carry credential-like material or be
        // unbounded in size.
        let config_obj = config
            .as_object()
            .ok_or_else(|| "soap_ws_security: config must be an object".to_string())?;

        // Strict admission: unknown root keys fail closed. This is what makes
        // the documented-but-never-read `nonce_replay_protection` object and
        // every misspelling an error instead of a silently weaker policy.
        let root = Some(config_obj);
        reject_unknown(root, "config", &ROOT_CONFIG_KEYS)?;

        // ── Media-type governance (GHSA-435h-f785-wmm4) ─────────────────
        //
        // The default is `strict`: every request on a proxy carrying this
        // plugin is a governed SOAP request. Selecting a representation the
        // backend accepts but the gateway did not classify as SOAP was a
        // complete bypass of authentication, integrity, freshness, and replay
        // protection, so pass-through is now an explicit, named opt-out rather
        // than the consequence of a client-chosen header value.
        let content_type_cfg = soap_object(root, "config", "content_type")?;
        reject_unknown(
            content_type_cfg,
            "config.content_type",
            CONTENT_TYPE_CONFIG_KEYS,
        )?;
        let configured_mode = soap_string(content_type_cfg, "config.content_type", "mode")?;
        let content_type_mode = match configured_mode.as_deref().unwrap_or("strict") {
            "strict" => ContentTypeMode::Strict,
            "mixed_route" => ContentTypeMode::MixedRoute,
            _ => {
                return Err(
                    "soap_ws_security: 'config.content_type.mode' must be one of: strict, \
                     mixed_route"
                        .to_string(),
                );
            }
        };
        // Whether the operator *named* `allow_mtom`, as distinct from taking its
        // default. An explicit `true` alongside an X.509 policy is a
        // contradiction worth refusing at admission rather than silently
        // rejecting every MTOM request at runtime.
        let allow_mtom_explicit =
            present(content_type_cfg, "config.content_type", "allow_mtom")?.is_some();
        let allow_mtom = soap_bool(content_type_cfg, "config.content_type", "allow_mtom", true)?;

        // ── Timestamp config ────────────────────────────────────────────
        let ts_cfg = soap_object(root, "config", "timestamp")?;
        reject_unknown(ts_cfg, "config.timestamp", TIMESTAMP_CONFIG_KEYS)?;
        let require_timestamp = soap_bool(ts_cfg, "config.timestamp", "require", true)?;
        let timestamp_max_age_seconds = soap_u64_bounded(
            ts_cfg,
            "config.timestamp",
            "max_age_seconds",
            300,
            MIN_TIMESTAMP_MAX_AGE_SECONDS,
            MAX_TIMESTAMP_MAX_AGE_SECONDS,
        )?;
        let timestamp_require_expires =
            soap_bool(ts_cfg, "config.timestamp", "require_expires", false)?;
        let clock_skew_seconds = soap_u64_bounded(
            ts_cfg,
            "config.timestamp",
            "clock_skew_seconds",
            300,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        let timestamp_max_age = admitted_duration(
            "config.timestamp",
            "max_age_seconds",
            timestamp_max_age_seconds,
        )?;
        let clock_skew =
            admitted_duration("config.timestamp", "clock_skew_seconds", clock_skew_seconds)?;

        // ── UsernameToken config ────────────────────────────────────────
        let ut_cfg = soap_object(root, "config", "username_token")?;
        reject_unknown(ut_cfg, "config.username_token", USERNAME_TOKEN_CONFIG_KEYS)?;
        let username_token_enabled = soap_bool(ut_cfg, "config.username_token", "enabled", false)?;
        let configured_type = soap_string(ut_cfg, "config.username_token", "password_type")?;
        let password_type = match configured_type.as_deref().unwrap_or("PasswordDigest") {
            "PasswordText" => PasswordType::PasswordText,
            "PasswordDigest" => PasswordType::PasswordDigest,
            _ => {
                return Err(
                    "soap_ws_security: 'config.username_token.password_type' must be one of: PasswordText, PasswordDigest"
                        .to_string(),
                );
            }
        };

        // Credentials are validated entry by entry. A malformed entry is an
        // error rather than a dropped entry: silently shrinking the credential
        // set changes who can authenticate without any operator signal.
        let mut credentials: Vec<Credential> = Vec::new();
        if let Some(entries) = present(ut_cfg, "config.username_token", "credentials")? {
            let ut_path = "config.username_token";
            let Some(array) = entries.as_array() else {
                return Err(type_error(ut_path, "credentials", "an array"));
            };
            credentials.reserve(array.len());
            for (index, entry) in array.iter().enumerate() {
                let path = format!("{ut_path}.credentials[{index}]");
                let Some(entry_obj) = entry.as_object() else {
                    return Err(type_error(ut_path, "credentials", "an array of objects"));
                };
                let entry_ref = Some(entry_obj);
                reject_unknown(entry_ref, &path, CREDENTIAL_CONFIG_KEYS)?;
                let Some(username) = soap_string(entry_ref, &path, "username")? else {
                    return Err(required_error(&path, "username"));
                };
                let Some(password) = soap_string(entry_ref, &path, "password")? else {
                    return Err(required_error(&path, "password"));
                };
                // Duplicate usernames would make credential selection
                // first-wins, so a later rotation entry would be inert.
                if credentials.iter().any(|c| c.username == username) {
                    return Err(duplicate_error(&path));
                }
                let password_text_hash = sha256_array(password.as_bytes());
                credentials.push(Credential {
                    username,
                    password,
                    password_text_hash,
                });
            }
        }

        // UsernameToken `Created` freshness + outer-Timestamp binding. These are
        // parsed unconditionally so a latent PasswordText config cannot switch
        // to PasswordDigest later and activate an unvalidated window.
        let ut_created_max_age_seconds = soap_u64_bounded(
            ut_cfg,
            "config.username_token",
            "created_max_age_seconds",
            DEFAULT_UT_CREATED_MAX_AGE_SECONDS,
            MIN_UT_CREATED_MAX_AGE_SECONDS,
            MAX_UT_CREATED_MAX_AGE_SECONDS,
        )?;
        let ut_created_clock_skew_seconds = soap_u64_bounded(
            ut_cfg,
            "config.username_token",
            "created_clock_skew_seconds",
            DEFAULT_UT_CREATED_CLOCK_SKEW_SECONDS,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        let ut_created_max_timestamp_divergence_seconds = soap_u64_bounded(
            ut_cfg,
            "config.username_token",
            "created_max_timestamp_divergence_seconds",
            DEFAULT_UT_TIMESTAMP_DIVERGENCE_SECONDS,
            MIN_UT_TIMESTAMP_DIVERGENCE_SECONDS,
            MAX_UT_TIMESTAMP_DIVERGENCE_SECONDS,
        )?;
        let require_timestamp_binding = soap_bool(
            ut_cfg,
            "config.username_token",
            "require_timestamp_binding",
            true,
        )?;
        let ut_created_max_age = admitted_duration(
            "config.username_token",
            "created_max_age_seconds",
            ut_created_max_age_seconds,
        )?;
        let ut_created_clock_skew = admitted_duration(
            "config.username_token",
            "created_clock_skew_seconds",
            ut_created_clock_skew_seconds,
        )?;
        let ut_created_max_timestamp_divergence = admitted_duration(
            "config.username_token",
            "created_max_timestamp_divergence_seconds",
            ut_created_max_timestamp_divergence_seconds,
        )?;

        if username_token_enabled && credentials.is_empty() {
            return Err(
                "soap_ws_security: username_token is enabled but no credentials are configured"
                    .to_string(),
            );
        }

        // Random process-local material so lookup misses still execute the same
        // PasswordText / PasswordDigest verification work as known principals.
        // This value is never accepted as a configured credential.
        let dummy_password = format!("soap-ws-security-dummy:{}", uuid::Uuid::new_v4());
        let dummy_password_text_hash = sha256_array(dummy_password.as_bytes());

        // ── X.509 signature config ──────────────────────────────────────
        let x509_cfg = soap_object(root, "config", "x509_signature")?;
        reject_unknown(x509_cfg, "config.x509_signature", X509_CONFIG_KEYS)?;
        let x509_enabled = soap_bool(x509_cfg, "config.x509_signature", "enabled", false)?;

        let cert_paths = soap_string_array(x509_cfg, "config.x509_signature", "trusted_certs")?;
        let trusted_cert_paths: Vec<String> = cert_paths.unwrap_or_default();

        if x509_enabled && trusted_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: x509_signature is enabled but no trusted_certs are configured"
                    .to_string(),
            );
        }

        let mut trusted_certs = Vec::with_capacity(trusted_cert_paths.len());
        for path in &trusted_cert_paths {
            let source = parse_trusted_certificate_source(path);
            let material = load_material_blocking(&source, MaterialKind::Cert)
                .map_err(|e| format!("soap_ws_security: failed to load trusted cert: {e}"))?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' is not valid UTF-8: {}",
                    material.display_source_id, e
                )
            })?;

            // Every failure past a *successful* fetch names the material by its
            // redacted `display_source_id`, never the configured `path`. A
            // `vault://`/`aws://`/`azure://`/`gcp://` source carries its
            // identifier in that path, and a PEM/X.509/RSA parse failure is
            // reachable by an operator who can see the error but not the
            // secret store — so interpolating `path` here would disclose the
            // provider reference on exactly the paths most likely to fire.
            // This matches `MaterializedMaterial::display_source_id`'s stated
            // contract, which names this module as one of its call sites.
            let der_bytes = extract_pem_der(pem_str).ok_or_else(|| {
                format!(
                    "soap_ws_security: failed to decode PEM from '{}'",
                    material.display_source_id
                )
            })?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse X.509 cert '{}': {}",
                    material.display_source_id, e
                )
            })?;

            let public_key_der = load_rsa_public_key_from_cert(&cert).map_err(|e| {
                format!(
                    "soap_ws_security: trusted cert '{}' {}",
                    material.display_source_id, e
                )
            })?;

            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();
            let principal = format!("x509:sha256:{}", sha256_hex_lower(&der_bytes));

            trusted_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
                principal,
            });
        }

        let allowed_signature_algorithms: Vec<SignatureAlgorithm> = soap_enum_array(
            x509_cfg,
            "config.x509_signature",
            "allowed_algorithms",
            SIGNATURE_ALGORITHM_VARIANTS,
            &[SignatureAlgorithm::RsaSha256],
        )?;

        if x509_enabled && allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let allowed_digest_algorithms: Vec<DigestAlgorithm> = soap_enum_array(
            x509_cfg,
            "config.x509_signature",
            "allowed_digest_algorithms",
            DIGEST_ALGORITHM_VARIANTS,
            &[DigestAlgorithm::Sha256],
        )?;

        if x509_enabled && allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: x509_signature.allowed_digest_algorithms must contain at least \
                 one of 'sha256' or 'sha1' when x509_signature is enabled"
                    .to_string(),
            );
        }

        let require_signed_timestamp = soap_bool(
            x509_cfg,
            "config.x509_signature",
            "require_signed_timestamp",
            true,
        )?;

        // Contradictory configuration is refused at admission rather than
        // satisfied vacuously at request time. `require_signed_timestamp` now
        // rejects a message with no Timestamp, so pairing it with
        // `timestamp.require: false` declares two incompatible policies: one
        // says the Timestamp is optional, the other says it must be present and
        // signed. The old behaviour — "no Timestamp, therefore nothing to
        // check, therefore pass" — is the vacuous satisfaction described in
        // GHSA-3mwq-c8j6-9xhp.
        if x509_enabled && require_signed_timestamp && !require_timestamp {
            return Err(
                "soap_ws_security: 'config.x509_signature.require_signed_timestamp' requires \
                 'config.timestamp.require' to be true — a signed Timestamp cannot be required \
                 while the Timestamp itself is optional"
                    .to_string(),
            );
        }

        // Ferrum implements no WS-Security attachment-signature transform, so
        // an X.509 policy cannot cover the octets an `xop:Include` stands for.
        // Asking for both is asking for integrity Ferrum cannot establish;
        // XOP/MTOM representations are refused at request time either way, and
        // an explicit `allow_mtom: true` is refused here so the contradiction
        // surfaces at admission instead of as a runtime 415.
        if x509_enabled && allow_mtom_explicit && allow_mtom {
            return Err(
                "soap_ws_security: 'config.content_type.allow_mtom' cannot be true while \
                 'config.x509_signature.enabled' is true — Ferrum implements no WS-Security \
                 attachment-signature transform, so an X.509 signature cannot cover MTOM/XOP \
                 attachment octets"
                    .to_string(),
            );
        }

        // ── SAML config ─────────────────────────────────────────────────
        let saml_cfg = soap_object(root, "config", "saml")?;
        reject_unknown(saml_cfg, "config.saml", SAML_CONFIG_KEYS)?;
        let saml_enabled = soap_bool(saml_cfg, "config.saml", "enabled", false)?;

        let issuers = soap_string_array(saml_cfg, "config.saml", "trusted_issuers")?;
        let saml_trusted_issuers: Vec<String> = issuers.unwrap_or_default();

        if saml_enabled && saml_trusted_issuers.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_issuers are configured"
                    .to_string(),
            );
        }

        // A wrong-typed audience used to become `None`, silently removing
        // service binding while SAML stayed enabled. It is now also mandatory:
        // an optional audience meant a signed assertion issued for a different
        // relying party by the same trusted IdP was accepted here.
        let saml_audience = soap_string(saml_cfg, "config.saml", "audience")?;
        if saml_enabled && saml_audience.is_none() {
            return Err(
                "soap_ws_security: 'config.saml.audience' is required when saml is enabled — \
                 without a service-specific AudienceRestriction binding, an assertion minted by \
                 the same trusted issuer for another service is accepted here"
                    .to_string(),
            );
        }
        let saml_recipient = soap_string(saml_cfg, "config.saml", "recipient")?;
        if saml_enabled && saml_recipient.is_none() {
            return Err(
                "soap_ws_security: 'config.saml.recipient' is required when saml is enabled — it \
                 is matched against SubjectConfirmationData/@Recipient so a captured assertion \
                 cannot be presented to a different endpoint"
                    .to_string(),
            );
        }
        let saml_max_assertion_lifetime_seconds = soap_u64_bounded(
            saml_cfg,
            "config.saml",
            "max_assertion_lifetime_seconds",
            DEFAULT_SAML_ASSERTION_LIFETIME_SECONDS,
            MIN_SAML_ASSERTION_LIFETIME_SECONDS,
            MAX_SAML_ASSERTION_LIFETIME_SECONDS,
        )?;
        let saml_max_assertion_lifetime = admitted_duration(
            "config.saml",
            "max_assertion_lifetime_seconds",
            saml_max_assertion_lifetime_seconds,
        )?;
        let saml_allowed_confirmation_methods = match soap_string_array(
            saml_cfg,
            "config.saml",
            "allowed_subject_confirmation_methods",
        )? {
            None => vec![SAML2_CM_BEARER.to_string()],
            Some(methods) if methods.is_empty() => {
                return Err(type_error(
                    "config.saml",
                    "allowed_subject_confirmation_methods",
                    "a non-empty array of supported SubjectConfirmation method URIs",
                ));
            }
            Some(methods) => {
                for method in &methods {
                    // Only semantics Ferrum actually implements may be
                    // configured. `holder-of-key` needs the confirmation key to
                    // be proven against the message signature, which this
                    // plugin does not do, so accepting it would be a policy the
                    // gateway cannot enforce.
                    if method != SAML2_CM_BEARER {
                        let supported = if method == SAML2_CM_HOLDER_OF_KEY {
                            "'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key' is not supported \
                             because the confirmation key is not bound to the message signature"
                        } else {
                            "only 'urn:oasis:names:tc:SAML:2.0:cm:bearer' is supported"
                        };
                        return Err(format!(
                            "soap_ws_security: \
                             'config.saml.allowed_subject_confirmation_methods' contains an \
                             unsupported method; {supported}"
                        ));
                    }
                }
                methods
            }
        };
        let saml_clock_skew_seconds = soap_u64_bounded(
            saml_cfg,
            "config.saml",
            "clock_skew_seconds",
            300,
            MIN_CLOCK_SKEW_SECONDS,
            MAX_CLOCK_SKEW_SECONDS,
        )?;
        let saml_clock_skew =
            admitted_duration("config.saml", "clock_skew_seconds", saml_clock_skew_seconds)?;

        // SAML trusted signing certs — IdP X.509 certs used to verify the
        // assertion's `<Signature>`. Matched by SHA-256 fingerprint of the
        // full DER, so operators must trust each leaf cert directly (no CA
        // chain validation). This is the standard practice for SAML where
        // IdPs publish their signing certs in metadata.
        let signing_certs = soap_string_array(saml_cfg, "config.saml", "trusted_signing_certs")?;
        let saml_trusted_signing_cert_paths: Vec<String> = signing_certs.unwrap_or_default();

        if saml_enabled && saml_trusted_signing_cert_paths.is_empty() {
            return Err(
                "soap_ws_security: saml is enabled but no trusted_signing_certs are configured — \
                 without trusted IdP signing certs, assertion signatures cannot be verified and \
                 any caller could forge an assertion claiming to be issued by a trusted issuer"
                    .to_string(),
            );
        }

        let mut saml_trusted_signing_certs =
            Vec::with_capacity(saml_trusted_signing_cert_paths.len());
        for path in &saml_trusted_signing_cert_paths {
            let source = parse_trusted_certificate_source(path);
            let material = load_material_blocking(&source, MaterialKind::Cert).map_err(|e| {
                format!("soap_ws_security: failed to load SAML trusted signing cert: {e}")
            })?;

            let pem_str = std::str::from_utf8(material.bytes.expose_secret()).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' is not valid UTF-8: {}",
                    material.display_source_id, e
                )
            })?;

            // Same rule as the WS-Security X.509 loop above: past a successful
            // fetch the material is named only by its redacted
            // `display_source_id`.
            let der_bytes = extract_pem_der(pem_str).ok_or_else(|| {
                format!(
                    "soap_ws_security: failed to decode PEM from SAML trusted signing cert '{}'",
                    material.display_source_id
                )
            })?;

            let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
                format!(
                    "soap_ws_security: failed to parse SAML trusted signing cert '{}': {}",
                    material.display_source_id, e
                )
            })?;

            let public_key_der = load_rsa_public_key_from_cert(&cert).map_err(|e| {
                format!(
                    "soap_ws_security: SAML trusted signing cert '{}' {}",
                    material.display_source_id, e
                )
            })?;
            let fingerprint = digest::digest(&digest::SHA256, &der_bytes)
                .as_ref()
                .to_vec();
            let principal = format!("x509:sha256:{}", sha256_hex_lower(&der_bytes));

            saml_trusted_signing_certs.push(TrustedCert {
                public_key_der,
                fingerprint,
                principal,
            });
        }

        let saml_allowed_signature_algorithms: Vec<SignatureAlgorithm> = soap_enum_array(
            saml_cfg,
            "config.saml",
            "allowed_signature_algorithms",
            SIGNATURE_ALGORITHM_VARIANTS,
            &[SignatureAlgorithm::RsaSha256],
        )?;

        if saml_enabled && saml_allowed_signature_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_signature_algorithms must contain at least one of \
                 'rsa-sha256' or 'rsa-sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        let saml_allowed_digest_algorithms: Vec<DigestAlgorithm> = soap_enum_array(
            saml_cfg,
            "config.saml",
            "allowed_digest_algorithms",
            DIGEST_ALGORITHM_VARIANTS,
            &[DigestAlgorithm::Sha256],
        )?;

        if saml_enabled && saml_allowed_digest_algorithms.is_empty() {
            return Err(
                "soap_ws_security: saml.allowed_digest_algorithms must contain at least one of \
                 'sha256' or 'sha1' when SAML is enabled"
                    .to_string(),
            );
        }

        // ── Nonce / replay config ───────────────────────────────────────
        // Zero capacity used to be accepted and made replay detection inert
        // while the plugin still advertised it, so every capacity bound now has
        // an enforced lower bound. Retention is no longer among them: it is the
        // fixed horizon, unreachable from configuration.
        let nonce_cfg = soap_object(root, "config", "nonce")?;
        reject_unknown(nonce_cfg, "config.nonce", NONCE_CONFIG_KEYS)?;
        // Claim retention is not configurable. It is the fixed schema-wide
        // `NONCE_CLAIM_RETENTION_SECONDS` horizon, which dominates the retention
        // *this* policy's `Created` window requires and every window any future
        // admitted generation could open. The per-policy requirement is still
        // computed and enforced here so the dominance relation is a checked
        // property of the code rather than a claim in prose; it is unreachable
        // for admitted inputs, which are bounded by the same ceilings the
        // horizon is derived from.
        let minimum_retention_seconds = minimum_replay_retention_seconds(
            ut_created_max_age_seconds,
            ut_created_clock_skew_seconds,
        )
        .ok_or_else(|| {
            "soap_ws_security: 'config.username_token' Created window overflows the replay \
             retention it requires"
                .to_string()
        })?;
        if minimum_retention_seconds > NONCE_CLAIM_RETENTION_SECONDS {
            return Err(format!(
                "soap_ws_security: 'config.username_token' Created window requires \
                 {minimum_retention_seconds}s of nonce replay retention, which exceeds the \
                 {NONCE_CLAIM_RETENTION_SECONDS}s claims are retained for"
            ));
        }
        let max_nonce_cache_size = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_cache_size",
            DEFAULT_NONCE_MAX_CACHE_SIZE,
            MIN_NONCE_MAX_CACHE_SIZE,
            MAX_NONCE_MAX_CACHE_SIZE,
        )?;
        let max_nonce_encoded_length = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_encoded_length",
            DEFAULT_NONCE_MAX_ENCODED_LENGTH,
            MIN_NONCE_MAX_ENCODED_LENGTH,
            MAX_NONCE_MAX_ENCODED_LENGTH,
        )?;
        let max_nonce_cache_bytes = soap_u64_bounded(
            nonce_cfg,
            "config.nonce",
            "max_total_cache_bytes",
            DEFAULT_NONCE_MAX_TOTAL_CACHE_BYTES,
            MIN_NONCE_MAX_TOTAL_CACHE_BYTES,
            MAX_NONCE_MAX_TOTAL_CACHE_BYTES,
        )?;
        // A byte cap below one maximum-length nonce would reject every
        // PasswordDigest request; refuse the contradiction at admission rather
        // than failing closed on live traffic.
        if max_nonce_cache_bytes < max_nonce_encoded_length {
            let expected = format!("at least max_encoded_length ({max_nonce_encoded_length})");
            let path = "config.nonce";
            return Err(type_error(path, "max_total_cache_bytes", &expected));
        }
        let max_nonce_cache_size = usize_or_max(max_nonce_cache_size);
        let max_nonce_encoded_length = usize_or_max(max_nonce_encoded_length);
        let max_nonce_cache_bytes = usize_or_max(max_nonce_cache_bytes);

        // ── Replay scope / shared backend ───────────────────────────────
        //
        // `replay_scope` has no default. A gateway cannot detect how many
        // replicas serve a proxy, so the deployment shape is an explicit
        // operator declaration; a silent process-local default is what let one
        // captured UsernameToken be spent once per replica and once per reload.
        let configured_scope = soap_string(nonce_cfg, "config.nonce", "replay_scope")?;
        let replay_scope = match configured_scope.as_deref() {
            None => None,
            Some("process") => Some(NonceReplayScope::Process),
            Some("shared") => Some(NonceReplayScope::Shared),
            // Value-redacted: the rejected string is operator input adjacent to
            // credential material in the same object graph.
            Some(_) => {
                return Err(
                    "soap_ws_security: 'config.nonce.replay_scope' must be exactly 'process' or \
                     'shared'"
                        .to_string(),
                );
            }
        };

        let digest_replay_active =
            username_token_enabled && password_type == PasswordType::PasswordDigest;
        // A signed SAML assertion is a reusable bearer value: nothing in the
        // assertion changes between presentations, and the outer WS-Security
        // Timestamp it travels with is not covered by the assertion signature,
        // so it can be reminted on every replay. Single-use enforcement is
        // therefore mandatory, which means the deployment shape has to be
        // declared for SAML exactly as it is for PasswordDigest
        // (GHSA-f44p-hfqr-cvcc).
        let replay_active = digest_replay_active || saml_enabled;

        if replay_active && replay_scope.is_none() {
            let trigger = if digest_replay_active && saml_enabled {
                "username_token.password_type is 'PasswordDigest' and saml is enabled"
            } else if digest_replay_active {
                "username_token.password_type is 'PasswordDigest'"
            } else {
                "saml is enabled"
            };
            return Err(format!(
                "soap_ws_security: 'config.nonce.replay_scope' is required when {trigger} — use \
                 'shared' together with sync_mode: 'redis' for any deployment running more than \
                 one gateway replica, or 'process' to declare a single-replica deployment whose \
                 replay protection is not cross-replica"
            ));
        }

        // A blank id would collapse every plugin config in a namespace onto one
        // replay scope / keyspace; fail closed rather than merge them.
        if plugin_config_id.is_some_and(|config_id| config_id.trim().is_empty()) {
            return Err("soap_ws_security: plugin config id must not be blank".to_string());
        }

        // Redis fields are parsed (and range/shape-validated) whether or not
        // they are active, matching every other Redis-backed plugin.
        let default_prefix = default_nonce_redis_key_prefix(namespace, plugin_config_id);
        let redis_config = RedisConfig::from_plugin_config(config, &default_prefix)?;
        match (replay_scope, redis_config.is_some()) {
            (Some(NonceReplayScope::Shared), false) => {
                return Err(
                    "soap_ws_security: 'config.nonce.replay_scope' = 'shared' requires \
                     sync_mode: 'redis' and a 'redis_url'"
                        .to_string(),
                );
            }
            (scope, true) if scope != Some(NonceReplayScope::Shared) => {
                return Err(
                    "soap_ws_security: sync_mode: 'redis' is only meaningful with \
                     'config.nonce.replay_scope' = 'shared'"
                        .to_string(),
                );
            }
            _ => {}
        }

        let nonce_backend = match redis_config {
            Some(redis_config) => {
                let dns_cache = http_client.and_then(|client| client.dns_cache().cloned());
                let tls_no_verify = http_client.is_some_and(|client| client.tls_no_verify());
                let tls_ca_bundle_path = http_client.and_then(|c| c.tls_ca_bundle_path());
                NonceReplayBackend::Shared(Arc::new(RedisRateLimitClient::new(
                    redis_config,
                    dns_cache,
                    tls_no_verify,
                    tls_ca_bundle_path,
                )))
            }
            None => {
                // Only a policy that can actually make process-local replay
                // claims needs reload-stable registry state. Timestamp-only,
                // PasswordText-only, and other replay-inactive policies keep
                // private empty state so their operator-controlled config ids
                // cannot consume the bounded registry reserved for live
                // replay scopes.
                let scope_key = if replay_active && replay_scope == Some(NonceReplayScope::Process)
                {
                    plugin_config_id.map(|config_id| nonce_replay_scope_key(namespace, config_id))
                } else {
                    None
                };
                NonceReplayBackend::Process(process_replay_state(scope_key.as_deref())?)
            }
        };

        // ── General ─────────────────────────────────────────────────────
        let reject_missing_security_header =
            soap_bool(root, "config", "reject_missing_security_header", true)?;

        // Must have at least one security feature enabled
        if !username_token_enabled && !x509_enabled && !saml_enabled && !require_timestamp {
            return Err(
                "soap_ws_security: no security features enabled — enable at least one of: username_token, x509_signature, saml, or timestamp.require"
                    .to_string(),
            );
        }

        Ok(Self {
            content_type_mode,
            allow_mtom,
            require_timestamp,
            timestamp_max_age_seconds,
            timestamp_require_expires,
            timestamp_max_age,
            clock_skew,
            username_token_enabled,
            password_type,
            credentials,
            ut_created_max_age,
            ut_created_max_age_seconds,
            ut_created_clock_skew,
            ut_created_max_timestamp_divergence,
            ut_created_max_timestamp_divergence_seconds,
            require_timestamp_binding,
            dummy_password,
            dummy_password_text_hash,
            x509_enabled,
            trusted_certs,
            allowed_signature_algorithms,
            allowed_digest_algorithms,
            require_signed_timestamp,
            saml_enabled,
            saml_trusted_issuers,
            saml_audience,
            saml_recipient,
            saml_max_assertion_lifetime,
            saml_max_assertion_lifetime_seconds,
            saml_allowed_confirmation_methods,
            saml_clock_skew,
            saml_trusted_signing_certs,
            saml_allowed_signature_algorithms,
            saml_allowed_digest_algorithms,
            nonce_backend,
            max_nonce_cache_size,
            max_nonce_encoded_length,
            max_nonce_cache_bytes,
            reject_missing_security_header,
        })
    }

    // ── Timestamp validation ────────────────────────────────────────────

    /// The single namespace-correct `wsu:Timestamp` inside the selected
    /// Security header, if present.
    fn timestamp_node<'a, 'input>(
        security: Node<'a, 'input>,
    ) -> Result<Option<Node<'a, 'input>>, String> {
        unique_ns_child(security, WSU_NAMESPACE_URI, "Timestamp", "WS-Security")
    }

    fn timestamp_instant(
        timestamp: Node<'_, '_>,
        local_name: &str,
    ) -> Result<Option<DateTime<Utc>>, String> {
        let Some(node) = unique_ns_child(timestamp, WSU_NAMESPACE_URI, local_name, "WS-Security")?
        else {
            return Ok(None);
        };
        let raw = element_text(node)
            .ok_or_else(|| format!("WS-Security: Timestamp {local_name} element is empty"))?;
        let parsed = parse_ws_datetime(&raw)
            .ok_or_else(|| format!("WS-Security: invalid {local_name} timestamp"))?;
        Ok(Some(parsed))
    }

    fn validate_timestamp(&self, security: Node<'_, '_>, now: DateTime<Utc>) -> Result<(), String> {
        let ts_node = match Self::timestamp_node(security)? {
            Some(node) => node,
            None => {
                return if self.require_timestamp {
                    Err("WS-Security: missing Timestamp element".to_string())
                } else {
                    Ok(())
                };
            }
        };

        let created = Self::timestamp_instant(ts_node, "Created")?
            .ok_or_else(|| "WS-Security: Timestamp missing Created element".to_string())?;

        // Durations are pre-converted at config admission and `parse_ws_datetime`
        // clamps parsed instants to `MIN_PARSED_YEAR..=MAX_PARSED_YEAR`, so
        // neither the duration construction nor the instant arithmetic below can
        // overflow under the current admission invariants. `checked_add_signed`
        // on Expires remains as defensive fail-closed arithmetic against future
        // clamp drift.
        let skew = self.clock_skew;
        let max_age = self.timestamp_max_age;

        // Created must not be in the future (with clock skew tolerance)
        if created > now + skew {
            return Err("WS-Security: Timestamp Created is in the future".to_string());
        }

        // Created must not be too old
        if now - created > max_age + skew {
            return Err(format!(
                "WS-Security: Timestamp Created is too old (max age {}s)",
                self.timestamp_max_age_seconds
            ));
        }

        // Expires check
        if let Some(expires) = Self::timestamp_instant(ts_node, "Expires")? {
            let expires_with_skew = expires.checked_add_signed(skew).ok_or_else(|| {
                "WS-Security: Expires timestamp is outside the supported range".to_string()
            })?;

            if now > expires_with_skew {
                return Err("WS-Security: Timestamp has expired".to_string());
            }
        } else if self.timestamp_require_expires {
            return Err("WS-Security: Timestamp missing required Expires element".to_string());
        }

        Ok(())
    }

    // ── UsernameToken validation ────────────────────────────────────────

    /// Enforce the UsernameToken `Created` freshness window and bind it to the
    /// independently validated outer `wsu:Timestamp`.
    ///
    /// `created_raw` is the *exact* string that was fed to the PasswordDigest
    /// computation, so what is validated here is what the digest commits to —
    /// there is no second parse of a different element.
    ///
    /// Two independent gates:
    ///
    /// 1. **Absolute freshness.** `Created` must not be in the future beyond
    ///    `created_clock_skew_seconds` and must not be older than
    ///    `created_max_age_seconds + skew`. Without this, a captured token stays
    ///    digest-valid forever and only the replay cache's finite TTL stands
    ///    between an attacker and a successful resubmission.
    /// 2. **Timestamp binding.** The outer `Timestamp/Created` is resolved with
    ///    the same element resolver `validate_timestamp` uses, so the instant
    ///    bound here is the instant that was independently validated — the two
    ///    cannot be made to disagree by element ordering or by a decoy
    ///    `<Timestamp>`. The two `Created` values must agree within
    ///    `created_max_timestamp_divergence_seconds`, and the UsernameToken
    ///    instant must not fall past an outer `Expires`. That is what stops a
    ///    captured UsernameToken from being paired with a freshly minted outer
    ///    Timestamp: moving the outer instant no longer moves the inner one, and
    ///    moving the inner one invalidates the captured digest.
    ///
    /// When `require_timestamp_binding` is true (default) a missing or
    /// unparsable outer `Timestamp/Created` is a rejection, so the binding
    /// cannot be dropped by simply omitting the element.
    fn validate_username_token_created(
        &self,
        security: Node<'_, '_>,
        created_raw: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let created = parse_ws_datetime(created_raw.trim()).ok_or_else(|| {
            // Never echo the value: it is a digest input under attacker control
            // and is bound to the shared secret.
            "WS-Security: UsernameToken Created is not a valid dateTime".to_string()
        })?;

        let skew = self.ut_created_clock_skew;
        if created > now + skew {
            return Err("WS-Security: UsernameToken Created is in the future".to_string());
        }
        if now - created > self.ut_created_max_age + skew {
            return Err(format!(
                "WS-Security: UsernameToken Created is too old (max age {}s)",
                self.ut_created_max_age_seconds
            ));
        }

        let outer = match Self::timestamp_node(security)? {
            Some(ts_node) => match Self::timestamp_instant(ts_node, "Created")? {
                Some(outer_created) => {
                    Some((outer_created, Self::timestamp_instant(ts_node, "Expires")?))
                }
                None => None,
            },
            None => None,
        };

        let Some((outer_created, outer_expires)) = outer else {
            return if self.require_timestamp_binding {
                Err(
                    "WS-Security: PasswordDigest requires a Timestamp with a valid Created value \
                     to bind the UsernameToken against"
                        .to_string(),
                )
            } else {
                Ok(())
            };
        };

        let divergence = if created >= outer_created {
            created - outer_created
        } else {
            outer_created - created
        };
        if divergence > self.ut_created_max_timestamp_divergence {
            return Err(format!(
                "WS-Security: UsernameToken Created diverges from the Timestamp Created by more \
                 than {}s",
                self.ut_created_max_timestamp_divergence_seconds
            ));
        }
        if let Some(outer_expires) = outer_expires {
            let outer_expires_with_skew =
                outer_expires.checked_add_signed(skew).ok_or_else(|| {
                    "WS-Security: Timestamp Expires is outside the supported range".to_string()
                })?;
            if created > outer_expires_with_skew {
                return Err(
                    "WS-Security: UsernameToken Created is past the Timestamp Expires".to_string(),
                );
            }
        }

        Ok(())
    }

    async fn validate_username_token(
        &self,
        security: Node<'_, '_>,
        now: DateTime<Utc>,
    ) -> Result<String, UsernameTokenError> {
        let structural = |message: &str| UsernameTokenError::Structural(message.to_string());
        let ut_node = unique_ns_child(security, WSSE_NAMESPACE_URI, "UsernameToken", "WS-Security")
            .map_err(UsernameTokenError::Structural)?
            .ok_or_else(|| structural("WS-Security: missing UsernameToken element"))?;

        let username_node = unique_ns_child(ut_node, WSSE_NAMESPACE_URI, "Username", "WS-Security")
            .map_err(UsernameTokenError::Structural)?
            .ok_or_else(|| structural("WS-Security: UsernameToken missing Username element"))?;
        let username = element_text(username_node)
            .ok_or_else(|| structural("WS-Security: UsernameToken Username element is empty"))?;

        let password_element =
            unique_ns_child(ut_node, WSSE_NAMESPACE_URI, "Password", "WS-Security")
                .map_err(UsernameTokenError::Structural)?
                .ok_or_else(|| structural("WS-Security: UsernameToken missing Password element"))?;

        let password_value = element_text(password_element)
            .ok_or_else(|| structural("WS-Security: Password element has no content"))?;

        // The verification mode is dictated solely by the operator-configured
        // `password_type`, NEVER by the client-supplied `Type` attribute.
        // Letting the wire value select the mode lets an attacker who knows the
        // plaintext credential downgrade a configured PasswordDigest policy
        // (Nonce / Created / replay protection) to plain PasswordText by sending
        // `Type="...#PasswordText"`. If a recognized `Type` attribute is present
        // it must agree with the configured policy; a mismatch is rejected.
        if let Some(type_attr) = password_element.attribute("Type") {
            let wire_type =
                if type_attr.contains("PasswordDigest") || type_attr == PASSWORD_DIGEST_TYPE {
                    Some(PasswordType::PasswordDigest)
                } else if type_attr.contains("PasswordText") || type_attr == PASSWORD_TEXT_TYPE {
                    Some(PasswordType::PasswordText)
                } else {
                    // Unrecognized Type value — fall through to the configured
                    // policy rather than guessing a verification mode.
                    None
                };
            if let Some(wire_type) = wire_type
                && wire_type != self.password_type
            {
                return Err(UsernameTokenError::Structural(
                    "WS-Security: Password Type does not match the configured password_type"
                        .to_string(),
                ));
            }
        }
        let effective_type = self.password_type;

        // Always run verification against either the matched credential or
        // process-local dummy material so lookup misses do not skip crypto work
        // and do not produce a distinct public failure.
        let cred = self.credentials.iter().find(|c| c.username == username);
        let password_material = cred
            .map(|c| c.password.as_str())
            .unwrap_or(self.dummy_password.as_str());
        let username_known = cred.is_some();

        match effective_type {
            PasswordType::PasswordText => {
                // Hash the attacker input once, then compare fixed-width
                // digests. `constant_time_eq` intentionally returns early on a
                // length mismatch, so comparing plaintext directly would make
                // the dummy path observably different whenever the configured
                // password and dummy material have different lengths.
                let supplied_hash = sha256_array(password_value.as_bytes());
                let expected_hash = cred
                    .map(|credential| &credential.password_text_hash)
                    .unwrap_or(&self.dummy_password_text_hash);
                let matched = constant_time_eq(&supplied_hash, expected_hash);
                // Dummy material is timing padding only and must never establish
                // identity for an unregistered username.
                if username_known && matched {
                    Ok(username)
                } else {
                    Err(UsernameTokenError::InvalidCredentials)
                }
            }
            PasswordType::PasswordDigest => {
                // Structural Nonce/Created requirements are enforced before the
                // known/unknown credential branch so missing digest inputs cannot
                // themselves become a username oracle.
                // PasswordDigest = Base64(SHA-1(nonce + created + password))
                let nonce_node =
                    unique_ns_child(ut_node, WSSE_NAMESPACE_URI, "Nonce", "WS-Security")
                        .map_err(UsernameTokenError::Structural)?
                        .ok_or_else(|| {
                            structural("WS-Security: PasswordDigest requires Nonce element")
                        })?;
                let nonce_b64_raw = element_text(nonce_node)
                    .ok_or_else(|| structural("WS-Security: Nonce element is empty"))?;

                // One canonical form for both the digest input and the replay
                // cache key (`element_text` already trims; being explicit keeps
                // the two derivations from drifting apart). The length ceiling
                // is enforced on the *encoded* value before Base64 decoding, so
                // an oversized nonce never allocates a decode buffer and is
                // never retained.
                let nonce_b64 = nonce_b64_raw.trim();
                if nonce_b64.len() > self.max_nonce_encoded_length {
                    return Err(UsernameTokenError::Structural(
                        "WS-Security: Nonce exceeds the maximum permitted length".to_string(),
                    ));
                }

                let nonce_bytes = BASE64.decode(nonce_b64).map_err(|e| {
                    UsernameTokenError::Structural(format!(
                        "WS-Security: invalid Nonce base64 encoding: {}",
                        e
                    ))
                })?;

                let created_node =
                    unique_ns_child(ut_node, WSU_NAMESPACE_URI, "Created", "WS-Security")
                        .map_err(UsernameTokenError::Structural)?
                        .ok_or_else(|| {
                            structural("WS-Security: PasswordDigest requires Created element")
                        })?;
                let created = element_text(created_node)
                    .ok_or_else(|| structural("WS-Security: Created element is empty"))?;

                // Freshness + outer-Timestamp binding are structural: the
                // outcome does not depend on whether the principal exists, so
                // running them here (before the known/unknown branch) cannot
                // become a username oracle, and it keeps a stale token from
                // reaching digest verification at all.
                self.validate_username_token_created(security, &created, now)
                    .map_err(UsernameTokenError::Structural)?;

                // Compute expected digest: SHA-1(nonce + created + password)
                let mut data =
                    Vec::with_capacity(nonce_bytes.len() + created.len() + password_material.len());
                data.extend_from_slice(&nonce_bytes);
                data.extend_from_slice(created.as_bytes());
                data.extend_from_slice(password_material.as_bytes());

                let computed = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
                let expected_b64 = BASE64.encode(computed.as_ref());

                // Constant-time compare for consistency with the PasswordText
                // path (the digest is derived from the shared secret or dummy).
                let matched =
                    constant_time_eq(password_value.trim().as_bytes(), expected_b64.as_bytes());
                if username_known && matched {
                    // Only a successfully verified principal may consume a
                    // nonce. Recording attacker-controlled failed attempts
                    // would let an unknown-user or wrong-password request
                    // poison a victim's nonce before the legitimate request
                    // arrives. The atomic entry check also prevents two
                    // concurrent valid requests from both accepting it.
                    self.claim_nonce(nonce_b64)
                        .await
                        .map_err(UsernameTokenError::Structural)?;
                    Ok(username)
                } else {
                    Err(UsernameTokenError::InvalidCredentials)
                }
            }
        }
    }

    // ── Nonce replay protection ─────────────────────────────────────────

    /// Stable, fixed-cardinality failure classes for replay-state outcomes.
    /// The attacker-supplied nonce is never interpolated into a log line or a
    /// client-visible body.
    const NONCE_TOO_LONG_CLASS: &'static str = "nonce_too_long";
    const NONCE_STATE_SATURATED_CLASS: &'static str = "nonce_state_saturated";
    const NONCE_SHARED_BACKEND_UNAVAILABLE_CLASS: &'static str = "nonce_shared_backend_unavailable";

    /// Shared-backend outage is a replay-protection outage, so it fails closed
    /// exactly like local exhaustion. There is deliberately no "degrade to
    /// process-local" knob: a per-replica fallback would silently reinstate the
    /// bypass the shared backend exists to close.
    fn shared_backend_unavailable() -> String {
        warn!(
            failure_class = Self::NONCE_SHARED_BACKEND_UNAVAILABLE_CLASS,
            "soap_ws_security: shared replay backend is unavailable"
        );
        "WS-Security: replay protection backend is unavailable".to_string()
    }

    fn nonce_too_long() -> String {
        warn!(
            failure_class = Self::NONCE_TOO_LONG_CLASS,
            "soap_ws_security: Nonce exceeds the maximum permitted length"
        );
        "WS-Security: Nonce exceeds the maximum permitted length".to_string()
    }

    /// Claim `nonce` for exactly one authenticated request inside the fixed
    /// retention horizon, on whichever backend the operator declared.
    ///
    /// Reached only after the PasswordDigest has verified, so untrusted input
    /// never mutates, consumes, or evicts replay state.
    async fn claim_nonce(&self, nonce: &str) -> Result<(), String> {
        match &self.nonce_backend {
            NonceReplayBackend::Process(_) => self.check_nonce_replay(nonce),
            NonceReplayBackend::Shared(client) => self.claim_nonce_shared(client, nonce).await,
        }
    }

    /// Claim a SAML assertion id for exactly one request inside the fixed
    /// retention horizon (GHSA-f44p-hfqr-cvcc).
    ///
    /// The claim key binds the issuer to the id, so two IdPs cannot collide and
    /// one cannot burn the other's ids. Retention is the same schema-wide
    /// [`NONCE_CLAIM_RETENTION_SECONDS`] horizon, which a compile-time
    /// assertion proves dominates
    /// `MAX_SAML_ASSERTION_LIFETIME_SECONDS + 2 * MAX_CLOCK_SKEW_SECONDS` — the
    /// widest span any admissible SAML policy can accept one unchanged
    /// assertion over — so no reload generation can expire a claim while a
    /// later generation would still accept the assertion.
    ///
    /// The claim scope is exactly what `nonce.replay_scope` declares. `process`
    /// is single-replica by construction and makes no cross-replica claim;
    /// `shared` is one atomic Redis `SET NX EX` across every replica. There is
    /// deliberately no fallback between them: a per-replica fallback would
    /// silently reinstate "one replay per replica".
    async fn claim_saml_assertion(&self, issuer: &str, assertion_id: &str) -> Result<(), String> {
        // The claim key is a fixed-width digest, never the issuer or the
        // assertion id: both are credential-adjacent values that would
        // otherwise reach a Redis keyspace, `MONITOR`, `SLOWLOG`, and the Redis
        // client's error logging.
        let mut material = Vec::with_capacity(issuer.len() + assertion_id.len() + 32);
        material.extend_from_slice(b"soap-ws-security/saml-assertion/v1|");
        material.extend_from_slice(issuer.as_bytes());
        material.push(0);
        material.extend_from_slice(assertion_id.as_bytes());
        let claim_key = sha256_hex_lower(&material);

        match &self.nonce_backend {
            NonceReplayBackend::Process(_) => self
                .check_replay_claim_at(&saml_process_claim_key(&claim_key), Instant::now())
                .map_err(|error| {
                    if error == REPLAY_DETECTED_MESSAGE {
                        SAML_REPLAY_DETECTED_MESSAGE.to_string()
                    } else {
                        error
                    }
                }),
            NonceReplayBackend::Shared(client) => {
                if !client.is_available() {
                    return Err(Self::shared_backend_unavailable());
                }
                let key = client.make_key(&["saml-assertion", claim_key.as_str()]);
                match client
                    .set_bytes_nx_with_expire(
                        &key,
                        SHARED_NONCE_CLAIM_RECORD,
                        self.shared_claim_retention_seconds(),
                    )
                    .await
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(SAML_REPLAY_DETECTED_MESSAGE.to_string()),
                    Err(()) => Err(Self::shared_backend_unavailable()),
                }
            }
        }
    }

    /// TTL written with a shared claim: the fixed
    /// [`NONCE_CLAIM_RETENTION_SECONDS`] horizon, identical on every replica and
    /// in every generation.
    ///
    /// **Across generations.** Redis owns a key's expiry from the moment it is
    /// written, and one atomic `SET NX EX` can neither shorten nor extend a key
    /// it did not create. A per-generation TTL would therefore be unfixable in
    /// the widening direction: keys written under an old, shorter TTL expire
    /// early no matter what a later generation declares, and "raise the TTL,
    /// drain, then widen the window" is operator procedure, not something the
    /// gateway can enforce. Writing one schema-wide constant removes the
    /// asymmetry instead of documenting around it — every key that already
    /// exists, whichever generation or replica wrote it, already carries the
    /// full horizon, so `SET NX` declining to touch it is exactly correct.
    fn shared_claim_retention_seconds(&self) -> u64 {
        NONCE_CLAIM_RETENTION_SECONDS
    }

    /// Cross-replica claim: one atomic Redis `SET NX EX`.
    ///
    /// `SET key value NX EX ttl` is a single server-side operation, so among any
    /// number of concurrent requests on any number of replicas exactly one
    /// observes `Ok(true)` and every other observes `Ok(false)`. There is no
    /// read-then-write window to race, and no process-local pre-check that could
    /// answer differently from the shared truth.
    ///
    /// The key is `SHA-256(nonce)` in lowercase hex, never the nonce: Redis keys
    /// appear in `MONITOR`, in `SLOWLOG`, and in this client's own error logging
    /// (`key = %key`), and the nonce is a digest input bound to the shared
    /// secret. The stored value is a fixed non-secret marker — the claim is
    /// proven by the key existing, so nothing derived from credentials is
    /// written.
    async fn claim_nonce_shared(
        &self,
        client: &RedisRateLimitClient,
        nonce: &str,
    ) -> Result<(), String> {
        if nonce.len() > self.max_nonce_encoded_length {
            return Err(Self::nonce_too_long());
        }
        if !client.is_available() {
            return Err(Self::shared_backend_unavailable());
        }
        let key = client.make_key(&[sha256_hex_lower(nonce.as_bytes()).as_str()]);
        let ttl_seconds = self.shared_claim_retention_seconds();
        let claimed = client
            .set_bytes_nx_with_expire(&key, SHARED_NONCE_CLAIM_RECORD, ttl_seconds)
            .await;
        match claimed {
            Ok(true) => Ok(()),
            Ok(false) => Err(REPLAY_DETECTED_MESSAGE.to_string()),
            Err(()) => Err(Self::shared_backend_unavailable()),
        }
    }

    fn nonce_state_saturated() -> String {
        warn!(
            failure_class = Self::NONCE_STATE_SATURATED_CLASS,
            "soap_ws_security: replay protection state is at capacity"
        );
        "WS-Security: replay protection state is at capacity".to_string()
    }

    fn nonce_state_saturated_after_unlock(
        state: std::sync::MutexGuard<'_, NonceReplayState>,
    ) -> String {
        drop(state);
        Self::nonce_state_saturated()
    }

    fn nonce_age_seconds(now: Instant, inserted_at: Instant) -> u64 {
        now.checked_duration_since(inserted_at)
            .map_or(0, |age| age.as_secs())
    }

    /// Check if a nonce has been seen before within the fixed retention window,
    /// inserting it when it is not a replay.
    ///
    /// The cache is bounded on three independent axes so a caller cannot turn
    /// replay state into a memory or CPU sink: per-nonce encoded length, total
    /// retained entries, and total retained key bytes. Lookup is expected O(1)
    /// and every age-index update is O(log n). At capacity, at most
    /// `NONCE_MAX_MAINTENANCE_ENTRIES` exact oldest entries are examined; there
    /// is no lookup-map scan and no stale FIFO that can grow beyond the entry
    /// cap.
    ///
    /// **Live entries are never evicted.** Only entries older than the fixed
    /// [`NONCE_CLAIM_RETENTION_SECONDS`] horizon can be reclaimed, so every nonce
    /// claimed inside its window stays replay-protected for the whole window —
    /// including against any other reload generation, all of which measure
    /// against the same constant. If bounded expiry
    /// reclamation cannot free entry *and* byte room, this returns the fixed
    /// saturation rejection without admitting the nonce — the cache never
    /// unprotects an already-claimed nonce in order to accept a new one.
    ///
    /// **Concurrency.** Encoded-length rejection and all XML/base64/credential/
    /// crypto work run outside the lock. Admission, exact-oldest maintenance,
    /// insert/refresh, and byte accounting share one mutex held only for those
    /// security-state updates, so concurrent fresh claims cannot all observe
    /// room and then overshoot either hard cap. Same-key races resolve under
    /// the lock: an in-TTL hit is a replay (no reservation); an expired hit
    /// refreshes the same shared key in place without changing count/bytes.
    /// Lock poison, checked-arithmetic failure, or map/index drift all fail
    /// closed with the fixed saturation class and never recover through the
    /// poisoned state.
    ///
    /// **Retention.** The window an entry is measured against is the fixed
    /// [`NONCE_CLAIM_RETENTION_SECONDS`] horizon — no per-instance and no
    /// per-scope value is consulted. Because that constant is the maximum over
    /// the *whole admissible schema*, a claim outlives its token under the
    /// claiming generation, under every other generation currently sharing the
    /// scope, and under every generation that may be admitted later, including
    /// one that widens the acceptance window long after a per-generation
    /// retention would have expired the entry.
    ///
    /// **Scope.** This is the `nonce.replay_scope = "process"` path. The state
    /// it consults is registered under a stable `{namespace}|{plugin-config-id}`
    /// key, so it survives reload generations, but it is process-local by
    /// construction and makes no cross-replica claim. A `shared`-scope instance
    /// has no process-local state and fails closed here rather than answering
    /// from an empty map.
    pub fn check_nonce_replay(&self, nonce: &str) -> Result<(), String> {
        self.check_nonce_replay_at(nonce, Instant::now())
    }

    fn check_nonce_replay_at(&self, nonce: &str, now: Instant) -> Result<(), String> {
        // Attacker-controlled length compare only — outside the admission lock.
        if nonce.len() > self.max_nonce_encoded_length {
            return Err(Self::nonce_too_long());
        }
        self.check_replay_claim_at(&nonce_process_claim_key(nonce), now)
    }

    /// Process-local single-use claim for an already-namespaced key.
    ///
    /// Shared by PasswordDigest nonces and SAML assertion ids; the caller
    /// supplies a key carrying its own claim-kind prefix so the two classes can
    /// never collide in the one process-global map.
    fn check_replay_claim_at(&self, nonce: &str, now: Instant) -> Result<(), String> {
        let NonceReplayBackend::Process(replay_state) = &self.nonce_backend else {
            // A shared-scope instance has no process-local state to consult;
            // answering from an empty local map would be a silent bypass.
            return Err(Self::shared_backend_unavailable());
        };

        let mut state = match replay_state.lock() {
            Ok(state) => state,
            Err(_) => return Err(Self::nonce_state_saturated()),
        };
        // Retention is the fixed schema-wide horizon, never a per-instance or
        // per-scope value: the state is shared across reload generations, so any
        // configured retention would let some generation expire (or refresh,
        // which re-admits) a claim another generation still needs — including a
        // future one that widens its acceptance window.
        let retention_seconds = NONCE_CLAIM_RETENTION_SECONDS;
        state.last_expired_removals = 0;

        if !state.structurally_consistent() {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }

        // Same-key path first: replay / in-place refresh must not consume a new
        // entry or byte reservation, and must not be rejected as saturated
        // merely because the cache is otherwise full.
        let existing_age_key = state.cache.get(nonce).map(|entry| entry.age_key);
        if let Some(age_key) = existing_age_key {
            let indexed_nonce_matches = state
                .age_index
                .get(&age_key)
                .is_some_and(|indexed_nonce| indexed_nonce.as_ref() == nonce);
            if !indexed_nonce_matches {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
            if Self::nonce_age_seconds(now, age_key.0) < retention_seconds {
                return Err(REPLAY_DETECTED_MESSAGE.to_string());
            }

            let Some(new_age_key) = state.allocate_age_key(now) else {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            };
            let shared_nonce = match state.age_index.remove(&age_key) {
                Some(shared_nonce) => shared_nonce,
                None => return Err(Self::nonce_state_saturated_after_unlock(state)),
            };
            if state
                .age_index
                .insert(new_age_key, Arc::clone(&shared_nonce))
                .is_some()
            {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
            let Some(entry) = state.cache.get_mut(shared_nonce.as_ref()) else {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            };
            entry.age_key = new_age_key;
            return Ok(());
        }

        let incoming_bytes = charged_claim_key_bytes(nonce);
        if !state.has_capacity(
            incoming_bytes,
            self.max_nonce_cache_size,
            self.max_nonce_cache_bytes,
        ) {
            let made_room = match Self::reclaim_expired_nonce_room_locked(
                &mut state,
                incoming_bytes,
                self.max_nonce_cache_size,
                self.max_nonce_cache_bytes,
                retention_seconds,
                now,
            ) {
                Ok(made_room) => made_room,
                Err(()) => {
                    return Err(Self::nonce_state_saturated_after_unlock(state));
                }
            };
            if !made_room {
                return Err(Self::nonce_state_saturated_after_unlock(state));
            }
        }

        let Some(retained_key_bytes) = state.retained_key_bytes.checked_add(incoming_bytes) else {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        };
        if retained_key_bytes > self.max_nonce_cache_bytes
            || state.cache.len() >= self.max_nonce_cache_size
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        let Some(age_key) = state.allocate_age_key(now) else {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        };

        let shared_nonce: Arc<str> = Arc::from(nonce);
        if state
            .age_index
            .insert(age_key, Arc::clone(&shared_nonce))
            .is_some()
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        if state
            .cache
            .insert(shared_nonce, NonceEntry { age_key })
            .is_some()
        {
            return Err(Self::nonce_state_saturated_after_unlock(state));
        }
        state.retained_key_bytes = retained_key_bytes;
        Ok(())
    }

    /// Reclaim capacity for one incoming nonce using **only** entries proven
    /// older than the fixed [`NONCE_CLAIM_RETENTION_SECONDS`] horizon, walking
    /// the ordered age index from the oldest end and never touching the lookup
    /// map.
    ///
    /// The age index is ordered by `(insertion instant, sequence)`, so the first
    /// key is always the oldest live-or-expired entry. Once that head is inside
    /// the TTL every remaining entry is too, and the walk stops: an unexpired
    /// nonce is never removed to make space. Each removal commits immediately
    /// and is charged against a per-request `NONCE_MAX_MAINTENANCE_ENTRIES`
    /// budget, so hostile traffic cannot turn maintenance into a CPU sink.
    ///
    /// Returns `Ok(true)` only when both hard caps can now accommodate
    /// `incoming_bytes`. `Ok(false)` means the cache is genuinely full of live
    /// replay coverage (or the bounded budget ran out) and the caller must fail
    /// closed. `Err(())` reports impossible map/index drift, which also fails
    /// closed.
    fn reclaim_expired_nonce_room_locked(
        state: &mut NonceReplayState,
        incoming_bytes: usize,
        max_entries: usize,
        max_bytes: usize,
        ttl_seconds: u64,
        now: Instant,
    ) -> Result<bool, ()> {
        while !state.has_capacity(incoming_bytes, max_entries, max_bytes)
            && state.last_expired_removals < NONCE_MAX_MAINTENANCE_ENTRIES
        {
            // An empty index with no capacity is impossible for admitted
            // configuration (`max_encoded_length <= max_total_cache_bytes` and
            // `max_cache_size >= 1`), so treat it as drift and fail closed.
            let Some((&age_key, nonce)) = state.age_index.first_key_value() else {
                return Err(());
            };
            if !state.age_entry_matches(&age_key, nonce) {
                return Err(());
            }
            if Self::nonce_age_seconds(now, age_key.0) < ttl_seconds {
                // Oldest retained nonce is still inside its replay window, and
                // every newer entry is too. Reclaim nothing.
                break;
            }
            state.remove_age_entry(&age_key)?;
            state.last_expired_removals += 1;
        }

        Ok(state.has_capacity(incoming_bytes, max_entries, max_bytes))
    }

    // These seams are consumed through `lib::_test_support`; the binary target
    // compiles the shared plugin module without that facade.
    #[allow(dead_code)]
    pub(crate) fn check_nonce_replay_at_for_tests(
        &self,
        nonce: &str,
        now: Instant,
    ) -> Result<(), String> {
        self.check_nonce_replay_at(nonce, now)
    }

    #[allow(dead_code)]
    pub(crate) fn nonce_replay_observation_for_tests(
        &self,
    ) -> Result<NonceReplayObservationForTests, String> {
        let NonceReplayBackend::Process(replay_state) = &self.nonce_backend else {
            return Err("soap_ws_security: replay observation is process-scope only".to_string());
        };
        let state = replay_state
            .lock()
            .map_err(|_| "soap_ws_security: nonce replay observation unavailable".to_string())?;
        let recomputed_key_bytes = state.cache.keys().try_fold(0usize, |total, nonce| {
            total.checked_add(charged_claim_key_bytes(nonce))
        });
        let Some(recomputed_key_bytes) = recomputed_key_bytes else {
            return Err(
                "soap_ws_security: nonce replay observation accounting overflow".to_string(),
            );
        };
        let shared_key_entries = state
            .age_index
            .iter()
            .filter(|item| {
                let (age_key, indexed_nonce) = *item;
                state
                    .cache
                    .get_key_value(indexed_nonce.as_ref())
                    .is_some_and(|(cache_nonce, entry)| {
                        entry.age_key == *age_key && Arc::ptr_eq(cache_nonce, indexed_nonce)
                    })
            })
            .count();

        Ok(NonceReplayObservationForTests {
            entry_count: state.cache.len(),
            age_index_entry_count: state.age_index.len(),
            retained_key_bytes: state.retained_key_bytes,
            recomputed_key_bytes,
            shared_key_entries,
            last_expired_removals: state.last_expired_removals,
            max_maintenance_entries: NONCE_MAX_MAINTENANCE_ENTRIES,
            retention_seconds: NONCE_CLAIM_RETENTION_SECONDS,
        })
    }

    /// The inner-`Created` admission decision at an explicit instant, so the
    /// exact endpoints of the acceptance interval can be pinned without a
    /// wall-clock race.
    #[allow(dead_code)]
    pub(crate) fn username_token_created_outcome_for_tests(
        &self,
        security_block: &str,
        created_raw: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        // `security_block` is the *inner* content of a `wsse:Security` header;
        // the wrapper (and its namespace bindings) is supplied here so a test
        // fixture cannot accidentally exercise a differently-namespaced shape.
        let wrapped = format!(
            r#"<wsse:Security xmlns:wsse="{WSSE_NAMESPACE_URI}" xmlns:wsu="{WSU_NAMESPACE_URI}">{security_block}</wsse:Security>"#
        );
        let document = parse_bounded_xml(&wrapped, "test Security block")?;
        self.validate_username_token_created(document.root_element(), created_raw, now)
    }

    /// Media-type classification outcome for external tests as a stable string:
    /// `"xml"` / `"xop"` / `"mtom"` for a governed representation,
    /// `"pass_through"`, or `"reject:<status>:<class>"`.
    #[allow(dead_code)]
    pub(crate) fn classify_request_for_tests(&self, content_type: Option<&str>) -> String {
        match self.classify_request(content_type) {
            SoapRequestDisposition::Governed(SoapMediaClass::Mtom { .. }) => "mtom".to_string(),
            SoapRequestDisposition::Governed(SoapMediaClass::Xop) => "xop".to_string(),
            SoapRequestDisposition::Governed(SoapMediaClass::Xml) => "xml".to_string(),
            SoapRequestDisposition::PassThrough => "pass_through".to_string(),
            SoapRequestDisposition::Reject(rejection) => {
                let status = rejection.status_code();
                format!("reject:{status}:{}", rejection.class())
            }
        }
    }

    /// One SAML assertion single-use claim, so replay across generations and
    /// instances can be pinned without a live message.
    #[allow(dead_code)]
    pub(crate) async fn claim_saml_assertion_for_tests(
        &self,
        issuer: &str,
        assertion_id: &str,
    ) -> Result<(), String> {
        self.claim_saml_assertion(issuer, assertion_id).await
    }

    /// The TTL a shared (Redis) claim is written with, without needing a live
    /// server. Same value `claim_nonce_shared` passes to `SET NX EX`.
    #[allow(dead_code)]
    pub(crate) fn shared_claim_retention_seconds_for_tests(&self) -> Result<u64, String> {
        match &self.nonce_backend {
            NonceReplayBackend::Shared(_) => Ok(self.shared_claim_retention_seconds()),
            NonceReplayBackend::Process(_) => {
                Err("soap_ws_security: shared claim retention is shared-scope only".to_string())
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn corrupt_nonce_age_index_for_tests(&self) -> Result<(), String> {
        let NonceReplayBackend::Process(replay_state) = &self.nonce_backend else {
            return Err("soap_ws_security: replay test state is process-scope only".to_string());
        };
        let mut state = replay_state
            .lock()
            .map_err(|_| "soap_ws_security: nonce replay test state unavailable".to_string())?;
        let age_key = state
            .age_index
            .first_key_value()
            .map(|(age_key, _)| *age_key)
            .ok_or_else(|| "soap_ws_security: nonce replay test state is empty".to_string())?;
        if state.age_index.remove(&age_key).is_none() {
            return Err("soap_ws_security: nonce replay test corruption failed".to_string());
        }
        Ok(())
    }

    /// Preserve index cardinality while breaking its cache mapping (test
    /// support). This distinguishes full reclamation validation from the O(1)
    /// request-path cardinality guard.
    #[allow(dead_code)]
    pub(crate) fn corrupt_nonce_age_index_value_for_tests(&self) -> Result<(), String> {
        let NonceReplayBackend::Process(replay_state) = &self.nonce_backend else {
            return Err("soap_ws_security: replay test state is process-scope only".to_string());
        };
        let mut state = replay_state
            .lock()
            .map_err(|_| "soap_ws_security: nonce replay test state unavailable".to_string())?;
        let age_key = state
            .age_index
            .first_key_value()
            .map(|(age_key, _)| *age_key)
            .ok_or_else(|| "soap_ws_security: nonce replay test state is empty".to_string())?;
        state
            .age_index
            .insert(age_key, Arc::<str>::from("same-cardinality-index-drift"));
        Ok(())
    }

    /// Poison this instance's process replay-scope mutex (test support).
    #[allow(dead_code)]
    pub(crate) fn poison_nonce_replay_state_for_tests(&self) -> Result<(), String> {
        let NonceReplayBackend::Process(replay_state) = &self.nonce_backend else {
            return Err("soap_ws_security: replay test state is process-scope only".to_string());
        };
        let state = Arc::clone(replay_state);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.lock().expect("lock before poison");
            panic!("soap_ws_security: intentional nonce replay state poison for tests");
        }));
        Ok(())
    }

    // ── X.509 signature verification ────────────────────────────────────

    /// Verify the WS-Security X.509 message signature.
    ///
    /// Returns the request principal the trusted certificate stands for.
    ///
    /// **Ordering (GHSA-9g4v-h9hm-846r).** Certificate trust and
    /// `SignatureValue`-over-`SignedInfo` are settled *before* a single
    /// attacker-selected `<Reference>` is resolved, canonicalized, or digested.
    /// Trust is a fixed-size fingerprint comparison and `SignedInfo` is a small
    /// bounded subtree, so an untrusted or forged signature is refused after
    /// constant work no matter how the References are shaped. Previously every
    /// declared Reference drove two full-envelope id scans plus a subtree
    /// canonicalization first, so 64 references to one large element multiplied
    /// a 10 MiB body into gigabytes of unauthenticated work.
    ///
    /// **Coverage (GHSA-3mwq-c8j6-9xhp).** A valid signature is not enough: a
    /// Reference must resolve uniquely to the *namespace-correct SOAP Body the
    /// backend will consume*, so a trusted signature over only the Timestamp
    /// can no longer authorize an arbitrary rewritten operation.
    fn validate_x509_signature<'a, 'i>(
        &self,
        structure: &SoapEnvelopeStructure<'a, 'i>,
        security: Node<'a, 'i>,
        id_index: &DocumentIdIndex<'a, 'i>,
        envelope: &str,
        budget: &mut WorkBudget,
    ) -> Result<&str, String> {
        let sig_node =
            unique_ns_child(security, XMLDSIG_NAMESPACE_URI, "Signature", "WS-Security")?
                .ok_or_else(|| "WS-Security: missing Signature element".to_string())?;
        let signed_info_node =
            unique_ns_child(sig_node, XMLDSIG_NAMESPACE_URI, "SignedInfo", "WS-Security")?
                .ok_or_else(|| "WS-Security: Signature missing SignedInfo element".to_string())?;

        // Determine signature algorithm
        let sig_method = unique_ns_child(
            signed_info_node,
            XMLDSIG_NAMESPACE_URI,
            "SignatureMethod",
            "WS-Security",
        )?
        .ok_or_else(|| "WS-Security: SignedInfo missing SignatureMethod".to_string())?;
        let sig_algorithm_uri = sig_method.attribute("Algorithm").ok_or_else(|| {
            "WS-Security: SignatureMethod missing Algorithm attribute".to_string()
        })?;

        let sig_algorithm = match sig_algorithm_uri {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self.allowed_signature_algorithms.contains(&sig_algorithm) {
            return Err(format!(
                "WS-Security: signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        let canonicalization = parse_signed_info_canonicalization(signed_info_node, "WS-Security")?;

        // Extract SignatureValue
        let sig_value_node = unique_ns_child(
            sig_node,
            XMLDSIG_NAMESPACE_URI,
            "SignatureValue",
            "WS-Security",
        )?
        .ok_or_else(|| "WS-Security: Signature missing SignatureValue".to_string())?;
        let sig_value_b64 = sig_value_node
            .text()
            .ok_or_else(|| "WS-Security: SignatureValue is empty".to_string())?;

        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: invalid SignatureValue base64: {}", e))?;

        // ── Authenticate the signer BEFORE resolving any Reference ──────
        let cert_der = self.extract_signing_cert(security, sig_node)?;
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();
        let trusted = self
            .trusted_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);
        let Some(trusted) = trusted else {
            return Err("WS-Security: signing certificate is not trusted".to_string());
        };

        // Verify the signature over the canonicalized SignedInfo node. Parsing
        // the full envelope preserves namespace declarations inherited from
        // Signature/Security/Envelope that are absent from the wire substring.
        let signed_info_bytes = exclusive_canonicalize(
            envelope,
            signed_info_node,
            &canonicalization.inclusive_prefixes,
            None,
            budget,
        )?;

        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key =
            ring_sig::UnparsedPublicKey::new(verify_algorithm, &trusted.public_key_der);

        public_key
            .verify(&signed_info_bytes, &sig_bytes)
            .map_err(|_| "WS-Security: signature verification failed".to_string())?;

        // ── Authenticated. Only now is Reference work performed ─────────
        let coverage = self.verify_reference_digests(
            signed_info_node,
            security,
            sig_node,
            &ReferenceDigestDocument {
                structure,
                id_index,
                envelope,
            },
            budget,
        )?;

        // A signature that does not commit to the operation the backend will
        // execute authenticates nothing about that operation.
        if !coverage.covers_body {
            return Err(
                "WS-Security: signature does not cover the SOAP Body — a Reference must resolve \
                 uniquely to the backend-visible Body element"
                    .to_string(),
            );
        }

        // Check that Timestamp is signed (if required)
        if self.require_signed_timestamp {
            Self::verify_timestamp_is_signed(security, &coverage)?;
        }

        debug!("soap_ws_security: X.509 signature verified successfully");
        Ok(trusted.principal.as_str())
    }

    fn verify_reference_digests<'a, 'i>(
        &self,
        signed_info: Node<'a, 'i>,
        security: Node<'a, 'i>,
        signature_node: Node<'a, 'i>,
        document: &ReferenceDigestDocument<'_, 'a, 'i>,
        budget: &mut WorkBudget,
    ) -> Result<ReferenceCoverage, String> {
        let references: Vec<Node<'a, 'i>> = signed_info
            .children()
            .filter(|node| node.has_tag_name((XMLDSIG_NAMESPACE_URI, "Reference")))
            .collect();
        // Bound authenticated work. References are resolved only after the
        // signer is trusted, so this is no longer an unauthenticated
        // amplification budget — but the profiles Ferrum supports (Timestamp,
        // Body, a small number of headers) never approach it.
        if references.len() > MAX_SIGNED_REFERENCES {
            return Err(format!(
                "WS-Security: too many Signature References (> {})",
                MAX_SIGNED_REFERENCES
            ));
        }

        // Collect and de-duplicate the fragment ids first, so the raw-attribute
        // uniqueness guard is one bounded pass over the envelope for the whole
        // SignedInfo rather than one pass per Reference.
        let mut reference_ids: Vec<&str> = Vec::with_capacity(references.len());
        for reference in &references {
            let uri = reference
                .attribute("URI")
                .ok_or_else(|| "WS-Security: Reference missing URI attribute".to_string())?;
            let Some(ref_id) = uri.strip_prefix('#') else {
                return Err("WS-Security: unsupported non-fragment Reference URI".to_string());
            };
            if ref_id.is_empty() {
                return Err("WS-Security: empty fragment Reference URI is unsupported".to_string());
            }
            // Two References to one id are never meaningful and are exactly the
            // shape that multiplied canonicalization work in
            // GHSA-9g4v-h9hm-846r.
            if reference_ids.contains(&ref_id) {
                return Err(
                    "WS-Security: duplicate Signature Reference URI is not allowed".to_string(),
                );
            }
            reference_ids.push(ref_id);
        }
        let raw_occurrences = count_raw_id_occurrences(document.envelope, &reference_ids)?;

        let mut coverage = ReferenceCoverage::default();
        for (index, reference) in references.iter().enumerate() {
            let reference = *reference;
            let ref_id = reference_ids[index];
            // Determine the digest algorithm
            let digest_method = unique_ns_child(
                reference,
                XMLDSIG_NAMESPACE_URI,
                "DigestMethod",
                "WS-Security",
            )?
            .ok_or_else(|| "WS-Security: Reference missing DigestMethod".to_string())?;
            let digest_alg_uri = digest_method
                .attribute("Algorithm")
                .ok_or_else(|| "WS-Security: DigestMethod missing Algorithm".to_string())?;

            // Extract expected digest
            let digest_value = unique_ns_child(
                reference,
                XMLDSIG_NAMESPACE_URI,
                "DigestValue",
                "WS-Security",
            )?
            .ok_or_else(|| "WS-Security: Reference missing DigestValue".to_string())?;
            let expected_b64 = digest_value
                .text()
                .ok_or_else(|| "WS-Security: DigestValue is empty".to_string())?;

            let expected_bytes = BASE64
                .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid DigestValue base64: {}", e))?;

            // XML Signature Wrapping defense: a signed reference must resolve to
            // exactly ONE element in the whole envelope. `resolve_unique` below
            // is what enforces "exactly one" — it reads the entity-decoded DOM,
            // so it sees the same value a backend's parser sees. The raw
            // start-tag scan is the defence-in-depth *over-count* on top of it:
            // it recognizes broader id spellings a tolerant backend might
            // resolve but the DOM index does not index.
            //
            // It must stay an over-count check. A raw byte scan cannot see
            // through character references, so `wsu:Id="TS&#x2D;1"` — one
            // legitimate element whose decoded id is exactly `TS-1` — scans as
            // zero raw occurrences. Requiring exactly one here would reject that
            // message while adding nothing: any decoded duplicate is already
            // caught by `resolve_unique`, and any raw duplicate under a spelling
            // the DOM misses is caught by `> 1`.
            if raw_occurrences[index] > 1 {
                return Err(format!(
                    "WS-Security: referenced id is not unique in the envelope ({} raw \
                     occurrences) — possible XML signature wrapping",
                    raw_occurrences[index]
                ));
            }
            let referenced_node = document.id_index.resolve_unique(ref_id)?;

            // The referenced element must live inside the Security header or
            // inside the backend-visible Body. Anything else is a subtree the
            // gateway does not govern and a backend does not consume.
            let referenced_id = referenced_node.id();
            let in_security = node_is_within(referenced_node, security);
            let in_body = node_is_within(referenced_node, document.structure.body);
            if !in_security && !in_body {
                return Err(
                    "WS-Security: Reference resolves outside the Security header and the SOAP Body"
                        .to_string(),
                );
            }
            if referenced_id == document.structure.body.id() {
                coverage.covers_body = true;
            }
            coverage.covered.push(referenced_id);

            let transforms = parse_reference_transforms(reference, "WS-Security")?;
            let excluded_signature = transforms
                .enveloped_signature
                .then_some(signature_node.id());
            let referenced_content = exclusive_canonicalize(
                document.envelope,
                referenced_node,
                &transforms.inclusive_prefixes,
                excluded_signature,
                budget,
            )?;

            // Compute and compare digest. The allowed_digest_algorithms list
            // is checked independently of the signature algorithm list — an
            // operator who wants rsa-sha256 signatures over sha1 digests
            // (rare but valid per XMLDSIG) configures both knobs explicitly,
            // and the default (sha256 only) refuses sha1 digests regardless
            // of which signature algorithm is in use.
            let computed = match digest_alg_uri {
                XMLDSIG_SHA256 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha256)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA256, &referenced_content)
                }
                XMLDSIG_SHA1 => {
                    if !self
                        .allowed_digest_algorithms
                        .contains(&DigestAlgorithm::Sha1)
                    {
                        return Err(format!(
                            "WS-Security: digest algorithm '{}' is not allowed",
                            digest_alg_uri
                        ));
                    }
                    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &referenced_content)
                }
                other => {
                    return Err(format!(
                        "WS-Security: unsupported digest algorithm '{}'",
                        other
                    ));
                }
            };

            if computed.as_ref() != expected_bytes.as_slice() {
                return Err("WS-Security: Reference digest mismatch".to_string());
            }
        }

        // XMLDSig requires SignedInfo to contain at least one Reference.
        // A signature with zero references would otherwise be considered
        // valid here even though it signs nothing meaningful — making it
        // trivial to bypass `require_signed_timestamp`.
        if references.is_empty() {
            return Err("WS-Security: SignedInfo contains no Reference elements".to_string());
        }

        Ok(coverage)
    }

    /// A required signed Timestamp must actually exist and actually be covered.
    ///
    /// This used to return `Ok` when the selected Security header carried no
    /// Timestamp at all, so `require_signed_timestamp: true` was satisfied
    /// vacuously by omitting the element (GHSA-3mwq-c8j6-9xhp). Admission now
    /// also refuses `require_signed_timestamp` alongside
    /// `timestamp.require: false`, so the two policies cannot contradict.
    fn verify_timestamp_is_signed(
        security: Node<'_, '_>,
        coverage: &ReferenceCoverage,
    ) -> Result<(), String> {
        let Some(timestamp) = Self::timestamp_node(security)? else {
            return Err(
                "WS-Security: a signed Timestamp is required but the Security header has none"
                    .to_string(),
            );
        };
        if !coverage.covered.contains(&timestamp.id()) {
            return Err("WS-Security: Timestamp is not included in the signature".to_string());
        }
        Ok(())
    }

    /// Resolve the signing certificate from the namespace-correct
    /// `wsse:BinarySecurityToken` child of the Security header, or from
    /// `dsig:KeyInfo/dsig:X509Data/dsig:X509Certificate` inside the signature.
    fn extract_signing_cert(
        &self,
        security: Node<'_, '_>,
        signature: Node<'_, '_>,
    ) -> Result<Vec<u8>, String> {
        if let Some(bst) = unique_ns_child(
            security,
            WSSE_NAMESPACE_URI,
            "BinarySecurityToken",
            "WS-Security",
        )? {
            let cert_b64 = element_text(bst)
                .ok_or_else(|| "WS-Security: BinarySecurityToken has no content".to_string())?;
            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid BinarySecurityToken base64: {}", e));
        }

        if let Some(cert_b64) = xmldsig_key_info_certificate(signature, "WS-Security")? {
            return BASE64
                .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
                .map_err(|e| format!("WS-Security: invalid X509Certificate base64: {}", e));
        }

        Err("WS-Security: no signing certificate found (expected BinarySecurityToken or X509Certificate in KeyInfo)".to_string())
    }

    // ── SAML assertion validation ───────────────────────────────────────

    /// Validate the SAML assertion inside a WS-Security header.
    ///
    /// Returns the assertion's Subject `NameID` on success — the "who" of the
    /// assertion — which the caller publishes as the request principal. Exactly
    /// one namespace-correct, nonblank `NameID` is required, and it is resolved
    /// before the single-use claim, so an assertion that authenticates nobody
    /// fails closed without consuming replay state.
    ///
    /// Verification order is signature-first: an attacker who can post a SOAP
    /// body controls every text node in the assertion, so issuer / conditions
    /// / audience / recipient checks only mean something AFTER the assertion's
    /// XMLDSIG signature has been verified against a configured trusted IdP
    /// cert.
    ///
    /// **GHSA-f44p-hfqr-cvcc.** A signed assertion is a bearer value: nothing
    /// in it changes between presentations, and the outer WS-Security Timestamp
    /// it travels beside is not covered by its signature, so an attacker can
    /// remint that Timestamp and replay indefinitely. This path therefore
    /// requires, in order: a bounded `Conditions` window (both instants
    /// mandatory, span capped by `max_assertion_lifetime_seconds`), the
    /// configured service `Audience`, a supported `SubjectConfirmation` whose
    /// `SubjectConfirmationData` names the configured `Recipient` and carries
    /// its own bounded `NotOnOrAfter`, a resolvable Subject `NameID`, and
    /// finally an atomic single-use claim on the assertion id in the declared
    /// replay scope. `OneTimeUse` needs no special case because every accepted
    /// assertion is claimed exactly once; a replay backend outage fails closed
    /// like every other replay decision.
    async fn validate_saml_assertion<'a, 'i>(
        &self,
        security: Node<'a, 'i>,
        envelope: &str,
        now: DateTime<Utc>,
        budget: &mut WorkBudget,
    ) -> Result<String, String> {
        let document = security.document();
        let mut assertion_node = None;
        for node in document.descendants().filter(Node::is_element) {
            if !node.has_tag_name((SAML2_ASSERTION_NS, "Assertion")) {
                continue;
            }
            // Only ever validate a single assertion. A second one anywhere in
            // the envelope lets a downstream consumer that walks all assertions
            // see an identity the gateway never verified.
            if assertion_node.replace(node).is_some() {
                return Err(
                    "WS-Security: multiple SAML Assertion elements are not allowed".to_string(),
                );
            }
            if !node_is_within(node, security) {
                return Err(
                    "WS-Security: SAML Assertion appears outside the wsse:Security header"
                        .to_string(),
                );
            }
        }
        // Only reached from an enabled SAML policy, so an absent assertion is
        // always terminal.
        let Some(assertion_node) = assertion_node else {
            return Err("WS-Security: missing SAML Assertion element".to_string());
        };

        // ── 1. Signature verification ─────────────────────────────────
        // Must run before any other check — every other field is
        // attacker-controlled until we know the IdP signed this assertion.
        self.validate_saml_signature(assertion_node, envelope, budget)?;

        // ── 2. Issuer trust ───────────────────────────────────────────
        let issuer_node = unique_ns_child(
            assertion_node,
            SAML2_ASSERTION_NS,
            "Issuer",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Assertion missing Issuer element".to_string())?;
        let issuer = element_text(issuer_node)
            .ok_or_else(|| "WS-Security: SAML Issuer is empty".to_string())?;

        // The rejected issuer is credential material presented by the caller
        // and is never echoed to the client or written to a log line.
        if !self.saml_trusted_issuers.iter().any(|ti| ti == &issuer) {
            return Err("WS-Security: SAML Issuer is not trusted".to_string());
        }

        // ── 3. Conditions: bounded validity + service audience ────────
        let skew = self.saml_clock_skew;
        let conditions = unique_ns_child(
            assertion_node,
            SAML2_ASSERTION_NS,
            "Conditions",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| {
            "WS-Security: SAML Assertion has no Conditions — a bounded validity window is required"
                .to_string()
        })?;

        let not_before = conditions
            .attribute("NotBefore")
            .ok_or_else(|| "WS-Security: SAML Conditions missing NotBefore".to_string())
            .and_then(|raw| {
                parse_ws_datetime(raw)
                    .ok_or_else(|| "WS-Security: invalid SAML NotBefore".to_string())
            })?;
        let not_on_or_after = conditions
            .attribute("NotOnOrAfter")
            .ok_or_else(|| "WS-Security: SAML Conditions missing NotOnOrAfter".to_string())
            .and_then(|raw| {
                parse_ws_datetime(raw)
                    .ok_or_else(|| "WS-Security: invalid SAML NotOnOrAfter".to_string())
            })?;
        if not_on_or_after <= not_before {
            return Err("WS-Security: SAML Conditions window is empty or inverted".to_string());
        }
        // The cap is what keeps a captured assertion from being an effectively
        // indefinite credential even before replay state is consulted, and it
        // is what makes the fixed replay-claim horizon provably sufficient.
        if not_on_or_after - not_before > self.saml_max_assertion_lifetime {
            return Err(format!(
                "WS-Security: SAML Assertion validity window exceeds the permitted {}s",
                self.saml_max_assertion_lifetime_seconds
            ));
        }
        if now + skew < not_before {
            return Err("WS-Security: SAML Assertion is not yet valid".to_string());
        }
        let expiry_with_skew = not_on_or_after.checked_add_signed(skew).ok_or_else(|| {
            "WS-Security: SAML NotOnOrAfter is outside the supported range".to_string()
        })?;
        if now > expiry_with_skew {
            return Err("WS-Security: SAML Assertion has expired".to_string());
        }

        let expected_audience = self
            .saml_audience
            .as_deref()
            .ok_or_else(|| "WS-Security: SAML audience binding is not configured".to_string())?;
        let mut audience_matched = false;
        let mut audience_restrictions = 0usize;
        for restriction in conditions
            .children()
            .filter(|node| node.has_tag_name((SAML2_ASSERTION_NS, "AudienceRestriction")))
        {
            audience_restrictions += 1;
            // Every AudienceRestriction is a conjunct: each one must admit this
            // service, so a second restriction naming only another relying
            // party invalidates the assertion here.
            let mut restriction_matched = false;
            for audience in restriction
                .children()
                .filter(|node| node.has_tag_name((SAML2_ASSERTION_NS, "Audience")))
            {
                if element_text(audience).as_deref() == Some(expected_audience) {
                    restriction_matched = true;
                }
            }
            if !restriction_matched {
                return Err(
                    "WS-Security: SAML AudienceRestriction does not admit this service".to_string(),
                );
            }
            audience_matched = true;
        }
        if audience_restrictions == 0 || !audience_matched {
            return Err(
                "WS-Security: SAML Conditions must carry an AudienceRestriction naming this \
                 service"
                    .to_string(),
            );
        }

        // ── 4. SubjectConfirmation / Recipient binding ────────────────
        let subject = unique_ns_child(
            assertion_node,
            SAML2_ASSERTION_NS,
            "Subject",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Assertion missing Subject element".to_string())?;
        self.validate_saml_subject_confirmation(subject, now)?;

        // ── 5. Subject NameID: the assertion's authoritative identity ─
        //
        // This runs *before* the single-use claim, not after it. An enabled
        // SAML policy makes this instance an authentication plugin, and the
        // documented principal it publishes is the Subject `NameID`. An
        // assertion that satisfies every other check but names nobody cannot
        // authenticate anything, so accepting it and returning no principal
        // silently degraded the request to unauthenticated while still burning
        // the assertion's replay id — which also let an attacker who observed a
        // legitimate assertion id spend it on a principal-less lookalike.
        // Requiring exactly one namespace-correct, nonblank `NameID` here makes
        // that a semantic failure that consumes no replay state.
        let name_id_node =
            unique_ns_child(subject, SAML2_ASSERTION_NS, "NameID", "WS-Security: SAML")?;
        let Some(name_id) = name_id_node.and_then(element_text) else {
            return Err("WS-Security: SAML Subject has no nonblank NameID".to_string());
        };

        // ── 6. Single use ─────────────────────────────────────────────
        // Claimed after every semantic check so a rejected assertion cannot
        // burn a legitimate one's id, and before the identity is returned so no
        // caller can act on an assertion whose claim was refused.
        let assertion_id = assertion_node
            .attribute("ID")
            .or_else(|| assertion_node.attribute("AssertionID"))
            .ok_or_else(|| "WS-Security: SAML Assertion missing ID attribute".to_string())?;
        self.claim_saml_assertion(&issuer, assertion_id).await?;

        debug!("soap_ws_security: SAML assertion validated successfully");
        Ok(name_id)
    }

    /// Enforce supported `SubjectConfirmation` semantics.
    ///
    /// Exactly one confirmation must be acceptable: its `Method` must be in the
    /// configured allow list (bearer only, today), and its
    /// `SubjectConfirmationData` must name the configured `Recipient`, carry
    /// its own bounded `NotOnOrAfter`, honour any `NotBefore`, and omit
    /// `InResponseTo` — there is no SAML request in a WS-Security bearer flow
    /// to correlate one against, so a value Ferrum cannot check must not be
    /// silently ignored.
    fn validate_saml_subject_confirmation(
        &self,
        subject: Node<'_, '_>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let expected_recipient = self
            .saml_recipient
            .as_deref()
            .ok_or_else(|| "WS-Security: SAML recipient binding is not configured".to_string())?;
        let skew = self.saml_clock_skew;
        let mut accepted = false;

        for confirmation in subject
            .children()
            .filter(|node| node.has_tag_name((SAML2_ASSERTION_NS, "SubjectConfirmation")))
        {
            let method = confirmation.attribute("Method").ok_or_else(|| {
                "WS-Security: SAML SubjectConfirmation missing Method attribute".to_string()
            })?;
            if !self
                .saml_allowed_confirmation_methods
                .iter()
                .any(|allowed| allowed == method)
            {
                continue;
            }
            let data = unique_ns_child(
                confirmation,
                SAML2_ASSERTION_NS,
                "SubjectConfirmationData",
                "WS-Security: SAML",
            )?
            .ok_or_else(|| {
                "WS-Security: SAML SubjectConfirmation missing SubjectConfirmationData".to_string()
            })?;

            if data.attribute("InResponseTo").is_some() {
                return Err(
                    "WS-Security: SAML SubjectConfirmationData carries an InResponseTo value that \
                     cannot be validated in a WS-Security bearer flow"
                        .to_string(),
                );
            }
            let recipient = data.attribute("Recipient").ok_or_else(|| {
                "WS-Security: SAML SubjectConfirmationData missing Recipient".to_string()
            })?;
            if recipient.trim() != expected_recipient {
                return Err(
                    "WS-Security: SAML SubjectConfirmationData Recipient does not match this \
                     service"
                        .to_string(),
                );
            }
            let not_on_or_after = data
                .attribute("NotOnOrAfter")
                .ok_or_else(|| {
                    "WS-Security: SAML SubjectConfirmationData missing NotOnOrAfter".to_string()
                })
                .and_then(|raw| {
                    parse_ws_datetime(raw).ok_or_else(|| {
                        "WS-Security: invalid SAML SubjectConfirmationData NotOnOrAfter".to_string()
                    })
                })?;
            let expiry_with_skew = not_on_or_after.checked_add_signed(skew).ok_or_else(|| {
                "WS-Security: SAML SubjectConfirmationData NotOnOrAfter is outside the supported \
                 range"
                    .to_string()
            })?;
            if now > expiry_with_skew {
                return Err("WS-Security: SAML SubjectConfirmationData has expired".to_string());
            }
            if let Some(raw) = data.attribute("NotBefore") {
                let not_before = parse_ws_datetime(raw).ok_or_else(|| {
                    "WS-Security: invalid SAML SubjectConfirmationData NotBefore".to_string()
                })?;
                if now + skew < not_before {
                    return Err(
                        "WS-Security: SAML SubjectConfirmationData is not yet valid".to_string()
                    );
                }
            }
            if accepted {
                return Err(
                    "WS-Security: SAML Subject carries multiple acceptable SubjectConfirmation \
                     elements"
                        .to_string(),
                );
            }
            accepted = true;
        }

        if !accepted {
            return Err(
                "WS-Security: SAML Subject has no supported SubjectConfirmation for this service"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Verify the SAML assertion's XMLDSIG signature.
    ///
    /// Steps, in this order:
    /// 1. Locate `<Signature>` inside the assertion and resolve the signing
    ///    algorithm, confirming it is in the allow list.
    /// 2. Extract the signing cert from `KeyInfo/X509Data/X509Certificate`
    ///    (or `BinarySecurityToken`) and confirm its SHA-256 fingerprint
    ///    matches a configured trusted IdP cert.
    /// 3. Verify `<SignatureValue>` over exclusive-canonicalized
    ///    `<SignedInfo>` using the matched cert's public key.
    /// 4. Only then verify each `<Reference>` digest after applying its
    ///    declared enveloped-signature / exclusive-c14n transform chain.
    ///
    /// Step 4 last is the GHSA-9g4v-h9hm-846r fix: the assertion subtree is
    /// canonicalized once per Reference, so resolving References before trust
    /// let an untrusted caller drive that work with duplicate References over a
    /// large assertion.
    fn validate_saml_signature(
        &self,
        assertion_node: Node<'_, '_>,
        envelope: &str,
        budget: &mut WorkBudget,
    ) -> Result<(), String> {
        let sig_node = unique_ns_child(
            assertion_node,
            XMLDSIG_NAMESPACE_URI,
            "Signature",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Assertion missing Signature element".to_string())?;
        let signed_info_node = unique_ns_child(
            sig_node,
            XMLDSIG_NAMESPACE_URI,
            "SignedInfo",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Signature missing SignedInfo element".to_string())?;

        // ── Resolve signature algorithm ───────────────────────────────
        let sig_method = unique_ns_child(
            signed_info_node,
            XMLDSIG_NAMESPACE_URI,
            "SignatureMethod",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML SignedInfo missing SignatureMethod".to_string())?;
        let sig_algorithm_uri = sig_method.attribute("Algorithm").ok_or_else(|| {
            "WS-Security: SAML SignatureMethod missing Algorithm attribute".to_string()
        })?;

        let sig_algorithm = match sig_algorithm_uri {
            XMLDSIG_RSA_SHA256 => SignatureAlgorithm::RsaSha256,
            XMLDSIG_RSA_SHA1 => SignatureAlgorithm::RsaSha1,
            other => {
                return Err(format!(
                    "WS-Security: SAML unsupported signature algorithm '{}'",
                    other
                ));
            }
        };

        if !self
            .saml_allowed_signature_algorithms
            .contains(&sig_algorithm)
        {
            return Err(format!(
                "WS-Security: SAML signature algorithm '{}' is not allowed",
                sig_algorithm_uri
            ));
        }

        let canonicalization =
            parse_signed_info_canonicalization(signed_info_node, "WS-Security: SAML")?;

        // ── Extract SignatureValue ────────────────────────────────────
        let sig_value_node = unique_ns_child(
            sig_node,
            XMLDSIG_NAMESPACE_URI,
            "SignatureValue",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Signature missing SignatureValue".to_string())?;
        let sig_value_b64 = sig_value_node
            .text()
            .ok_or_else(|| "WS-Security: SAML SignatureValue is empty".to_string())?;
        let sig_bytes = BASE64
            .decode(sig_value_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid SignatureValue base64: {}", e))?;

        // ── Resolve signing cert and confirm it is trusted ────────────
        let cert_der = extract_saml_signing_cert(sig_node)?;
        let cert_fingerprint = digest::digest(&digest::SHA256, &cert_der).as_ref().to_vec();

        let trusted = self
            .saml_trusted_signing_certs
            .iter()
            .find(|tc| tc.fingerprint == cert_fingerprint);

        let public_key_der = match trusted {
            Some(tc) => &tc.public_key_der,
            None => {
                return Err("WS-Security: SAML signing certificate is not trusted".to_string());
            }
        };

        // ── Verify the signature over canonicalized SignedInfo ────────
        let verify_algorithm: &dyn ring_sig::VerificationAlgorithm = match sig_algorithm {
            SignatureAlgorithm::RsaSha256 => &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            SignatureAlgorithm::RsaSha1 => &ring_sig::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        };

        let public_key = ring_sig::UnparsedPublicKey::new(verify_algorithm, public_key_der);

        let canonical_signed_info = exclusive_canonicalize(
            envelope,
            signed_info_node,
            &canonicalization.inclusive_prefixes,
            None,
            budget,
        )?;

        public_key
            .verify(&canonical_signed_info, &sig_bytes)
            .map_err(|_| "WS-Security: SAML signature verification failed".to_string())?;

        // ── Authenticated. Only now is Reference work performed ───────
        self.verify_saml_reference_digests(
            signed_info_node,
            assertion_node,
            sig_node,
            envelope,
            budget,
        )?;

        debug!("soap_ws_security: SAML assertion signature verified");
        Ok(())
    }

    /// Verify Reference digests inside the SAML SignedInfo.
    ///
    /// Exactly one Reference is supported and it must target the enclosing
    /// assertion via `URI="#<assertion-ID>"`. Other References (e.g. SAML 2.0
    /// SubjectConfirmationData) are NOT supported here — they would require
    /// resolving arbitrary IDs inside the assertion and applying additional
    /// transforms, which is outside the scope of the current implementation.
    /// Permitting up to 64 same-URI References was the SAML half of
    /// GHSA-9g4v-h9hm-846r; a duplicate now fails closed rather than
    /// re-canonicalizing the assertion.
    fn verify_saml_reference_digests(
        &self,
        signed_info: Node<'_, '_>,
        assertion: Node<'_, '_>,
        signature: Node<'_, '_>,
        envelope: &str,
        budget: &mut WorkBudget,
    ) -> Result<(), String> {
        let assertion_id = assertion
            .attribute("ID")
            .or_else(|| assertion.attribute("AssertionID"))
            .ok_or_else(|| "WS-Security: SAML Assertion missing ID attribute".to_string())?;
        let expected_uri = format!("#{}", assertion_id);

        let references: Vec<Node<'_, '_>> = signed_info
            .children()
            .filter(|node| node.has_tag_name((XMLDSIG_NAMESPACE_URI, "Reference")))
            .collect();
        if references.is_empty() {
            return Err("WS-Security: SAML SignedInfo contains no Reference elements".to_string());
        }
        if references.len() > 1 {
            return Err(
                "WS-Security: SAML SignedInfo must contain exactly one Reference to the enclosing \
                 Assertion"
                    .to_string(),
            );
        }
        let reference = references[0];

        let uri = reference
            .attribute("URI")
            .ok_or_else(|| "WS-Security: SAML Reference missing URI attribute".to_string())?;

        // Only a Reference URI that targets this assertion is accepted — an
        // attacker who can choose the Reference URI would otherwise pick a
        // stable subtree they control.
        if uri != expected_uri {
            return Err(
                "WS-Security: SAML Reference URI does not target the enclosing Assertion"
                    .to_string(),
            );
        }

        let digest_method = unique_ns_child(
            reference,
            XMLDSIG_NAMESPACE_URI,
            "DigestMethod",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Reference missing DigestMethod".to_string())?;
        let digest_alg_uri = digest_method.attribute("Algorithm").ok_or_else(|| {
            "WS-Security: SAML DigestMethod missing Algorithm attribute".to_string()
        })?;

        let digest_value = unique_ns_child(
            reference,
            XMLDSIG_NAMESPACE_URI,
            "DigestValue",
            "WS-Security: SAML",
        )?
        .ok_or_else(|| "WS-Security: SAML Reference missing DigestValue".to_string())?;
        let expected_b64 = digest_value
            .text()
            .ok_or_else(|| "WS-Security: SAML DigestValue is empty".to_string())?;
        let expected_bytes = BASE64
            .decode(expected_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid DigestValue base64: {}", e))?;

        let transforms = parse_reference_transforms(reference, "WS-Security: SAML")?;
        let excluded_signature = transforms.enveloped_signature.then_some(signature.id());
        let canonical_assertion = exclusive_canonicalize(
            envelope,
            assertion,
            &transforms.inclusive_prefixes,
            excluded_signature,
            budget,
        )?;

        let computed = match digest_alg_uri {
            XMLDSIG_SHA256 => {
                if !self
                    .saml_allowed_digest_algorithms
                    .contains(&DigestAlgorithm::Sha256)
                {
                    return Err(format!(
                        "WS-Security: SAML digest algorithm '{}' is not allowed",
                        digest_alg_uri
                    ));
                }
                digest::digest(&digest::SHA256, &canonical_assertion)
            }
            XMLDSIG_SHA1 => {
                if !self
                    .saml_allowed_digest_algorithms
                    .contains(&DigestAlgorithm::Sha1)
                {
                    return Err(format!(
                        "WS-Security: SAML digest algorithm '{}' is not allowed",
                        digest_alg_uri
                    ));
                }
                digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &canonical_assertion)
            }
            other => {
                return Err(format!(
                    "WS-Security: SAML unsupported digest algorithm '{}'",
                    other
                ));
            }
        };

        if computed.as_ref() != expected_bytes.as_slice() {
            return Err("WS-Security: SAML assertion digest mismatch".to_string());
        }

        Ok(())
    }

    // ── Content-type classification (GHSA-435h-f785-wmm4) ───────────────

    /// Decide how this request's declared representation is governed.
    ///
    /// Substring matching used to decide this ("does the header text contain
    /// `application/xml` anywhere?"), which both under- and over-matched: a
    /// SOAP envelope labelled `application/octet-stream` skipped the whole
    /// policy while a `multipart/form-data; boundary=application/xml` request
    /// was raw-scanned as if it were an envelope. Classification is now
    /// structural — the media type is parsed into `type/subtype` plus
    /// parameters, and only exact essences are recognized.
    fn classify_request(&self, content_type: Option<&str>) -> SoapRequestDisposition {
        let Some(content_type) = content_type else {
            return match self.content_type_mode {
                // Strict routes govern every request. An absent Content-Type on
                // a SOAP-protected proxy is exactly the bypass the advisory
                // describes: a backend that routes by path or SOAPAction still
                // executes the operation.
                ContentTypeMode::Strict => SoapRequestDisposition::Reject(
                    MediaTypeRejection::MissingContentTypeOnProtectedRoute,
                ),
                ContentTypeMode::MixedRoute => SoapRequestDisposition::PassThrough,
            };
        };
        let classified = classify_soap_media_type(content_type, self.allow_mtom);

        // An X.509 policy claims *integrity* over the message the backend
        // executes. Ferrum implements no WS-Security attachment transform, so
        // for a XOP representation the digest it verifies covers the
        // `xop:Include` element and not the attachment octets that element
        // stands for — an attacker-selected attachment substituted before
        // validation is never detected. Refusing the representation is the
        // honest outcome; claiming coverage Ferrum cannot establish is not.
        let xop = matches!(&classified, Ok(Some(class)) if class.is_xop());
        if self.x509_enabled && xop {
            let refusal = MediaTypeRejection::XopUnsupportedUnderX509;
            return SoapRequestDisposition::Reject(refusal);
        }

        match classified {
            Ok(Some(class)) => SoapRequestDisposition::Governed(class),
            Ok(None) => match self.content_type_mode {
                ContentTypeMode::Strict => SoapRequestDisposition::Reject(
                    MediaTypeRejection::UnsupportedMediaTypeOnProtectedRoute,
                ),
                ContentTypeMode::MixedRoute => SoapRequestDisposition::PassThrough,
            },
            // Malformed or hostile media-type syntax always fails closed, even
            // on a mixed route: an unparsable label cannot be proven non-SOAP.
            Err(rejection) => SoapRequestDisposition::Reject(rejection),
        }
    }

    /// Whether this request's body must be buffered for SOAP validation.
    fn request_body_is_governed(&self, content_type: Option<&str>) -> bool {
        matches!(
            self.classify_request(content_type),
            SoapRequestDisposition::Governed(_)
        )
    }

    /// True when an accepted message yields a request principal.
    ///
    /// UsernameToken, X.509 and SAML each establish "who" sent the message, so
    /// those configurations run in the `authenticate` phase and populate the
    /// authoritative request identity (GHSA-gfrx-43w6-jq3c). A timestamp-only
    /// policy proves freshness and nothing about the caller; it has no identity
    /// to publish, must not join the authentication chain (it would turn every
    /// request into "Authentication required"), and keeps validating in
    /// `before_proxy`. The two phases are mutually exclusive by configuration,
    /// so no message is ever validated twice.
    fn establishes_identity(&self) -> bool {
        self.username_token_enabled || self.x509_enabled || self.saml_enabled
    }
}

// ── Media-type classification ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentTypeMode {
    /// Every request on this proxy is a governed SOAP request. Missing or
    /// unsupported media types are rejected before backend dispatch.
    Strict,
    /// Only requests whose media type is a recognized SOAP representation are
    /// governed; everything else passes through. The explicit, documented
    /// opt-out for proxies that intentionally serve mixed traffic.
    MixedRoute,
}

/// How a governed SOAP message is packaged on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SoapMediaClass {
    /// `text/xml`, `application/soap+xml`, or `application/xml`: the whole body
    /// is the SOAP envelope and nothing it references lives outside it.
    Xml,
    /// A bare `application/xop+xml` infoset: the whole body is the envelope,
    /// but it declares the XOP optimization, so `xop:Include` elements in it
    /// stand for octets Ferrum has no packaged source for.
    Xop,
    /// MTOM/XOP `multipart/related`: the envelope is the root part and the
    /// remaining parts are binary attachments the gateway never decodes.
    Mtom {
        boundary: String,
        start: Option<String>,
    },
}

impl SoapMediaClass {
    /// Whether this representation declares the XOP optimization, i.e. whether
    /// the envelope may reference octets that live outside the bytes Ferrum
    /// validates. Only relevant to policies that claim message integrity.
    fn is_xop(&self) -> bool {
        matches!(self, Self::Xop | Self::Mtom { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaTypeRejection {
    MissingContentTypeOnProtectedRoute,
    UnsupportedMediaTypeOnProtectedRoute,
    MalformedMediaType,
    MalformedMultipartPackaging,
    /// A XOP/MTOM representation on a route whose `x509_signature` policy
    /// claims message integrity Ferrum cannot establish over attachment octets.
    XopUnsupportedUnderX509,
}

impl MediaTypeRejection {
    fn status_code(self) -> u16 {
        match self {
            Self::MissingContentTypeOnProtectedRoute
            | Self::UnsupportedMediaTypeOnProtectedRoute
            | Self::XopUnsupportedUnderX509 => 415,
            Self::MalformedMediaType | Self::MalformedMultipartPackaging => 400,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::MissingContentTypeOnProtectedRoute => {
                "SOAP request is missing a Content-Type on a SOAP-protected route"
            }
            Self::UnsupportedMediaTypeOnProtectedRoute => {
                "SOAP request uses an unsupported media type on a SOAP-protected route"
            }
            Self::MalformedMediaType => "SOAP request Content-Type is malformed",
            Self::MalformedMultipartPackaging => {
                "SOAP request MTOM/XOP packaging is malformed or unsupported"
            }
            Self::XopUnsupportedUnderX509 => {
                "SOAP request uses MTOM/XOP; attachment octets are outside X.509 coverage"
            }
        }
    }

    /// Fixed-cardinality telemetry class. The rejected header value is operator-
    /// and attacker-controlled and is never logged.
    fn class(self) -> &'static str {
        match self {
            Self::MissingContentTypeOnProtectedRoute => "missing_content_type",
            Self::UnsupportedMediaTypeOnProtectedRoute => "unsupported_media_type",
            Self::MalformedMediaType => "malformed_media_type",
            Self::MalformedMultipartPackaging => "malformed_multipart",
            Self::XopUnsupportedUnderX509 => "xop_unsupported_under_x509",
        }
    }
}

enum SoapRequestDisposition {
    Governed(SoapMediaClass),
    PassThrough,
    Reject(MediaTypeRejection),
}

/// Exact media-type essences that carry a SOAP envelope directly.
const SOAP_XML_ESSENCES: &[&str] = &[
    // SOAP 1.1
    "text/xml",
    // SOAP 1.2
    "application/soap+xml",
    // Generic XML, accepted by many SOAP stacks
    "application/xml",
];

/// A bare XOP infoset (MTOM without the multipart wrapper). Classified apart
/// from [`SOAP_XML_ESSENCES`] because it declares the XOP optimization, which
/// matters to any policy claiming coverage of the whole message.
const XOP_INFOSET_ESSENCE: &str = "application/xop+xml";

/// Essences accepted as an MTOM root part's own type.
const MTOM_ROOT_ESSENCES: &[&str] = &["application/xop+xml", "text/xml", "application/soap+xml"];

/// Parse `content_type` structurally and decide whether it names a SOAP
/// representation this plugin can validate.
///
/// `Ok(None)` means "definitely not SOAP". `Err` means the label itself is
/// malformed, ambiguous, or names a SOAP packaging Ferrum cannot unpack — those
/// always fail closed rather than falling through to a pass-through decision.
fn classify_soap_media_type(
    content_type: &str,
    allow_mtom: bool,
) -> Result<Option<SoapMediaClass>, MediaTypeRejection> {
    let essence = media_type_essence(content_type)?;
    if SOAP_XML_ESSENCES.contains(&essence.as_str()) {
        return Ok(Some(SoapMediaClass::Xml));
    }
    if essence == XOP_INFOSET_ESSENCE {
        return Ok(Some(SoapMediaClass::Xop));
    }
    if essence != "multipart/related" {
        return Ok(None);
    }

    // MTOM/XOP. The packaging is only SOAP when it says so: `type` must name a
    // SOAP root part. Without that parameter the multipart is some other
    // related-part payload and is not this plugin's business.
    let mut boundary = None;
    let mut root_type = None;
    let mut start = None;
    let mut rest = skip_content_type_media_type(content_type)
        .map_err(|_| MediaTypeRejection::MalformedMediaType)?;
    while let Some((name, value, next)) =
        next_content_type_parameter(rest).map_err(|_| MediaTypeRejection::MalformedMediaType)?
    {
        rest = next;
        if name.eq_ignore_ascii_case("boundary") {
            if boundary.replace(value.to_string()).is_some() {
                return Err(MediaTypeRejection::MalformedMultipartPackaging);
            }
        } else if name.eq_ignore_ascii_case("type") {
            if root_type.replace(value.to_ascii_lowercase()).is_some() {
                return Err(MediaTypeRejection::MalformedMultipartPackaging);
            }
        } else if name.eq_ignore_ascii_case("start")
            && start.replace(normalize_content_id(value)).is_some()
        {
            return Err(MediaTypeRejection::MalformedMultipartPackaging);
        }
    }

    let Some(root_type) = root_type else {
        return Ok(None);
    };
    if !MTOM_ROOT_ESSENCES.contains(&root_type.as_str()) {
        return Ok(None);
    }
    if !allow_mtom {
        // The operator declared this route does not accept MTOM. A SOAP-bearing
        // multipart must not silently stream past the policy.
        return Err(MediaTypeRejection::UnsupportedMediaTypeOnProtectedRoute);
    }
    let Some(boundary) = boundary else {
        return Err(MediaTypeRejection::MalformedMultipartPackaging);
    };
    if boundary.is_empty()
        || boundary.len() > MAX_MULTIPART_BOUNDARY_BYTES
        || boundary.ends_with(' ')
        || !boundary.bytes().all(is_multipart_boundary_byte)
    {
        return Err(MediaTypeRejection::MalformedMultipartPackaging);
    }
    Ok(Some(SoapMediaClass::Mtom { boundary, start }))
}

/// RFC 2046 `bcharsnospace` plus space. The caller separately rejects a final
/// space, which is forbidden by the boundary grammar.
fn is_multipart_boundary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&byte)
}

/// Lowercased `type/subtype`, rejecting anything that is not a single
/// well-formed media type token pair.
fn media_type_essence(content_type: &str) -> Result<String, MediaTypeRejection> {
    let head = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches(|ch: char| ch.is_ascii_whitespace());
    if head.is_empty() {
        return Err(MediaTypeRejection::MalformedMediaType);
    }
    let Some((kind, subtype)) = head.split_once('/') else {
        return Err(MediaTypeRejection::MalformedMediaType);
    };
    if kind.is_empty() || subtype.is_empty() {
        return Err(MediaTypeRejection::MalformedMediaType);
    }
    if !kind.bytes().all(is_media_type_token_byte) || !subtype.bytes().all(is_media_type_token_byte)
    {
        return Err(MediaTypeRejection::MalformedMediaType);
    }
    Ok(head.to_ascii_lowercase())
}

/// RFC 9110 `token` characters. Quotes, backslashes, whitespace, and `/` are
/// excluded so a parameter value can never be mistaken for an essence.
fn is_media_type_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Strip the optional `<...>` wrapper from a MIME `Content-ID` / `start` value.
fn normalize_content_id(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('<')
        .and_then(|inner| inner.strip_suffix('>'))
        .unwrap_or(trimmed)
        .to_string()
}

// ── Message validation orchestration ────────────────────────────────────────

/// A validated SOAP message's authoritative request principal.
///
/// `principal` is what becomes `RequestContext::authenticated_identity` and, on
/// a namespace-correct match, `identified_consumer`. `metadata` carries the
/// mechanism-specific values downstream logging has always seen.
#[derive(Default)]
struct SoapPrincipal {
    principal: Option<String>,
    username: Option<String>,
    saml_subject: Option<String>,
}

/// A terminal SOAP rejection: status, client-visible body, and the fixed
/// telemetry class that is safe to log.
struct SoapRejection {
    status_code: u16,
    body: String,
    failure_class: &'static str,
}

impl SoapRejection {
    fn new(status_code: u16, message: &str, failure_class: &'static str) -> Self {
        Self {
            status_code,
            body: format!(r#"{{"error":"{}"}}"#, escape_json_chars(message)),
            failure_class,
        }
    }

    fn into_plugin_result(self) -> PluginResult {
        // Fixed-cardinality class only. The envelope, the credential, and the
        // rejected header value never reach a log line.
        debug!(
            failure_class = self.failure_class,
            status_code = self.status_code,
            "soap_ws_security: request rejected"
        );
        PluginResult::Reject {
            status_code: self.status_code,
            body: self.body,
            headers: HashMap::new(),
        }
    }
}

impl SoapWsSecurity {
    /// Validate one SOAP message end to end.
    ///
    /// Everything that borrows the decoded body stays inside this function and
    /// only an owned [`SoapPrincipal`] escapes, so no partially-authenticated
    /// state can outlive a later rejection and the caller is free to mutate the
    /// request context afterwards.
    async fn validate_message(
        &self,
        ctx: &RequestContext,
        content_type: &str,
        media_class: &SoapMediaClass,
    ) -> Result<Option<SoapPrincipal>, SoapRejection> {
        let body = match resolve_soap_request_body(ctx, content_type, media_class) {
            Ok(Some(body)) => body,
            Ok(None) => {
                // An empty body carries no `wsse:Security` header because it
                // carries nothing at all. This is the one shape
                // `reject_missing_security_header: false` may still forward —
                // it is a genuinely absent header, not a parse disagreement.
                if self.reject_missing_security_header {
                    return Err(SoapRejection::new(
                        400,
                        "SOAP request body is empty",
                        "empty_body",
                    ));
                }
                return Ok(None);
            }
            Err(err) => {
                // Fail closed on hostile/unsupported encodings. Never log the
                // body, attacker-controlled Content-Type parameters, or
                // credential material — only the stable error class.
                return Err(SoapRejection::new(
                    err.status_code(),
                    err.message(),
                    err.class(),
                ));
            }
        };

        let envelope = body.trim();
        if contains_forbidden_xml_declaration(envelope) {
            return Err(SoapRejection::new(
                400,
                "SOAP request contains forbidden XML declaration",
                "forbidden_xml_declaration",
            ));
        }

        // One bounded parse for the whole message. Every structural selection
        // below is namespace-qualified against this single document, so the
        // gateway and the backend cannot be steered to different elements
        // (GHSA-3mwq-c8j6-9xhp), and the previous three independent parses of
        // the same envelope are gone.
        //
        // Neither failure below is gated on `reject_missing_security_header`.
        // That option exists to allow a governed message that genuinely carries
        // no `wsse:Security` header; it is not a licence to forward a
        // representation the gateway could not parse. Treating a parse
        // disagreement as pass-through is the bypass itself: Ferrum declines to
        // read the envelope, the backend reads it fine, and every check below
        // — timestamp, credentials, signature, replay — is skipped for a
        // message the backend still executes. Once a representation is
        // governed, malformed XML, a node/DTD budget failure, and unsupported
        // or ambiguous envelope structure are terminal.
        let document = match parse_bounded_xml(envelope, "SOAP") {
            Ok(document) => document,
            Err(error) => return Err(SoapRejection::new(400, &error, "malformed_xml")),
        };
        let structure = match resolve_soap_envelope(&document) {
            Ok(structure) => structure,
            Err(error) => return Err(SoapRejection::new(400, &error, "malformed_envelope")),
        };

        let security = resolve_security_node(&document, &structure)
            .map_err(|error| SoapRejection::new(400, &error, "ambiguous_security_header"))?;
        let Some(security) = security else {
            if self.reject_missing_security_header {
                return Err(SoapRejection::new(
                    401,
                    "WS-Security header is missing",
                    "missing_security_header",
                ));
            }
            return Ok(None);
        };

        let now = Utc::now();
        let mut budget = WorkBudget::for_envelope(envelope);
        let mut principal = SoapPrincipal::default();

        // Validate Timestamp.
        //
        // This runs unconditionally (the helper is a no-op for an absent
        // Timestamp when `timestamp.require` is false) so that a *present*
        // Timestamp is always independently validated. The UsernameToken
        // PasswordDigest binding compares against this same element, and binding
        // against an unvalidated instant would be no binding at all.
        if let Err(error) = self.validate_timestamp(security, now) {
            warn!(
                failure_class = "timestamp",
                "soap_ws_security: timestamp validation failed"
            );
            return Err(SoapRejection::new(401, &error, "timestamp"));
        }

        // Validate UsernameToken
        if self.username_token_enabled {
            match self.validate_username_token(security, now).await {
                Ok(username) => {
                    debug!("soap_ws_security: UsernameToken validated");
                    principal.principal.get_or_insert_with(|| username.clone());
                    principal.username = Some(username);
                }
                Err(UsernameTokenError::InvalidCredentials) => {
                    // Generic response + stable failure class: do not log the
                    // candidate username or password/digest verification detail.
                    warn!(
                        failure_class = UsernameTokenError::INVALID_CREDENTIALS_CLASS,
                        "soap_ws_security: UsernameToken authentication failed"
                    );
                    return Err(SoapRejection {
                        status_code: 401,
                        body: UsernameTokenError::INVALID_CREDENTIALS_BODY.to_string(),
                        failure_class: UsernameTokenError::INVALID_CREDENTIALS_CLASS,
                    });
                }
                Err(UsernameTokenError::Structural(detail)) => {
                    warn!(
                        failure_class = UsernameTokenError::STRUCTURAL_CLASS,
                        "soap_ws_security: UsernameToken structural validation failed"
                    );
                    return Err(SoapRejection::new(
                        401,
                        &detail,
                        UsernameTokenError::STRUCTURAL_CLASS,
                    ));
                }
            }
        }

        // Validate X.509 signature. The id index is built once here — after the
        // structure is settled and before the first Reference is resolved —
        // instead of rescanning the whole envelope per Reference.
        if self.x509_enabled {
            let id_index = DocumentIdIndex::build(&document);
            match self.validate_x509_signature(
                &structure,
                security,
                &id_index,
                envelope,
                &mut budget,
            ) {
                Ok(cert_principal) => {
                    principal
                        .principal
                        .get_or_insert_with(|| cert_principal.to_string());
                }
                Err(error) => {
                    warn!(
                        failure_class = "x509_signature",
                        "soap_ws_security: X.509 signature validation failed"
                    );
                    return Err(SoapRejection::new(401, &error, "x509_signature"));
                }
            }
        }

        // Validate SAML assertion
        if self.saml_enabled {
            match self
                .validate_saml_assertion(security, envelope, now, &mut budget)
                .await
            {
                Ok(name_id) => {
                    debug!("soap_ws_security: SAML assertion accepted");
                    principal.principal.get_or_insert_with(|| name_id.clone());
                    principal.saml_subject = Some(name_id);
                }
                Err(error) => {
                    warn!(
                        failure_class = "saml",
                        "soap_ws_security: SAML validation failed"
                    );
                    return Err(SoapRejection::new(401, &error, "saml"));
                }
            }
        }

        Ok(Some(principal))
    }

    /// Common request entry point for both phases.
    ///
    /// `commit_identity` is `false` for the timestamp-only configuration, which
    /// runs in `before_proxy` and has no principal to publish.
    async fn run_soap_policy(
        &self,
        ctx: &mut RequestContext,
        content_type_header: Option<String>,
        consumer_index: Option<&ConsumerIndex>,
    ) -> PluginResult {
        let media_class = match self.classify_request(content_type_header.as_deref()) {
            SoapRequestDisposition::Governed(class) => class,
            SoapRequestDisposition::PassThrough => return PluginResult::Continue,
            SoapRequestDisposition::Reject(rejection) => {
                warn!(
                    failure_class = rejection.class(),
                    "soap_ws_security: request representation rejected on a SOAP-protected route"
                );
                return SoapRejection::new(
                    rejection.status_code(),
                    rejection.message(),
                    rejection.class(),
                )
                .into_plugin_result();
            }
        };
        // `classify_request` only returns `Governed` for a present header.
        let content_type = content_type_header.unwrap_or_default();

        let principal = match self
            .validate_message(ctx, &content_type, &media_class)
            .await
        {
            Ok(Some(principal)) => principal,
            Ok(None) => return PluginResult::Continue,
            Err(rejection) => return rejection.into_plugin_result(),
        };

        // Record the exact representation that was authenticated so a later
        // request-body transform cannot silently substitute a different message
        // for the one this policy accepted.
        //
        // Only the identity-establishing form records it, matching
        // `requires_final_request_body_before_backend_dispatch`. A timestamp-only
        // policy authenticates nobody and claims no integrity over the Body: it
        // proves the message was fresh when it arrived, and it runs in
        // `before_proxy` rather than ahead of the shared body-normalization
        // phase, so there is no ordering hazard to close. Binding its
        // representation anyway would protect nothing while turning an ordinary
        // composition with a request-body transformer — whose rewrite lands
        // immediately before the final-body hooks — into an unconditional `500`
        // for every governed SOAP request.
        if self.establishes_identity() {
            let authenticated_digest = ctx
                .request_body_bytes
                .as_ref()
                .map(|bytes| sha256_array(bytes));
            ctx.soap_ws_security_authenticated_body_digest = authenticated_digest;
        }

        if let Some(username) = principal.username.clone() {
            ctx.metadata
                .insert("soap_ws_username".to_string(), username);
        }
        if let Some(subject) = principal.saml_subject.clone() {
            ctx.metadata
                .insert("soap_ws_saml_subject".to_string(), subject);
        }

        let Some(consumer_index) = consumer_index else {
            return PluginResult::Continue;
        };
        let Some(identity) = principal.principal else {
            return PluginResult::Continue;
        };

        // Namespace-correct Consumer mapping: a Consumer resolved by identity
        // only counts when it belongs to the matched proxy's namespace. A
        // cross-namespace match is treated as "no Consumer", so the request
        // still runs under the verified external principal rather than under
        // another tenant's Consumer record.
        let proxy_namespace = ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.namespace.clone());
        let consumer = proxy_namespace.and_then(|namespace| {
            consumer_index
                .find_by_identity(&identity)
                .filter(|consumer| consumer.namespace == namespace)
        });

        match auth_flow::commit_authentication_attempt(
            ctx,
            AuthenticationAttempt::new(),
            auth_flow::VerifyOutcome::Success {
                consumer,
                external_identity: Some(identity),
                external_identity_header: None,
            },
            SOAP_WS_SECURITY_AUTH_METHOD,
            true,
        ) {
            Ok(_) => PluginResult::Continue,
            Err(auth_flow::VerifyOutcome::Forbidden(body)) => PluginResult::Reject {
                status_code: 403,
                body,
                headers: HashMap::new(),
            },
            Err(_) => PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"WS-Security: identity could not be established"}"#.to_string(),
                headers: HashMap::new(),
            },
        }
    }
}

/// `auth_method` published for a SOAP-authenticated request.
const SOAP_WS_SECURITY_AUTH_METHOD: &str = "soap_ws_security";

// ── Composition admission (GHSA-gfrx-43w6-jq3c, GHSA-435h-f785-wmm4) ────────

/// Auth plugin names that participate in the central authentication chain.
///
/// Kept as a literal list rather than derived from constructed plugins because
/// composition is validated at config admission, before any plugin is built.
const CENTRAL_AUTH_PLUGIN_NAMES: &[&str] = &[
    "mtls_auth",
    "jwks_auth",
    "oauth2_introspection",
    "oidc_relying_party",
    "jwt_auth",
    "key_auth",
    "ldap_auth",
    "basic_auth",
    "hmac_auth",
];

/// Whether a `soap_ws_security` plugin config establishes a request principal
/// and therefore joins the authentication chain.
///
/// Read from raw JSON: composition is checked before construction, and a config
/// that fails its own admission is reported by that admission rather than here.
fn soap_config_establishes_identity(plugin: &crate::config::types::PluginConfig) -> bool {
    let inner_enabled = |key: &str| {
        plugin
            .config
            .get(key)
            .and_then(|section| section.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    inner_enabled("username_token") || inner_enabled("x509_signature") || inner_enabled("saml")
}

/// Whether a `compression` plugin config decodes the request body.
fn compression_config_decompresses_request(plugin: &crate::config::types::PluginConfig) -> bool {
    plugin
        .config
        .get("decompress_request")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Refuse compositions this plugin's ordering guarantees cannot survive.
///
/// Two of them:
///
/// 1. **Another authentication plugin in either auth mode.** Both modes stop
///    after the first mechanism establishes an identity, and single-auth also
///    makes the first rejection terminal. WS-Security is a message *gate*, not
///    one of several interchangeable credentials: since `soap_ws_security` is
///    the highest-numbered priority in the AuthN band, an earlier mechanism's
///    success would normally skip SOAP validation entirely. Multi-auth can also
///    let a later success override an earlier SOAP rejection when priorities
///    are overridden. A second identity-establishing SOAP instance is another
///    message gate with the same problem. The composition is refused rather
///    than silently reordered.
/// 2. **Request decompression on the same proxy.** SOAP authentication now runs
///    in the `authenticate` phase, which precedes the shared buffered-body
///    normalization phase where `compression`'s `decompress_request` decodes
///    the body. The plugin would therefore validate the encoded bytes rather
///    than the plaintext the backend parses. The runtime digest guard in
///    `on_final_request_body_with_context` would catch this on every request;
///    refusing it at admission turns a guaranteed 500 into a configuration
///    error the operator can act on.
pub fn validate_composition(
    config: &crate::config::types::GatewayConfig,
) -> Result<(), Vec<String>> {
    use crate::config::types::{AuthMode, PluginConfig, PluginScope};

    let plugin_by_scoped_id: HashMap<(&str, &str), &PluginConfig> = config
        .plugin_configs
        .iter()
        .map(|plugin| ((plugin.namespace.as_str(), plugin.id.as_str()), plugin))
        .collect();

    // Resolve the effective instances of `name` for `proxy` exactly the way the
    // runtime merge does: a scoped instance shadows the same-named global by
    // its outer `enabled` flag alone.
    let effective = |proxy: &crate::config::types::Proxy, name: &str| -> Vec<&PluginConfig> {
        let local: Vec<&PluginConfig> = proxy
            .plugins
            .iter()
            .filter_map(|association| {
                let plugin = *plugin_by_scoped_id.get(&(
                    proxy.namespace.as_str(),
                    association.plugin_config_id.as_str(),
                ))?;
                let scope_applies = match plugin.scope {
                    PluginScope::Proxy => plugin.proxy_id.as_deref() == Some(proxy.id.as_str()),
                    PluginScope::ProxyGroup => true,
                    PluginScope::Global => false,
                };
                (plugin.enabled && plugin.plugin_name == name && scope_applies).then_some(plugin)
            })
            .collect();
        if !local.is_empty() {
            return local;
        }
        config
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.enabled && plugin.scope == PluginScope::Global && plugin.plugin_name == name
            })
            .collect()
    };

    let mut errors = Vec::new();
    for proxy in &config.proxies {
        let soap: Vec<&PluginConfig> = effective(proxy, "soap_ws_security");
        if soap.is_empty() {
            continue;
        }
        let identity_soap: Vec<&PluginConfig> = soap
            .iter()
            .copied()
            .filter(|plugin| soap_config_establishes_identity(plugin))
            .collect();

        if !identity_soap.is_empty() {
            // A second identity-establishing SOAP instance is another
            // authentication plugin too. Every authentication mode may stop
            // after the first success, so every SOAP message gate must be the
            // sole identity mechanism on its effective proxy chain.
            let mut others: Vec<String> = identity_soap
                .iter()
                .skip(1)
                .map(|plugin| plugin.id.clone())
                .collect();
            others.extend(
                CENTRAL_AUTH_PLUGIN_NAMES
                    .iter()
                    .flat_map(|name| effective(proxy, name))
                    .map(|plugin| plugin.id.clone()),
            );
            if !others.is_empty() {
                let auth_mode = match &proxy.auth_mode {
                    AuthMode::Single => "single",
                    AuthMode::Multi => "multi",
                };
                errors.push(format!(
                    "soap_ws_security must be the sole authentication mechanism on proxy '{}' \
                     while auth_mode is '{}': both authentication modes stop after the first \
                     mechanism establishes an identity, single-auth also makes the first rejection \
                     terminal, and multi-auth can let a later success override an earlier rejection, \
                     so one or more WS-Security message gates would be skipped or ignored. \
                     soap_ws_security: {}; other auth plugins: {}. Disable the other mechanisms \
                     on this proxy",
                    proxy.id,
                    auth_mode,
                    identity_soap
                        .iter()
                        .map(|plugin| plugin.id.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                    others.join(", ")
                ));
            }
        }

        let decompressors: Vec<String> = effective(proxy, "compression")
            .into_iter()
            .filter(|plugin| compression_config_decompresses_request(plugin))
            .map(|plugin| plugin.id.clone())
            .collect();
        if !identity_soap.is_empty() && !decompressors.is_empty() {
            errors.push(format!(
                "soap_ws_security cannot be composed with compression 'decompress_request' on \
                 proxy '{}': SOAP identity is established in the authenticate phase, which runs \
                 before request-body decompression, so the gateway would validate the encoded \
                 bytes rather than the plaintext the backend parses. soap_ws_security: {}; \
                 compression: {}. Decompress upstream of the gateway, or disable \
                 decompress_request on this proxy",
                proxy.id,
                identity_soap
                    .iter()
                    .map(|plugin| plugin.id.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
                decompressors.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ── Plugin trait implementation ─────────────────────────────────────────────

#[async_trait]
impl Plugin for SoapWsSecurity {
    fn name(&self) -> &str {
        "soap_ws_security"
    }

    fn priority(&self) -> u16 {
        super::priority::SOAP_WS_SECURITY
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    /// The timestamp-only configuration keeps validating in `before_proxy`; an
    /// identity-establishing one moves to `authenticate` instead. The two are
    /// mutually exclusive, so no message is validated twice.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        !self.establishes_identity()
    }

    /// Body-aware authentication (GHSA-gfrx-43w6-jq3c).
    ///
    /// SOAP identity used to be established in `before_proxy`, after central
    /// authentication *and* authorization had already run — so `access_control`
    /// saw no consumer and consumer-scoped `rate_limiting` charged the source
    /// IP. Buffering before the authenticate phase lets the SOAP principal be
    /// the request's one authoritative identity for authorization, rate
    /// limiting, logging, retries, and chargeback.
    fn requires_request_body_before_authenticate(&self) -> bool {
        self.establishes_identity()
    }

    fn is_auth_plugin(&self) -> bool {
        self.establishes_identity()
    }

    fn needs_request_body_bytes(&self) -> bool {
        // SOAP may arrive as UTF-16 (or other non-UTF-8 XML encodings), and
        // MTOM/XOP packaging is binary framing. The shared proxy handoff only
        // populates metadata["request_body"] when std::str::from_utf8 succeeds,
        // so this plugin must retain raw bytes.
        true
    }

    fn needs_request_body_text(&self) -> bool {
        // Decode from request_body_bytes with strict BOM/charset rules instead
        // of relying on the UTF-8-only metadata copy.
        false
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.request_body_is_governed(ctx.headers.get("content-type").map(String::as_str))
    }

    fn should_buffer_request_body_before_authenticate(
        &self,
        ctx: &RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> bool {
        self.should_buffer_request_body(ctx)
    }

    /// The authenticated representation must still be the representation the
    /// backend receives. Running this hook unconditionally before dispatch is
    /// what makes the digest comparison below reachable for every governed
    /// request rather than only for requests some other plugin already forced
    /// the hook on.
    fn requires_final_request_body_before_backend_dispatch(&self) -> bool {
        self.establishes_identity()
    }

    /// Only the identity-establishing form records an authenticated-representation
    /// digest, so only it needs the request context in the final-body hook. A
    /// timestamp-only policy's hook can answer nothing but `Continue`, and
    /// returning `true` for it would make the proxy clone a request context on
    /// every governed request for no decision.
    fn needs_final_request_body_context(&self) -> bool {
        self.establishes_identity()
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        match &self.nonce_backend {
            NonceReplayBackend::Shared(client) => client.warmup_hostname().into_iter().collect(),
            NonceReplayBackend::Process(_) => Vec::new(),
        }
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        if !self.establishes_identity() {
            return PluginResult::Continue;
        }
        let content_type = ctx.headers.get("content-type").cloned();
        self.run_soap_policy(ctx, content_type, Some(consumer_index))
            .await
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // An identity-establishing policy already ran in `authenticate`.
        if self.establishes_identity() {
            return PluginResult::Continue;
        }
        // Read from `headers` param (not `ctx.headers`) because the handler may
        // temporarily move headers out of ctx when no plugin modifies them.
        let content_type = headers.get("content-type").cloned();
        self.run_soap_policy(ctx, content_type, None).await
    }

    /// Refuse to dispatch a message whose backend-visible bytes are no longer
    /// the bytes this policy authenticated.
    ///
    /// SOAP authentication now precedes the shared buffered-body normalization
    /// phase, so a later request-body transform could otherwise hand the
    /// backend an operation that was never signed. Admission additionally
    /// refuses the one composition that would do this systematically (see
    /// [`validate_composition`]); this is the runtime backstop for every other
    /// transform, including custom plugins.
    ///
    /// Only the identity-establishing form records the digest this compares
    /// against, so a timestamp-only policy — which authenticates nobody and
    /// makes no integrity claim — stays composable with request-body
    /// transformers instead of failing every governed request closed.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let Some(expected) = ctx.soap_ws_security_authenticated_body_digest else {
            return PluginResult::Continue;
        };
        if sha256_array(body) == expected {
            return PluginResult::Continue;
        }
        warn!(
            failure_class = "authenticated_body_mutated",
            "soap_ws_security: refusing to dispatch a SOAP message whose body changed after \
             WS-Security validation"
        );
        PluginResult::Reject {
            status_code: 500,
            body: r#"{"error":"WS-Security: the authenticated SOAP message was modified before backend dispatch"}"#
                .to_string(),
            headers: HashMap::new(),
        }
    }
}

// ── XML Exclusive Canonicalization helpers ─────────────────────────────────

struct CanonicalizationSpec {
    inclusive_prefixes: Vec<String>,
}

struct ReferenceTransforms {
    enveloped_signature: bool,
    inclusive_prefixes: Vec<String>,
}

fn parse_bounded_xml<'a>(xml: &'a str, context: &str) -> Result<Document<'a>, String> {
    Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_XML_NODES,
        },
    )
    .map_err(|error| {
        format!(
            "WS-Security: malformed or overly complex {} XML: {}",
            context, error
        )
    })
}

// ── Namespace-correct SOAP structure (GHSA-3mwq-c8j6-9xhp) ─────────────────
//
// Header / Security / Body used to be located by *local name* anywhere in the
// document, so a signed element under a namespace-confusable `<Body>` could be
// selected while the backend consumed the real, unsigned `soap:Body`. Every
// structural selection below is bound to an exact namespace URI and to an exact
// position in the envelope, and the whole document is checked for additional
// namespace-correct occurrences so a wrapped duplicate fails closed rather than
// creating a gateway/backend parser differential.

/// The one namespace-correct SOAP envelope this request is validated against.
///
/// Lifetimes mirror `roxmltree::Node<'a, 'input: 'a>`: `'a` is the borrow of
/// the parsed `Document`, and `'input` is the original XML text that document
/// borrows. Namespace URIs from `tag_name().namespace()` are `&'a str`.
struct SoapEnvelopeStructure<'a, 'input: 'a> {
    envelope_ns: &'a str,
    header: Option<Node<'a, 'input>>,
    /// The SOAP `Body` the backend will consume. X.509 signature coverage is
    /// proven against exactly this node.
    body: Node<'a, 'input>,
}

fn is_soap_envelope_namespace(namespace: &str) -> bool {
    namespace == SOAP11_ENVELOPE_NS || namespace == SOAP12_ENVELOPE_NS
}

/// Resolve exactly one `Envelope` / optional `Header` / exactly one `Body`,
/// all in the same SOAP envelope namespace, and reject any additional
/// namespace-correct `Envelope`/`Header`/`Body` element anywhere in the
/// document.
fn resolve_soap_envelope<'a, 'input: 'a>(
    document: &'a Document<'input>,
) -> Result<SoapEnvelopeStructure<'a, 'input>, String> {
    let envelope = document.root_element();
    let envelope_tag = envelope.tag_name();
    let Some(envelope_ns) = envelope_tag
        .namespace()
        .filter(|ns| is_soap_envelope_namespace(ns))
    else {
        return Err(
            "WS-Security: request root element is not a namespace-qualified SOAP Envelope"
                .to_string(),
        );
    };
    if envelope_tag.name() != "Envelope" {
        return Err(
            "WS-Security: request root element is not a namespace-qualified SOAP Envelope"
                .to_string(),
        );
    }

    let mut header = None;
    let mut body = None;
    for child in envelope.children().filter(Node::is_element) {
        let tag = child.tag_name();
        if tag.namespace() != Some(envelope_ns) {
            return Err(
                "WS-Security: SOAP Envelope contains a child outside the SOAP envelope namespace"
                    .to_string(),
            );
        }
        match tag.name() {
            "Header" => {
                if header.replace(child).is_some() {
                    return Err("WS-Security: SOAP Envelope has multiple Header elements".into());
                }
            }
            "Body" => {
                if body.replace(child).is_some() {
                    return Err("WS-Security: SOAP Envelope has multiple Body elements".into());
                }
            }
            _ => {
                return Err(
                    "WS-Security: SOAP Envelope contains an element other than Header and Body"
                        .to_string(),
                );
            }
        }
    }
    let Some(body) = body else {
        return Err("WS-Security: SOAP Envelope has no Body element".to_string());
    };
    if header.is_some_and(|header| header.next_sibling_element() != Some(body)) {
        return Err("WS-Security: SOAP Header must immediately precede the Body".to_string());
    }

    // A second namespace-correct Envelope/Header/Body anywhere else in the
    // document is the wrapping vector: the gateway would resolve one and a
    // tolerant backend the other. Nothing legitimate carries one.
    for node in document.descendants().filter(Node::is_element) {
        let tag = node.tag_name();
        if !tag.namespace().is_some_and(is_soap_envelope_namespace) {
            continue;
        }
        if !matches!(tag.name(), "Envelope" | "Header" | "Body") {
            continue;
        }
        let resolved = node == envelope || Some(node) == header || node == body;
        if !resolved {
            return Err(format!(
                "WS-Security: envelope contains a duplicate namespace-qualified SOAP {} element \
                 — possible XML signature wrapping",
                tag.name()
            ));
        }
    }

    Ok(SoapEnvelopeStructure {
        envelope_ns,
        header,
        body,
    })
}

/// Whether a `wsse:Security` header targets this receiver.
///
/// An absent `actor`/`role` means the ultimate receiver, which is the gateway
/// acting for the backend. `next` and (SOAP 1.2) `ultimateReceiver` also target
/// it. Headers addressed to some other intermediary are left alone — they are
/// not this policy's to enforce and must not be mistaken for it.
fn security_header_targets_receiver(node: Node<'_, '_>, envelope_ns: &str) -> bool {
    let addressed = if envelope_ns == SOAP11_ENVELOPE_NS {
        node.attribute((SOAP11_ENVELOPE_NS, "actor"))
    } else {
        node.attribute((SOAP12_ENVELOPE_NS, "role"))
    };
    match addressed.map(str::trim) {
        None | Some("") => true,
        Some(SOAP11_ACTOR_NEXT) | Some(SOAP12_ROLE_NEXT) | Some(SOAP12_ROLE_ULTIMATE_RECEIVER) => {
            true
        }
        Some(_) => false,
    }
}

/// Resolve the single `wsse:Security` header this gateway enforces.
///
/// Every `wsse:Security` element in the document must be a direct child of the
/// SOAP `Header`; one placed anywhere else (inside the Body, inside another
/// header block) is a wrapping attempt. Exactly one of them may target this
/// receiver.
fn resolve_security_node<'a, 'input: 'a>(
    document: &'a Document<'input>,
    structure: &SoapEnvelopeStructure<'a, 'input>,
) -> Result<Option<Node<'a, 'input>>, String> {
    let mut selected = None;
    for node in document.descendants().filter(Node::is_element) {
        let tag = node.tag_name();
        if tag.namespace() != Some(WSSE_NAMESPACE_URI) || tag.name() != "Security" {
            continue;
        }
        if structure.header != node.parent() {
            return Err(
                "WS-Security: a wsse:Security element appears outside the SOAP Header".to_string(),
            );
        }
        if !security_header_targets_receiver(node, structure.envelope_ns) {
            continue;
        }
        if selected.replace(node).is_some() {
            return Err(
                "WS-Security: multiple wsse:Security headers target this receiver".to_string(),
            );
        }
    }
    Ok(selected)
}

/// Exactly-one child element in a required namespace.
fn unique_ns_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &str,
    local_name: &str,
    context: &str,
) -> Result<Option<Node<'a, 'input>>, String> {
    let mut matches = parent
        .children()
        .filter(|node| node.has_tag_name((namespace, local_name)));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(format!(
            "{context}: multiple {local_name} elements are not allowed"
        ));
    }
    Ok(first)
}

/// Trimmed text of the single text child, or `None` when the element is empty.
fn element_text(node: Node<'_, '_>) -> Option<String> {
    let text = node.text()?.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Bounded, single-pass index of every XML id-bearing attribute in the
/// document.
///
/// Built once per validated message, after the signature is trusted, instead of
/// re-scanning the whole envelope per `<Reference>` — the
/// `O(references × body)` amplification of GHSA-9g4v-h9hm-846r. Counting spans
/// the broad set of id spellings a tolerant backend might resolve (`wsu:Id`,
/// bare `Id`, `ID`, `id`, `xml:id`) so a duplicate under any of them fails
/// closed.
///
/// Keys are `&'a str` because `roxmltree::Attribute::value()` returns a borrow
/// of the document (`&'a str`), not a direct `&'input str`.
struct DocumentIdIndex<'a, 'input: 'a> {
    entries: HashMap<&'a str, (usize, Node<'a, 'input>)>,
}

impl<'a, 'input: 'a> DocumentIdIndex<'a, 'input> {
    fn build(document: &'a Document<'input>) -> Self {
        let mut entries: HashMap<&'a str, (usize, Node<'a, 'input>)> = HashMap::new();
        for node in document.descendants().filter(Node::is_element) {
            for attribute in node.attributes() {
                if !is_xml_id_attribute(attribute.name(), attribute.namespace()) {
                    continue;
                }
                entries
                    .entry(attribute.value())
                    .and_modify(|(count, _)| *count += 1)
                    .or_insert((1, node));
            }
        }
        Self { entries }
    }

    /// The unique element bearing `id`, or an error naming how many carry it.
    fn resolve_unique(&self, id: &str) -> Result<Node<'a, 'input>, String> {
        match self.entries.get(id) {
            Some((1, node)) => Ok(*node),
            Some((count, _)) => Err(format!(
                "WS-Security: referenced id is not unique in the envelope ({count} occurrences) \
                 — possible XML signature wrapping"
            )),
            None => Err("WS-Security: referenced element not found".to_string()),
        }
    }
}

fn is_xml_id_attribute(name: &str, namespace: Option<&str>) -> bool {
    match namespace {
        None => matches!(name, "Id" | "ID" | "id"),
        Some(WSU_NAMESPACE_URI) => name == "Id",
        Some("http://www.w3.org/XML/1998/namespace") => name == "id",
        // Any other namespace-qualified `Id` a backend might resolve.
        Some(_) => name == "Id",
    }
}

/// Borrowed envelope state for [`SoapWsSecurity::verify_reference_digests`].
struct ReferenceDigestDocument<'ctx, 'a, 'i: 'a> {
    structure: &'ctx SoapEnvelopeStructure<'a, 'i>,
    id_index: &'ctx DocumentIdIndex<'a, 'i>,
    envelope: &'ctx str,
}

/// What a verified `SignedInfo` actually protects.
#[derive(Default)]
struct ReferenceCoverage {
    /// Node ids of every element a verified Reference resolved to.
    covered: Vec<NodeId>,
    /// Whether one of them is the namespace-correct backend-visible SOAP Body.
    covers_body: bool,
}

/// Whether `node` is `ancestor` or a descendant of it.
fn node_is_within(node: Node<'_, '_>, ancestor: Node<'_, '_>) -> bool {
    let ancestor_id = ancestor.id();
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.id() == ancestor_id {
            return true;
        }
        current = candidate.parent();
    }
    false
}

/// `KeyInfo/X509Data/X509Certificate` text, all three namespace-qualified and
/// each required to be unique.
fn xmldsig_key_info_certificate(
    signature: Node<'_, '_>,
    context: &str,
) -> Result<Option<String>, String> {
    let Some(key_info) = unique_ns_child(signature, XMLDSIG_NAMESPACE_URI, "KeyInfo", context)?
    else {
        return Ok(None);
    };
    let Some(x509_data) = unique_ns_child(key_info, XMLDSIG_NAMESPACE_URI, "X509Data", context)?
    else {
        return Ok(None);
    };
    let Some(certificate) =
        unique_ns_child(x509_data, XMLDSIG_NAMESPACE_URI, "X509Certificate", context)?
    else {
        return Ok(None);
    };
    Ok(element_text(certificate))
}

/// Aggregate canonicalization/scan work budget for one validated message.
///
/// Every `exclusive_canonicalize` charges both the source subtree it walks and
/// the canonical bytes it emits, so the total XML work one request can drive is
/// a small constant multiple of its own decoded body regardless of how many
/// References it declares or how they nest (GHSA-9g4v-h9hm-846r).
struct WorkBudget {
    remaining: usize,
}

impl WorkBudget {
    fn for_envelope(envelope: &str) -> Self {
        Self {
            remaining: envelope
                .len()
                .saturating_mul(CANONICALIZATION_BUDGET_MULTIPLIER)
                .max(MIN_CANONICALIZATION_BUDGET_BYTES),
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            "WS-Security: message exceeds the permitted XML canonicalization work budget"
                .to_string()
        })?;
        Ok(())
    }
}

fn parse_signed_info_canonicalization(
    signed_info: Node<'_, '_>,
    context: &str,
) -> Result<CanonicalizationSpec, String> {
    let method = unique_ns_child(
        signed_info,
        XMLDSIG_NAMESPACE_URI,
        "CanonicalizationMethod",
        context,
    )?
    .ok_or_else(|| format!("{}: SignedInfo missing CanonicalizationMethod", context))?;
    let algorithm = method.attribute("Algorithm").ok_or_else(|| {
        format!(
            "{}: CanonicalizationMethod missing Algorithm attribute",
            context
        )
    })?;
    if algorithm != XML_EXCLUSIVE_C14N {
        return Err(format!(
            "{}: unsupported CanonicalizationMethod algorithm '{}'",
            context, algorithm
        ));
    }

    Ok(CanonicalizationSpec {
        inclusive_prefixes: parse_inclusive_namespaces(method, context)?,
    })
}

fn parse_reference_transforms(
    reference: Node<'_, '_>,
    context: &str,
) -> Result<ReferenceTransforms, String> {
    let transforms = unique_ns_child(reference, XMLDSIG_NAMESPACE_URI, "Transforms", context)?
        .ok_or_else(|| {
            format!(
                "{}: Reference missing required exclusive-c14n Transform",
                context
            )
        })?;

    for child in transforms.children().filter(Node::is_element) {
        if !child.has_tag_name((XMLDSIG_NAMESPACE_URI, "Transform")) {
            return Err(format!(
                "{}: unsupported element '{}' inside Transforms",
                context,
                child.tag_name().name()
            ));
        }
    }

    let mut enveloped_signature = false;
    let mut inclusive_prefixes = None;
    let mut transform_count = 0usize;
    for transform in transforms
        .children()
        .filter(|node| node.has_tag_name((XMLDSIG_NAMESPACE_URI, "Transform")))
    {
        transform_count += 1;
        if transform_count > 2 {
            return Err(format!(
                "{}: unsupported Reference transform chain length",
                context
            ));
        }
        let algorithm = transform
            .attribute("Algorithm")
            .ok_or_else(|| format!("{}: Transform missing Algorithm attribute", context))?;
        match algorithm {
            XMLDSIG_ENVELOPED_SIGNATURE => {
                if enveloped_signature {
                    return Err(format!(
                        "{}: duplicate enveloped-signature Transform",
                        context
                    ));
                }
                if inclusive_prefixes.is_some() {
                    return Err(format!(
                        "{}: enveloped-signature Transform cannot follow canonicalization",
                        context
                    ));
                }
                if transform.children().any(|node| node.is_element()) {
                    return Err(format!(
                        "{}: enveloped-signature Transform parameters are unsupported",
                        context
                    ));
                }
                enveloped_signature = true;
            }
            XML_EXCLUSIVE_C14N => {
                if inclusive_prefixes.is_some() {
                    return Err(format!("{}: duplicate exclusive-c14n Transform", context));
                }
                inclusive_prefixes = Some(parse_inclusive_namespaces(transform, context)?);
            }
            other => {
                return Err(format!(
                    "{}: unsupported Transform algorithm '{}'",
                    context, other
                ));
            }
        }
    }

    let inclusive_prefixes = inclusive_prefixes.ok_or_else(|| {
        format!(
            "{}: Reference transform chain does not include exclusive c14n",
            context
        )
    })?;

    Ok(ReferenceTransforms {
        enveloped_signature,
        inclusive_prefixes,
    })
}

fn parse_inclusive_namespaces(
    algorithm_node: Node<'_, '_>,
    context: &str,
) -> Result<Vec<String>, String> {
    let mut parameter = None;
    for child in algorithm_node.children().filter(Node::is_element) {
        if child.tag_name().name() != "InclusiveNamespaces"
            || child.tag_name().namespace() != Some(XML_EXCLUSIVE_C14N)
        {
            return Err(format!(
                "{}: unsupported canonicalization parameter '{}'",
                context,
                child.tag_name().name()
            ));
        }
        if parameter.replace(child).is_some() {
            return Err(format!(
                "{}: multiple InclusiveNamespaces parameters are not allowed",
                context
            ));
        }
    }

    let Some(parameter) = parameter else {
        return Ok(Vec::new());
    };
    let prefix_list = parameter
        .attribute("PrefixList")
        .ok_or_else(|| format!("{}: InclusiveNamespaces missing PrefixList", context))?;
    if prefix_list.len() > MAX_INCLUSIVE_PREFIX_LIST_BYTES {
        return Err(format!(
            "{}: InclusiveNamespaces PrefixList exceeds {} bytes",
            context, MAX_INCLUSIVE_PREFIX_LIST_BYTES
        ));
    }
    let mut prefixes = Vec::new();
    for token in prefix_list.split_whitespace() {
        if prefixes.len() >= MAX_INCLUSIVE_NAMESPACE_PREFIXES {
            return Err(format!(
                "{}: InclusiveNamespaces PrefixList contains more than {} prefixes",
                context, MAX_INCLUSIVE_NAMESPACE_PREFIXES
            ));
        }
        let prefix = if token == "#default" { "" } else { token };
        if token == "xmlns" || token.contains(':') || token.starts_with('#') && token != "#default"
        {
            return Err(format!(
                "{}: invalid InclusiveNamespaces prefix '{}'",
                context, token
            ));
        }
        if !prefixes.iter().any(|existing| existing == prefix) {
            prefixes.push(prefix.to_string());
        }
    }
    Ok(prefixes)
}

fn exclusive_canonicalize(
    xml: &str,
    root: Node<'_, '_>,
    inclusive_prefixes: &[String],
    excluded_node: Option<NodeId>,
    budget: &mut WorkBudget,
) -> Result<Vec<u8>, String> {
    if !root.is_element() {
        return Err("WS-Security: exclusive c14n requires an element node".to_string());
    }

    // Charge the subtree before walking it, so an over-budget request is
    // refused without doing the work, then charge the complete emitted
    // canonical representation. Both sides are needed: the source bounds the
    // walk, while the output bounds the allocation and digest input. Charging
    // only output expansion would account for max(source, output), not the
    // documented source + output work.
    let source_len = root.range().len();
    budget.charge(source_len)?;
    let mut output = String::with_capacity(source_len);
    let mut rendered_namespaces = HashMap::new();
    rendered_namespaces.insert(
        "xml".to_string(),
        "http://www.w3.org/XML/1998/namespace".to_string(),
    );
    canonicalize_node(
        xml,
        root,
        inclusive_prefixes,
        excluded_node,
        0,
        &mut rendered_namespaces,
        &mut output,
    )?;
    budget.charge(output.len())?;
    Ok(output.into_bytes())
}

// Reached only via the lib target's `_test_support` shim (external unit tests);
// the bin target duplicates the module tree with no caller, so it sees this as
// dead code.
#[allow(dead_code)]
pub(crate) fn exclusive_canonicalize_element_for_test(
    xml: &str,
    local_name: &str,
    prefix_list: &str,
) -> Result<String, String> {
    let document = parse_bounded_xml(xml, "test fixture")?;
    let root = document
        .descendants()
        .find(|node| node.has_tag_name(local_name))
        .ok_or_else(|| format!("WS-Security: test fixture missing {}", local_name))?;
    let prefixes = prefix_list
        .split_whitespace()
        .map(|prefix| {
            if prefix == "#default" {
                String::new()
            } else {
                prefix.to_string()
            }
        })
        .collect::<Vec<_>>();
    let mut budget = WorkBudget::for_envelope(xml);
    let canonical = exclusive_canonicalize(xml, root, &prefixes, None, &mut budget)?;
    String::from_utf8(canonical).map_err(|_| "WS-Security: canonical XML was not UTF-8".to_string())
}

fn canonicalize_node(
    xml: &str,
    node: Node<'_, '_>,
    inclusive_prefixes: &[String],
    excluded_node: Option<NodeId>,
    depth: usize,
    rendered_namespaces: &mut HashMap<String, String>,
    output: &mut String,
) -> Result<(), String> {
    if depth > MAX_CANONICALIZATION_DEPTH {
        return Err(format!(
            "WS-Security: exclusive c14n depth exceeds {} elements",
            MAX_CANONICALIZATION_DEPTH
        ));
    }
    if excluded_node == Some(node.id()) {
        return Ok(());
    }

    if node.is_text() {
        if let Some(text) = node.text() {
            push_canonical_text(output, text);
        }
        return Ok(());
    }
    if node.is_comment() {
        return Ok(());
    }
    if let Some(pi) = node.pi() {
        output.push_str("<?");
        output.push_str(pi.target);
        if let Some(value) = pi.value {
            output.push(' ');
            output.push_str(value);
        }
        output.push_str("?>");
        return Ok(());
    }
    if !node.is_element() {
        return Ok(());
    }

    let qname = element_qname(xml, node)?;
    output.push('<');
    output.push_str(qname);

    let mut required_prefixes: Vec<(&str, bool)> = inclusive_prefixes
        .iter()
        .map(|prefix| (prefix.as_str(), false))
        .collect();
    let element_prefix = qname
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .unwrap_or("");
    add_required_prefix(&mut required_prefixes, element_prefix, true);

    let mut attributes = Vec::new();
    for attribute in node.attributes() {
        let qname_range = attribute.range_qname();
        let attribute_qname = xml.get(qname_range).ok_or_else(|| {
            "WS-Security: XML parser returned an invalid attribute range".to_string()
        })?;
        if let Some((prefix, _)) = attribute_qname.split_once(':') {
            add_required_prefix(&mut required_prefixes, prefix, true);
        }
        attributes.push((
            attribute.namespace().unwrap_or(""),
            attribute.name(),
            attribute_qname,
            attribute.value(),
        ));
    }

    let mut namespace_declarations = Vec::new();
    for (prefix, required) in required_prefixes {
        if prefix == "xml" {
            continue;
        }
        let namespace_uri = if prefix.is_empty() {
            node.lookup_namespace_uri(None).unwrap_or("")
        } else if let Some(uri) = node.lookup_namespace_uri(Some(prefix)) {
            uri
        } else if required {
            return Err(format!(
                "WS-Security: visibly used namespace prefix '{}' is not bound",
                prefix
            ));
        } else {
            continue;
        };

        let already_rendered = rendered_namespaces
            .get(prefix)
            .map(String::as_str)
            .unwrap_or("");
        if namespace_uri != already_rendered {
            namespace_declarations.push((prefix.to_string(), namespace_uri.to_string()));
        }
    }
    namespace_declarations.sort_by(|left, right| left.0.cmp(&right.0));

    let mut namespace_history = Vec::new();
    for (prefix, uri) in namespace_declarations {
        namespace_history.push((prefix.clone(), rendered_namespaces.get(&prefix).cloned()));
        rendered_namespaces.insert(prefix.clone(), uri.clone());
        output.push_str(" xmlns");
        if !prefix.is_empty() {
            output.push(':');
            output.push_str(&prefix);
        }
        output.push_str("=\"");
        push_canonical_attribute_value(output, &uri);
        output.push('"');
    }

    attributes.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    for (_, _, qname, value) in attributes {
        output.push(' ');
        output.push_str(qname);
        output.push_str("=\"");
        push_canonical_attribute_value(output, value);
        output.push('"');
    }
    output.push('>');

    for child in node.children() {
        canonicalize_node(
            xml,
            child,
            inclusive_prefixes,
            excluded_node,
            depth + usize::from(child.is_element()),
            rendered_namespaces,
            output,
        )?;
    }

    output.push_str("</");
    output.push_str(qname);
    output.push('>');

    for (prefix, previous) in namespace_history.into_iter().rev() {
        if let Some(uri) = previous {
            rendered_namespaces.insert(prefix, uri);
        } else {
            rendered_namespaces.remove(&prefix);
        }
    }
    Ok(())
}

fn add_required_prefix<'a>(prefixes: &mut Vec<(&'a str, bool)>, prefix: &'a str, required: bool) {
    if let Some((_, existing_required)) = prefixes
        .iter_mut()
        .find(|(existing, _)| *existing == prefix)
    {
        *existing_required |= required;
    } else {
        prefixes.push((prefix, required));
    }
}

fn element_qname<'a>(xml: &'a str, node: Node<'_, '_>) -> Result<&'a str, String> {
    let range = node.range();
    let source = xml
        .get(range.start..range.end)
        .ok_or_else(|| "WS-Security: XML parser returned an invalid element range".to_string())?;
    let name = extract_full_tag_name_from_tag(source.strip_prefix('<').unwrap_or(source))
        .ok_or_else(|| "WS-Security: canonicalized element has no qualified name".to_string())?;
    Ok(name)
}

fn push_canonical_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            other => output.push(other),
        }
    }
}

fn push_canonical_attribute_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            other => output.push(other),
        }
    }
}

fn extract_full_tag_name_from_tag(tag: &str) -> Option<&str> {
    let trimmed = tag.trim_start();
    let end = trimmed
        .find([' ', '>', '/', '\t', '\n', '\r'])
        .unwrap_or(trimmed.len());
    if end == 0 {
        None
    } else {
        Some(&trimmed[..end])
    }
}

fn scan_tag_attributes<F>(tag: &str, mut on_attr: F) -> bool
where
    F: FnMut(&str, &str) -> bool,
{
    let bytes = tag.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'/' {
        i += 1;
    }

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b'/' {
            break;
        }

        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/')
        {
            i += 1;
        }
        let name = &tag[name_start..i];

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let Some(&quote) = bytes.get(i) else {
            break;
        };
        if !matches!(quote, b'\'' | b'"') {
            continue;
        }
        i += 1;
        let value_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let value = &tag[value_start..i];
        i += 1;

        if on_attr(name, value) {
            return true;
        }
    }

    false
}

/// Count how many start tags in `xml` bear the given XML id attribute value.
/// Used to reject XML Signature Wrapping (XSW): a signed reference whose id
/// appears on more than one element means an attacker injected a duplicate, so
/// the byte range the signature covers may differ from the element a backend
/// consumes.
///
/// The resolver still accepts WS-Security `*:Id` / bare `Id`, but this security
/// gate intentionally counts broader id spellings (`xml:id`, `ID`, `id`) so a
/// backend with broader fragment resolution fails closed. Scanning only start
/// tags avoids rejecting a legitimate request merely because body text contains
/// `Id="..."`. Comments, CDATA, processing instructions, and declarations are
/// skipped as non-element spans. Unlike the narrower extraction helpers, this
/// full-envelope scan treats malformed start tags as errors rather than
/// returning a partial count.
///
/// Single-id convenience wrapper over [`count_raw_id_occurrences`], reached only
/// through `lib::_test_support`; the request path scans the whole `SignedInfo` in
/// one pass. The binary target compiles this module without that facade.
#[allow(dead_code)]
pub(crate) fn count_wsu_id_occurrences(xml: &str, id: &str) -> Result<usize, String> {
    Ok(count_raw_id_occurrences(xml, &[id])?[0])
}

/// Count raw start-tag id occurrences for several ids in **one** pass.
///
/// Scanning per Reference made the guard itself `O(references × body)`, which
/// is half of what GHSA-9g4v-h9hm-846r measures. One pass answers the whole
/// `SignedInfo` at once; the returned counts are positionally aligned with
/// `ids`.
pub(crate) fn count_raw_id_occurrences(xml: &str, ids: &[&str]) -> Result<Vec<usize>, String> {
    let mut counts = vec![0usize; ids.len()];
    if ids.is_empty() {
        return Ok(counts);
    }
    let mut search_from = 0usize;
    while let Some(rel) = xml[search_from..].find('<') {
        let tag_start = search_from + rel;
        let Some(after_lt) = xml.as_bytes().get(tag_start + 1) else {
            return Err(
                "WS-Security: malformed XML start tag while scanning referenced ids".into(),
            );
        };
        if *after_lt == b'/' {
            search_from = tag_start + 1;
            continue;
        }
        if *after_lt == b'!' {
            search_from = skip_markup_declaration(xml, tag_start)?;
            continue;
        }
        if *after_lt == b'?' {
            search_from = skip_processing_instruction(xml, tag_start)?;
            continue;
        }

        let tag_end_rel = find_start_tag_end(xml, tag_start).ok_or_else(|| {
            "WS-Security: malformed XML start tag while scanning referenced ids".to_string()
        })?;
        let tag = &xml[tag_start + 1..tag_start + tag_end_rel];
        count_id_attributes_in_tag(tag, ids, &mut counts);
        search_from = tag_start + tag_end_rel + 1;
    }
    Ok(counts)
}

fn skip_markup_declaration(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;

    if from_start.starts_with("<!--") {
        return from_start
            .find("-->")
            .map(|end_rel| tag_start + end_rel + "-->".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML comment while scanning referenced ids".to_string()
            });
    }

    if from_start.starts_with("<![CDATA[") {
        return from_start
            .find("]]>")
            .map(|end_rel| tag_start + end_rel + "]]>".len())
            .ok_or_else(|| {
                "WS-Security: malformed XML CDATA while scanning referenced ids".to_string()
            });
    }

    let decl_end_rel = find_markup_declaration_end(xml, tag_start).ok_or_else(|| {
        "WS-Security: malformed XML declaration while scanning referenced ids".to_string()
    })?;
    Ok(tag_start + decl_end_rel + 1)
}

fn skip_processing_instruction(xml: &str, tag_start: usize) -> Result<usize, String> {
    let from_start = xml.get(tag_start..).ok_or_else(|| {
        "WS-Security: malformed XML processing instruction while scanning referenced ids"
            .to_string()
    })?;

    from_start
        .find("?>")
        .map(|end_rel| tag_start + end_rel + "?>".len())
        .ok_or_else(|| {
            "WS-Security: malformed XML processing instruction while scanning referenced ids"
                .to_string()
        })
}

/// Return the byte offset, relative to `tag_start`, of the end of a `<!...>`
/// declaration. Comments and CDATA have custom terminators and are handled
/// before this helper is called.
fn find_markup_declaration_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if !bytes.starts_with(b"<!") {
        return None;
    }

    let mut quote = None;
    let mut bracket_depth = 0usize;
    let mut i = 2usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'[' => bracket_depth = bracket_depth.saturating_add(1),
            None if bytes[i] == b']' => bracket_depth = bracket_depth.saturating_sub(1),
            None if bytes[i] == b'>' && bracket_depth == 0 => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

/// Return the byte offset, relative to `tag_start`, of the first unquoted `>`.
/// `tag_start` must point at `<`; malformed or unterminated start tags return
/// `None` so callers can fail closed instead of scanning a partial envelope.
fn find_start_tag_end(xml: &str, tag_start: usize) -> Option<usize> {
    debug_assert_eq!(xml.as_bytes().get(tag_start), Some(&b'<'));
    let bytes = xml.as_bytes().get(tag_start..)?;
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let mut quote = None;
    let mut i = 1usize;

    while i < bytes.len() {
        match quote {
            Some(q) if bytes[i] == q => quote = None,
            Some(_) => {}
            None if matches!(bytes[i], b'\'' | b'"') => quote = Some(bytes[i]),
            None if bytes[i] == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }

    None
}

fn count_id_attributes_in_tag(tag: &str, ids: &[&str], counts: &mut [usize]) {
    scan_tag_attributes(tag, |name, value| {
        if is_xml_id_attribute_name(name) {
            for (index, id) in ids.iter().enumerate() {
                if value == *id {
                    counts[index] += 1;
                }
            }
        }
        false
    });
}

fn is_xml_id_attribute_name(name: &str) -> bool {
    matches!(name, "Id" | "xml:id" | "ID" | "id")
        || name
            .rsplit_once(':')
            .is_some_and(|(_, local_name)| local_name == "Id")
}

/// Resolve the signing certificate from a SAML `<Signature>` block.
///
/// SAML signatures conventionally carry the signing cert inline in
/// `KeyInfo/X509Data/X509Certificate`. A `BinarySecurityToken` reference is
/// also accepted for symmetry with the WS-Security X.509 path, though that
/// is unusual for SAML.
fn extract_saml_signing_cert(signature: Node<'_, '_>) -> Result<Vec<u8>, String> {
    if let Some(cert_b64) = xmldsig_key_info_certificate(signature, "WS-Security: SAML")? {
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| format!("WS-Security: SAML invalid X509Certificate base64: {}", e));
    }

    if let Some(key_info) = unique_ns_child(
        signature,
        XMLDSIG_NAMESPACE_URI,
        "KeyInfo",
        "WS-Security: SAML",
    )? && let Some(bst) = unique_ns_child(
        key_info,
        WSSE_NAMESPACE_URI,
        "BinarySecurityToken",
        "WS-Security: SAML",
    )? {
        let cert_b64 = element_text(bst)
            .ok_or_else(|| "WS-Security: SAML BinarySecurityToken has no content".to_string())?;
        return BASE64
            .decode(cert_b64.replace(char::is_whitespace, "").as_bytes())
            .map_err(|e| {
                format!(
                    "WS-Security: SAML invalid BinarySecurityToken base64: {}",
                    e
                )
            });
    }

    Err(
        "WS-Security: SAML signature has no signing certificate (expected X509Certificate in KeyInfo)"
            .to_string(),
    )
}

/// Extract a bare RFC 8017 `RSAPublicKey` DER from a parsed X.509 cert,
/// rejecting non-RSA keys and malformed encodings at load time.
///
/// Both the WS-Security X.509 trust store and the SAML `trusted_signing_certs`
/// trust store funnel cert PEMs through this helper so the verifier always
/// sees the bare `RSAPublicKey` that `ring::signature::RSA_PKCS1_*` expects —
/// passing a full `SubjectPublicKeyInfo` would reject every signature with
/// a generic parse error.
///
/// The returned error string already includes a leading context phrase
/// ("is not an RSA public key …", "RSA SPKI BIT STRING has …", "has
/// malformed RSA public key DER: …"), so callers prepend their own cert
/// path and surrounding identification.
fn load_rsa_public_key_from_cert(cert: &X509Certificate<'_>) -> Result<Vec<u8>, String> {
    let public_key_info = cert.public_key();

    // Defense-in-depth: this plugin only supports RSA-PKCS#1 v1.5 signature
    // verification (rsa-sha256 / rsa-sha1). A non-RSA cert (e.g. ECDSA P-256)
    // would otherwise load silently and surface at request time as a generic
    // "signature verification failed" message, making the misconfiguration
    // hard to diagnose. Reject at load with a precise error.
    if public_key_info.algorithm.algorithm != oid_registry::OID_PKCS1_RSAENCRYPTION {
        return Err(format!(
            "is not an RSA public key (algorithm OID '{}', expected \
             '1.2.840.113549.1.1.1' / rsaEncryption); only RSA certificates \
             are supported for WS-Security signature verification",
            public_key_info.algorithm.algorithm,
        ));
    }

    // An RSA SubjectPublicKeyInfo encapsulates the RSAPublicKey in a BIT
    // STRING whose `unused_bits` MUST be 0 (the contents are byte-aligned
    // DER). Anything else is a malformed cert.
    if public_key_info.subject_public_key.unused_bits != 0 {
        return Err(format!(
            "RSA SPKI BIT STRING has {} unused bits (expected 0)",
            public_key_info.subject_public_key.unused_bits,
        ));
    }

    // Ring's `RSA_PKCS1_*` verification algorithms expect a bare RFC 8017
    // §A.1.1 `RSAPublicKey` (modulus + exponent), NOT a full RFC 5280
    // `SubjectPublicKeyInfo` (which wraps the key with the algorithm
    // identifier OID). For RSA SPKI the inner `subject_public_key` BitString
    // contents ARE that bare `RSAPublicKey` encoding, so use that directly
    // instead of `public_key().raw` (which is the entire SPKI DER) —
    // passing SPKI bytes makes `UnparsedPublicKey::verify` fail to parse
    // the key and reject every signature regardless of validity.
    let public_key_der = public_key_info.subject_public_key.data.to_vec();

    // Structural framing guard: an `RSAPublicKey` DER is a top-level
    // SEQUENCE whose declared length matches the buffer length. This rejects
    // truncated data, trailing bytes, and invalid DER length encodings before
    // the key reaches ring. It cannot distinguish a bare `RSAPublicKey` from
    // a complete `SubjectPublicKeyInfo`, because both are independently
    // well-formed SEQUENCE values; the extraction above and end-to-end
    // signature tests enforce that distinction.
    validate_rsa_public_key_der_shape(&public_key_der)
        .map_err(|e| format!("has malformed RSA public key DER: {}", e))?;

    Ok(public_key_der)
}

/// Structural sanity check: `der` must be a top-level DER `SEQUENCE` whose
/// declared length matches the buffer length exactly. This checks only the
/// outer framing of an RFC 8017 `RSAPublicKey ::= SEQUENCE { modulus,
/// publicExponent }`; ring parses the inner integers at verify time. This
/// framing check rejects invalid DER length encodings, truncation, and
/// trailing bytes. It does not by itself distinguish this sequence from
/// another well-formed DER sequence such as a complete `SubjectPublicKeyInfo`.
fn validate_rsa_public_key_der_shape(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("public key DER is empty".to_string());
    }
    if der[0] != 0x30 {
        return Err(format!(
            "expected DER SEQUENCE tag (0x30) at offset 0, got 0x{:02x}",
            der[0]
        ));
    }
    if der.len() < 2 {
        return Err("DER is truncated before length octet".to_string());
    }

    let first_len = der[1];
    let (declared_content_len, header_len) = if first_len & 0x80 == 0 {
        // Short-form: single-byte length, value 0..=127.
        ((first_len & 0x7f) as usize, 2)
    } else {
        // Long-form: low 7 bits give number of length octets that follow.
        let n = (first_len & 0x7f) as usize;
        if n == 0 {
            return Err("indefinite-length encoding is not valid DER".to_string());
        }
        if n > 4 {
            return Err(format!(
                "length uses {n} octets (refusing to parse > 4; a 4-octet length covers 4 GiB)"
            ));
        }
        if der.len() < 2 + n {
            return Err("DER is truncated inside length encoding".to_string());
        }
        let mut declared: usize = 0;
        for &b in &der[2..2 + n] {
            declared = (declared << 8) | b as usize;
        }
        (declared, 2 + n)
    };

    let expected_total = header_len
        .checked_add(declared_content_len)
        .ok_or_else(|| "declared length overflows usize".to_string())?;

    if expected_total != der.len() {
        return Err(format!(
            "length mismatch: header declares {declared_content_len} content bytes \
             ({expected_total}-byte total), buffer is {} bytes",
            der.len()
        ));
    }

    Ok(())
}

/// Decode PEM to DER bytes (handles the common CERTIFICATE block).
fn extract_pem_der(pem: &str) -> Option<Vec<u8>> {
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem.find(start_marker)? + start_marker.len();
    // Search only after the matching BEGIN marker. An attacker-controlled
    // inline source may contain an earlier END marker; slicing with that
    // offset would otherwise panic during configuration admission.
    let end = start + pem.get(start..)?.find(end_marker)?;

    let b64 = pem[start..end].replace(char::is_whitespace, "");
    BASE64.decode(b64.as_bytes()).ok()
}

/// Classify certificate-shaped input as inline material even when its PEM
/// markers are malformed or out of order. Passing such hostile input through
/// the generic path fallback would make the filesystem error echo the entire
/// configured value before the redacted PEM parser can reject it.
fn parse_trusted_certificate_source(raw: &str) -> CertSource {
    if raw.contains("-----BEGIN CERTIFICATE-----") || raw.contains("-----END CERTIFICATE-----") {
        CertSource::InlinePem(SecretString::new(raw.to_string()))
    } else {
        CertSource::parse(raw, MaterialKind::Cert)
    }
}

fn contains_forbidden_xml_declaration(xml: &str) -> bool {
    contains_ascii_case_insensitive(xml, "<!doctype")
        || contains_ascii_case_insensitive(xml, "<!entity")
}

/// Encoding rejection at the SOAP hostile-input boundary.
///
/// Messages are stable and body-free so logs/responses never echo credentials
/// or envelope contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoapBodyDecodeError {
    UnsupportedCharset,
    ConflictingCharset,
    MalformedEncoding,
}

impl SoapBodyDecodeError {
    fn status_code(self) -> u16 {
        match self {
            Self::UnsupportedCharset | Self::ConflictingCharset => 415,
            Self::MalformedEncoding => 400,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::UnsupportedCharset => "SOAP request uses an unsupported character encoding",
            Self::ConflictingCharset => {
                "SOAP request character encoding metadata is conflicting or ambiguous"
            }
            Self::MalformedEncoding => "SOAP request body is not valid for its character encoding",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::UnsupportedCharset => "unsupported_charset",
            Self::ConflictingCharset => "conflicting_charset",
            Self::MalformedEncoding => "malformed_encoding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoapXmlEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl SoapXmlEncoding {
    fn accepts_xml_decl_label(self, label: &str) -> bool {
        match self {
            Self::Utf8 => matches_utf8_label(label),
            // XML declarations commonly say encoding="UTF-16" without endianness;
            // the BOM / Content-Type already fixed the endian form.
            Self::Utf16Le | Self::Utf16Be => {
                matches_utf16_unspecified_label(label)
                    || (self == Self::Utf16Le && matches_utf16le_label(label))
                    || (self == Self::Utf16Be && matches_utf16be_label(label))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclaredCharset {
    Utf8,
    Utf16Le,
    Utf16Be,
    /// `charset=utf-16` without an endian hint — BOM required.
    Utf16Unspecified,
}

fn resolve_soap_request_body<'a>(
    ctx: &'a RequestContext,
    content_type: &str,
    media_class: &SoapMediaClass,
) -> Result<Option<Cow<'a, str>>, SoapBodyDecodeError> {
    if let Some(bytes) = ctx.request_body_bytes.as_ref() {
        if bytes.is_empty() {
            return Ok(None);
        }
        let (envelope_bytes, envelope_content_type) = match media_class {
            // A bare XOP infoset has no package around it, so like plain XML the
            // whole body is the envelope. It is only classified apart so an
            // integrity-claiming policy can refuse it.
            SoapMediaClass::Xml | SoapMediaClass::Xop => (&bytes[..], Cow::Borrowed(content_type)),
            SoapMediaClass::Mtom { boundary, start } => {
                let part = extract_mtom_root_part(bytes, boundary, start.as_deref())?;
                (part.body, Cow::Owned(part.content_type))
            }
        };
        if envelope_bytes.is_empty() {
            return Ok(None);
        }
        return decode_soap_xml_body(envelope_bytes, &envelope_content_type).map(Some);
    }
    // Fixture-only fallback: production prefers raw bytes. Still enforce the
    // UTF-8 XML-declaration contract so encoding validation is not bypassed.
    // MTOM is never reachable here: the multipart wrapper is binary framing and
    // the shared UTF-8 metadata copy is not a representation it can be unpacked
    // from, so it fails closed rather than validating the wrong bytes.
    if matches!(media_class, SoapMediaClass::Mtom { .. }) {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }
    match ctx.metadata.get("request_body") {
        Some(body) if body.is_empty() => Ok(None),
        Some(body) => {
            validate_xml_declaration_encoding(body, SoapXmlEncoding::Utf8)?;
            Ok(Some(Cow::Borrowed(body.as_str())))
        }
        None => Ok(None),
    }
}

/// The SOAP root part of an MTOM/XOP `multipart/related` body.
#[derive(Debug, PartialEq, Eq)]
struct MtomRootPart<'a> {
    body: &'a [u8],
    /// The part's own `Content-Type`, which carries the envelope's charset.
    content_type: String,
}

/// One framed MIME part of an MTOM/XOP package.
///
/// Only the three headers that decide *which* envelope is validated are kept;
/// every other header is syntax-checked and discarded. Attachment payloads are
/// never read, decoded, or validated.
struct MtomPart<'a> {
    content_type: Option<&'a str>,
    content_id: Option<String>,
    transfer_encoding: Option<&'a str>,
    body: &'a [u8],
}

/// A recognized boundary delimiter *line*.
struct MtomDelimiter {
    /// Offset of the first `-` of `--boundary`.
    line_start: usize,
    /// Offset just past the delimiter line, i.e. past its terminating CRLF (or
    /// at end of input for a closing delimiter that ends the body).
    next: usize,
    closing: bool,
}

/// Classify what follows `--boundary` on a candidate delimiter line.
///
/// Returns how many bytes the line occupies after the boundary token plus
/// whether this is the closing delimiter, or `None` when the candidate is not a
/// delimiter line at all — in which case those bytes are payload and the scan
/// continues past them.
///
/// Framing is exact CRLF and nothing else. RFC 2046 transport padding is
/// deliberately *not* accepted: a padded delimiter is precisely the construct
/// one parser treats as framing and another as payload, and rejecting it fails
/// closed instead of choosing a reading the backend may not share.
fn mtom_delimiter_tail(rest: &[u8]) -> Option<(usize, bool)> {
    let Some(after_dashes) = rest.strip_prefix(b"--") else {
        // A part delimiter line ends in exactly CRLF and nothing else.
        return rest.starts_with(b"\r\n").then_some((2, false));
    };
    // Close-delimiter. RFC 2046 allows an epilogue after its CRLF, and allows
    // the body to simply end here.
    if after_dashes.starts_with(b"\r\n") {
        return Some((4, true));
    }
    if after_dashes.is_empty() {
        return Some((2, true));
    }
    None
}

/// A bounded, line-anchored scanner over one package's delimiter lines.
///
/// A delimiter line exists only at the very start of the body or immediately
/// after a CRLF. That anchoring is what makes an embedded `--boundary`
/// substring inside a preamble, a header value, or an attachment payload inert
/// here — exactly as it is inert for a conforming backend parser. An unanchored
/// byte-substring search would instead let an attacker plant a fake part inside
/// a payload and have Ferrum validate it while the backend consumed the real
/// root part (GHSA-435h-f785-wmm4).
struct MtomScanner<'a> {
    bytes: &'a [u8],
    dash_boundary: Vec<u8>,
    crlf_dash_boundary: Vec<u8>,
    /// Delimiter-line candidates examined so far, across the whole package.
    candidates: usize,
}

impl<'a> MtomScanner<'a> {
    fn new(bytes: &'a [u8], boundary: &str) -> Self {
        let dash_boundary = format!("--{boundary}").into_bytes();
        let mut crlf_dash_boundary = Vec::with_capacity(dash_boundary.len() + 2);
        crlf_dash_boundary.extend_from_slice(b"\r\n");
        crlf_dash_boundary.extend_from_slice(&dash_boundary);
        Self {
            bytes,
            dash_boundary,
            crlf_dash_boundary,
            candidates: 0,
        }
    }

    /// The next delimiter line at or after `from`, or `Ok(None)` when the
    /// package has none left.
    fn next_from(&mut self, from: usize) -> Result<Option<MtomDelimiter>, SoapBodyDecodeError> {
        let mut search = from;
        loop {
            let line_start = if search == 0 && self.bytes.starts_with(&self.dash_boundary) {
                0
            } else {
                let Some(tail) = self.bytes.get(search..) else {
                    return Ok(None);
                };
                match find_subslice(tail, &self.crlf_dash_boundary) {
                    // The line starts *after* the CRLF that introduces it.
                    Some(offset) => search + offset + 2,
                    None => return Ok(None),
                }
            };
            self.candidates += 1;
            if self.candidates > MAX_MULTIPART_DELIMITER_CANDIDATES {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            }
            let after_boundary = line_start + self.dash_boundary.len();
            let rest = self
                .bytes
                .get(after_boundary..)
                .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
            if let Some((tail_len, closing)) = mtom_delimiter_tail(rest) {
                return Ok(Some(MtomDelimiter {
                    line_start,
                    next: after_boundary + tail_len,
                    closing,
                }));
            }
            // Boundary-shaped bytes that are not a delimiter line. Skip past
            // them and keep scanning; they belong to whatever part is being
            // framed. `dash_boundary` is at least three bytes, so the scan
            // always advances.
            search = after_boundary;
        }
    }

    /// Whether the boundary token occurs anywhere in `bytes[from..]`, anchored
    /// or not. Used for the epilogue, where any boundary-shaped bytes are
    /// ambiguous rather than ignorable.
    fn boundary_occurs_after(&self, from: usize) -> bool {
        self.bytes
            .get(from..)
            .is_some_and(|tail| find_subslice(tail, &self.dash_boundary).is_some())
    }
}

/// Parse one MIME part from its exact framed content.
///
/// Strict by construction: the header block ends at the first `CRLF CRLF`,
/// obsolete folded continuation lines are refused rather than unfolded, every
/// line must be a well-formed `token ":" value`, header bytes must be US-ASCII
/// with no bare CR or LF, and each of the three headers that decide which
/// envelope is validated may appear at most once. A first-wins rule over
/// duplicated or foldable headers is exactly the kind of ambiguity a backend
/// can resolve differently, so it fails closed here instead.
fn parse_mtom_part(content: &[u8]) -> Result<MtomPart<'_>, SoapBodyDecodeError> {
    let header_len =
        find_subslice(content, b"\r\n\r\n").ok_or(SoapBodyDecodeError::MalformedEncoding)?;
    if header_len > MAX_MULTIPART_PART_HEADER_BYTES {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }
    let header_bytes = &content[..header_len];
    if !header_bytes
        .iter()
        .all(|&byte| matches!(byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
    {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }
    let Ok(headers) = std::str::from_utf8(header_bytes) else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };

    let mut content_type: Option<&str> = None;
    let mut content_id_raw: Option<&str> = None;
    let mut transfer_encoding: Option<&str> = None;
    let mut lines = 0usize;
    for line in headers.split("\r\n") {
        // A part with no headers at all, or an empty line inside the block,
        // re-frames the part for a lenient parser.
        if line.is_empty() {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        // A bare CR or LF would end this line for some parsers and not others.
        if line.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        // Obsolete folding (RFC 5322 obs-fold): refused, not joined.
        if line.starts_with([' ', '\t']) {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        lines += 1;
        if lines > MAX_MULTIPART_PART_HEADERS {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        if name.is_empty() || !name.bytes().all(is_media_type_token_byte) {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        let value = value.trim_matches([' ', '\t']);
        let slot = if name.eq_ignore_ascii_case("content-type") {
            &mut content_type
        } else if name.eq_ignore_ascii_case("content-id") {
            &mut content_id_raw
        } else if name.eq_ignore_ascii_case("content-transfer-encoding") {
            &mut transfer_encoding
        } else {
            continue;
        };
        if slot.replace(value).is_some() {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
    }

    let content_id = match content_id_raw {
        Some(raw) => {
            let normalized = normalize_content_id(raw);
            if normalized.is_empty() {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            }
            Some(normalized)
        }
        None => None,
    };

    let body = content
        .get(header_len + 4..)
        .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
    Ok(MtomPart {
        content_type,
        content_id,
        transfer_encoding,
        body,
    })
}

/// Locate and return the SOAP root part of an MTOM/XOP package.
///
/// Only part *headers* are parsed; attachment payloads are skipped without
/// being read, decoded, or validated. The whole package is framed and every
/// part parsed *before* a root is selected, so no ambiguity later in the
/// package can be missed by an early return.
///
/// The contract this enforces, so that Ferrum and the backend cannot disagree
/// about which bytes are the envelope (GHSA-435h-f785-wmm4):
///
/// * Delimiter lines are recognized only at the body start or immediately after
///   a CRLF, with exact CRLF framing and no transport padding.
/// * Exactly one close-delimiter must be present, and the epilogue after it
///   must not contain the boundary token at all.
/// * Part headers are strict: US-ASCII, no obsolete folding, well-formed field
///   names, and at most one `Content-Type` / `Content-ID` /
///   `Content-Transfer-Encoding` per part.
/// * `Content-ID` values are unique across the package (RFC 2387).
/// * The root is the part whose `Content-ID` matches `start`, or the first part
///   when `start` is absent — and with `start` supplied exactly one part may
///   match.
/// * The root part must itself declare a SOAP/XOP infoset and must not declare
///   a re-encoding `Content-Transfer-Encoding`.
///
/// Every other shape — no parts, no matching root, LF-only framing, a missing
/// or malformed closure, a part header block over its byte/line ceiling, more
/// than [`MAX_MULTIPART_PARTS`] parts, or more than
/// [`MAX_MULTIPART_DELIMITER_CANDIDATES`] boundary-shaped candidates — fails
/// closed.
fn extract_mtom_root_part<'a>(
    bytes: &'a [u8],
    boundary: &str,
    start: Option<&str>,
) -> Result<MtomRootPart<'a>, SoapBodyDecodeError> {
    let mut scanner = MtomScanner::new(bytes, boundary);

    // Anything before the first delimiter line is the RFC 2046 preamble, which
    // every conforming parser ignores; it is skipped rather than inspected.
    let first = scanner
        .next_from(0)?
        .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
    if first.closing {
        // `--boundary--` with no parts: there is no envelope to validate.
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }

    let mut parts: Vec<MtomPart<'a>> = Vec::new();
    let mut cursor = first.next;
    let epilogue_start = loop {
        if parts.len() >= MAX_MULTIPART_PARTS {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        let next = scanner
            .next_from(cursor)?
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        // The CRLF immediately before a delimiter line is framing, not content.
        let content_end = next
            .line_start
            .checked_sub(2)
            .filter(|end| *end >= cursor)
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        if &bytes[content_end..next.line_start] != b"\r\n" {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        parts.push(parse_mtom_part(&bytes[cursor..content_end])?);
        cursor = next.next;
        if next.closing {
            break cursor;
        }
    };
    // A parser that keeps reading past the close-delimiter would frame more
    // parts than this one did, so any boundary token in the epilogue is
    // ambiguous rather than ignorable.
    if scanner.boundary_occurs_after(epilogue_start) {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }

    // RFC 2387 requires package-unique Content-IDs. Two parts claiming one id
    // let the gateway and the backend resolve `start` to different envelopes.
    for (index, part) in parts.iter().enumerate() {
        let Some(id) = part.content_id.as_deref() else {
            continue;
        };
        if parts[..index]
            .iter()
            .any(|earlier| earlier.content_id.as_deref() == Some(id))
        {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
    }

    let root = match start {
        Some(start) => {
            let mut matching = parts
                .iter()
                .filter(|part| part.content_id.as_deref() == Some(start));
            let Some(selected) = matching.next() else {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            };
            if matching.next().is_some() {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            }
            selected
        }
        None => parts
            .first()
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?,
    };

    // The root part must itself declare a SOAP/XOP infoset. A root part
    // labelled `application/octet-stream` is the same client-selected
    // mislabelling GHSA-435h-f785-wmm4 describes, one layer down.
    let root_content_type = root.content_type.unwrap_or("");
    let Ok(essence) = media_type_essence(root_content_type) else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };
    if !MTOM_ROOT_ESSENCES.contains(&essence.as_str()) {
        return Err(SoapBodyDecodeError::UnsupportedCharset);
    }
    // MTOM mandates a binary-safe transfer encoding. Anything that re-encodes
    // the payload would make the bytes Ferrum validates differ from the bytes
    // the backend decodes.
    if let Some(encoding) = root.transfer_encoding
        && !matches!(
            encoding.trim().to_ascii_lowercase().as_str(),
            "7bit" | "8bit" | "binary"
        )
    {
        return Err(SoapBodyDecodeError::UnsupportedCharset);
    }

    Ok(MtomRootPart {
        body: root.body,
        content_type: root_content_type.to_string(),
    })
}

/// The strict MTOM package parser, reached through the lib target's
/// `_test_support` shim so hostile-package regressions live in the external
/// unit suite rather than inline in this module.
#[allow(dead_code)]
pub(crate) fn extract_mtom_root_part_for_test(
    bytes: &[u8],
    boundary: &str,
    start: Option<&str>,
) -> Result<(Vec<u8>, String), &'static str> {
    extract_mtom_root_part(bytes, boundary, start)
        .map(|part| (part.body.to_vec(), part.content_type))
        .map_err(SoapBodyDecodeError::class)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Decode a buffered SOAP body into UTF-8 text for XML validation.
///
/// UTF-8 payloads borrow the wire buffer; UTF-16 payloads allocate a decoded
/// string. The original wire bytes in `ctx.request_body_bytes` are left
/// untouched so the backend still receives the client representation.
fn decode_soap_xml_body<'a>(
    bytes: &'a [u8],
    content_type: &str,
) -> Result<Cow<'a, str>, SoapBodyDecodeError> {
    let declared = parse_content_type_charset(content_type)?;
    let (encoding, payload) = resolve_soap_xml_encoding(bytes, declared)?;
    let decoded = decode_payload(encoding, payload)?;
    validate_xml_declaration_encoding(&decoded, encoding)?;
    Ok(decoded)
}

fn parse_content_type_charset(
    content_type: &str,
) -> Result<Option<DeclaredCharset>, SoapBodyDecodeError> {
    let mut charset = None;
    let mut rest = skip_content_type_media_type(content_type)?;
    while let Some((name, value, next)) = next_content_type_parameter(rest)? {
        rest = next;
        if !name.eq_ignore_ascii_case("charset") {
            continue;
        }
        if value.is_empty() {
            return Err(SoapBodyDecodeError::UnsupportedCharset);
        }
        if charset.is_some() {
            // Duplicate charset parameters are hostile/ambiguous metadata.
            return Err(SoapBodyDecodeError::ConflictingCharset);
        }
        charset = Some(normalize_declared_charset(value)?);
    }
    Ok(charset)
}

/// Advance past the media type (`type/subtype`) to the parameter region.
fn skip_content_type_media_type(content_type: &str) -> Result<&str, SoapBodyDecodeError> {
    let bytes = content_type.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' => return Ok(&content_type[i..]),
            // Media type tokens are not quoted; a quote here is hostile metadata.
            b'"' | b'\\' => return Err(SoapBodyDecodeError::ConflictingCharset),
            _ => i += 1,
        }
    }
    Ok("")
}

/// Parse the next `name=value` Content-Type parameter.
///
/// Parameter values may be tokens or quoted-strings. Semicolons inside a
/// quoted value do not terminate the parameter. Quoted-pair escapes (`\X`)
/// are rejected fail-closed — charset labels never require them.
fn next_content_type_parameter(
    rest: &str,
) -> Result<Option<(&str, &str, &str)>, SoapBodyDecodeError> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return Ok(None);
    }
    if bytes[i] != b';' {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] == b';' {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }

    let name_start = i;
    while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b';' && !bytes[i].is_ascii_whitespace()
    {
        i += 1;
    }
    if name_start == i {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let name = &rest[name_start..i];
    if !name.bytes().all(is_media_type_token_byte) {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }

    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'=' {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }

    let (value, after_value) = if bytes[i] == b'"' {
        parse_quoted_parameter_value(&rest[i..])?
    } else {
        let value_start = i;
        while i < bytes.len() && bytes[i] != b';' {
            if matches!(bytes[i], b'"' | b'\\') {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            i += 1;
        }
        let raw = rest[value_start..i].trim_end();
        if raw.is_empty() || !raw.bytes().all(is_media_type_token_byte) {
            return Err(SoapBodyDecodeError::ConflictingCharset);
        }
        (raw, &rest[i..])
    };
    Ok(Some((name, value, after_value)))
}

fn parse_quoted_parameter_value(raw: &str) -> Result<(&str, &str), SoapBodyDecodeError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let quote = bytes[0];
    if quote != b'"' {
        return Err(SoapBodyDecodeError::ConflictingCharset);
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Quoted-pair escapes are rejected deterministically. Charset
                // names are plain tokens and never require escaping.
                return Err(SoapBodyDecodeError::UnsupportedCharset);
            }
            b if b == quote => {
                let inner = &raw[1..i];
                if inner.is_empty() {
                    return Err(SoapBodyDecodeError::UnsupportedCharset);
                }
                let mut next = i + 1;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if next < bytes.len() && bytes[next] != b';' {
                    return Err(SoapBodyDecodeError::ConflictingCharset);
                }
                return Ok((inner, &raw[next..]));
            }
            _ => i += 1,
        }
    }
    Err(SoapBodyDecodeError::ConflictingCharset)
}

fn normalize_declared_charset(raw: &str) -> Result<DeclaredCharset, SoapBodyDecodeError> {
    if matches_utf8_label(raw) {
        Ok(DeclaredCharset::Utf8)
    } else if matches_utf16le_label(raw) {
        Ok(DeclaredCharset::Utf16Le)
    } else if matches_utf16be_label(raw) {
        Ok(DeclaredCharset::Utf16Be)
    } else if matches_utf16_unspecified_label(raw) {
        Ok(DeclaredCharset::Utf16Unspecified)
    } else {
        Err(SoapBodyDecodeError::UnsupportedCharset)
    }
}

fn matches_utf8_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-8")
        || label.eq_ignore_ascii_case("utf8")
        || label.eq_ignore_ascii_case("unicode-1-1-utf-8")
}

fn matches_utf16le_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16le") || label.eq_ignore_ascii_case("utf16le")
}

fn matches_utf16be_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16be")
        || label.eq_ignore_ascii_case("utf16be")
        || label.eq_ignore_ascii_case("unicodefffe")
}

fn matches_utf16_unspecified_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("utf-16") || label.eq_ignore_ascii_case("utf16")
}

fn detect_bom(bytes: &[u8]) -> Option<(SoapXmlEncoding, usize)> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        Some((SoapXmlEncoding::Utf8, 3))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        Some((SoapXmlEncoding::Utf16Be, 2))
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        Some((SoapXmlEncoding::Utf16Le, 2))
    } else {
        None
    }
}

fn resolve_soap_xml_encoding(
    bytes: &[u8],
    declared: Option<DeclaredCharset>,
) -> Result<(SoapXmlEncoding, &[u8]), SoapBodyDecodeError> {
    let bom = detect_bom(bytes);
    match (bom, declared) {
        (Some((encoding, skip)), None) => Ok((encoding, &bytes[skip..])),
        (Some((encoding, skip)), Some(DeclaredCharset::Utf8)) => {
            if encoding == SoapXmlEncoding::Utf8 {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Le)) => {
            if encoding == SoapXmlEncoding::Utf16Le {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Be)) => {
            if encoding == SoapXmlEncoding::Utf16Be {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (Some((encoding, skip)), Some(DeclaredCharset::Utf16Unspecified)) => {
            if matches!(
                encoding,
                SoapXmlEncoding::Utf16Le | SoapXmlEncoding::Utf16Be
            ) {
                Ok((encoding, &bytes[skip..]))
            } else {
                Err(SoapBodyDecodeError::ConflictingCharset)
            }
        }
        (None, Some(DeclaredCharset::Utf8)) => {
            if looks_like_bomless_utf16_xml(bytes) {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            Ok((SoapXmlEncoding::Utf8, bytes))
        }
        (None, None) => {
            // BOM-less, charset-less UTF-16 XML (`3c 00` / `00 3c`) is
            // unmistakable and must not be treated as UTF-8 (NUL-containing
            // bytes can otherwise pass leniently and be forwarded).
            if looks_like_bomless_utf16_xml(bytes) {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            Ok((SoapXmlEncoding::Utf8, bytes))
        }
        (None, Some(DeclaredCharset::Utf16Le)) => Ok((SoapXmlEncoding::Utf16Le, bytes)),
        (None, Some(DeclaredCharset::Utf16Be)) => Ok((SoapXmlEncoding::Utf16Be, bytes)),
        // charset=utf-16 without BOM/endian is ambiguous — fail closed.
        (None, Some(DeclaredCharset::Utf16Unspecified)) => {
            Err(SoapBodyDecodeError::ConflictingCharset)
        }
    }
}

/// True when the first code unit is ASCII '<' encoded as UTF-16LE or UTF-16BE
/// without a BOM (`3c 00 …` / `00 3c …`).
fn looks_like_bomless_utf16_xml(bytes: &[u8]) -> bool {
    matches!(bytes, [0x3c, 0x00, ..] | [0x00, 0x3c, ..])
}

fn decode_payload<'a>(
    encoding: SoapXmlEncoding,
    payload: &'a [u8],
) -> Result<Cow<'a, str>, SoapBodyDecodeError> {
    match encoding {
        SoapXmlEncoding::Utf8 => std::str::from_utf8(payload)
            .map(Cow::Borrowed)
            .map_err(|_| SoapBodyDecodeError::MalformedEncoding),
        SoapXmlEncoding::Utf16Le => decode_utf16(payload, false).map(Cow::Owned),
        SoapXmlEncoding::Utf16Be => decode_utf16(payload, true).map(Cow::Owned),
    }
}

/// Incrementally decode UTF-16 into UTF-8 without an intermediate `Vec<u16>`.
/// Odd length and unpaired / truncated surrogates fail closed.
fn decode_utf16(payload: &[u8], big_endian: bool) -> Result<String, SoapBodyDecodeError> {
    if !payload.len().is_multiple_of(2) {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    }
    // UTF-8 output is at most 3/2 of the UTF-16 wire length (see module note).
    let mut out = String::with_capacity(payload.len().saturating_mul(3) / 2);
    let mut chunks = payload.chunks_exact(2);
    while let Some(pair) = chunks.next() {
        let unit = if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        };
        if (0xD800..=0xDBFF).contains(&unit) {
            let Some(low_pair) = chunks.next() else {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            };
            let low = if big_endian {
                u16::from_be_bytes([low_pair[0], low_pair[1]])
            } else {
                u16::from_le_bytes([low_pair[0], low_pair[1]])
            };
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(SoapBodyDecodeError::MalformedEncoding);
            }
            let code = 0x10000 + (((u32::from(unit) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
            out.push(char::from_u32(code).ok_or(SoapBodyDecodeError::MalformedEncoding)?);
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        } else {
            // Non-surrogate BMP units are always valid scalar values.
            let ch =
                char::from_u32(u32::from(unit)).ok_or(SoapBodyDecodeError::MalformedEncoding)?;
            out.push(ch);
        }
    }
    Ok(out)
}

fn validate_xml_declaration_encoding(
    xml: &str,
    resolved: SoapXmlEncoding,
) -> Result<(), SoapBodyDecodeError> {
    let trimmed = xml.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let bytes = trimmed.as_bytes();
    if !bytes.starts_with(b"<?xml") || !bytes.get(5).is_some_and(|byte| byte.is_ascii_whitespace())
    {
        return Ok(());
    }
    let Some(end) = trimmed.find("?>") else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };
    let decl = &trimmed[..end + 2];
    let Some(label) = extract_xml_decl_encoding(decl)? else {
        return Ok(());
    };
    if resolved.accepts_xml_decl_label(&label) {
        Ok(())
    } else if matches_utf8_label(&label)
        || matches_utf16le_label(&label)
        || matches_utf16be_label(&label)
        || matches_utf16_unspecified_label(&label)
    {
        Err(SoapBodyDecodeError::ConflictingCharset)
    } else {
        // Unknown declaration encodings (e.g. iso-8859-1) are unsupported.
        Err(SoapBodyDecodeError::UnsupportedCharset)
    }
}

fn extract_xml_decl_encoding(decl: &str) -> Result<Option<String>, SoapBodyDecodeError> {
    let Some(mut rest) = decl.strip_prefix("<?xml") else {
        return Err(SoapBodyDecodeError::MalformedEncoding);
    };
    rest = rest
        .strip_suffix("?>")
        .ok_or(SoapBodyDecodeError::MalformedEncoding)?;

    let mut encoding = None;
    while !rest.trim_start().is_empty() {
        rest = rest.trim_start();
        let name_len = rest
            .bytes()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-' | b'.')
            })
            .count();
        if name_len == 0 {
            return Err(SoapBodyDecodeError::MalformedEncoding);
        }
        let (name, after_name) = rest.split_at(name_len);
        rest = after_name.trim_start();
        rest = rest
            .strip_prefix('=')
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?
            .trim_start();
        let quote = rest
            .chars()
            .next()
            .filter(|quote| matches!(quote, '"' | '\''))
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        rest = &rest[quote.len_utf8()..];
        let end = rest
            .find(quote)
            .ok_or(SoapBodyDecodeError::MalformedEncoding)?;
        let value = &rest[..end];
        rest = &rest[end + quote.len_utf8()..];

        if name.eq_ignore_ascii_case("encoding") {
            if encoding.is_some() || value.trim().is_empty() {
                return Err(SoapBodyDecodeError::ConflictingCharset);
            }
            encoding = Some(value.trim().to_string());
        }
    }
    Ok(encoding)
}

// Reached only via the lib target's `_test_support` shim (external unit tests).
#[allow(dead_code)]
pub(crate) fn decode_soap_xml_body_for_test(
    bytes: &[u8],
    content_type: &str,
) -> Result<String, String> {
    decode_soap_xml_body(bytes, content_type)
        .map(Cow::into_owned)
        .map_err(|err| err.message().to_string())
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Parse WS-Security datetime formats (ISO 8601 variants).
fn parse_ws_datetime(s: &str) -> Option<DateTime<Utc>> {
    // Reject instants outside the representable WS-Security window. `chrono`'s
    // `%Y` accepts years far beyond four digits and its `DateTime` `Add`/`Sub`
    // impls panic on overflow. Callers still use checked addition near the
    // accepted upper boundary; this clamp rejects nonsensical distant years
    // before any policy arithmetic. No legitimate WS-Security or SAML instant
    // falls outside this range.
    let parsed = parse_ws_datetime_unbounded(s)?;
    let year = parsed.year();
    if !(MIN_PARSED_YEAR..=MAX_PARSED_YEAR).contains(&year) {
        return None;
    }
    Some(parsed)
}

fn parse_ws_datetime_unbounded(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();

    // Try standard RFC 3339 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try common WS-Security formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
    ];

    for fmt in &formats {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }

    // Try without timezone (assume UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    None
}

/// Escape special characters for JSON string interpolation.
fn escape_json_chars(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            ch if ch < '\u{20}' => {
                escaped.push_str("\\u00");
                let byte = ch as u8;
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_escape_json_chars_round_trips_control_characters() {
        let raw = "validation failed\"\n<xml>\u{00}\u{1f}\\";
        let body = format!(r#"{{"error":"{}"}}"#, escape_json_chars(raw));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("escaped SOAP error should be valid JSON");

        assert_eq!(parsed["error"], raw);
        assert!(!escape_json_chars(raw).chars().any(|ch| ch < '\u{20}'));
    }

    const TEST_NS_DECLS: &str = concat!(
        r#" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/""#,
        r#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""#,
        r#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd""#,
        r#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#,
    );

    fn timestamp_only_plugin() -> SoapWsSecurity {
        SoapWsSecurity::new(&serde_json::json!({ "timestamp": { "require": true } }))
            .expect("timestamp-only config should construct")
    }

    /// Namespace-correct envelope whose Security header carries a Timestamp and
    /// a `ds:Signature` with the supplied `SignedInfo` children.
    fn signed_envelope(signed_info_children: &str) -> String {
        format!(
            "<soap:Envelope{decls}><soap:Header><wsse:Security>\
             <wsu:Timestamp wsu:Id=\"TS-1\"></wsu:Timestamp>\
             <ds:Signature><ds:SignedInfo>{children}</ds:SignedInfo></ds:Signature>\
             </wsse:Security></soap:Header><soap:Body></soap:Body></soap:Envelope>",
            decls = TEST_NS_DECLS,
            children = signed_info_children
        )
    }

    fn timestamp_reference() -> String {
        format!(
            r##"<ds:Reference URI="#TS-1"><ds:Transforms><ds:Transform Algorithm="{}"/></ds:Transforms><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>ZGVhZGJlZWY=</ds:DigestValue></ds:Reference>"##,
            XML_EXCLUSIVE_C14N, XMLDSIG_SHA256
        )
    }

    fn reference_digest_error(envelope: &str) -> String {
        let plugin = timestamp_only_plugin();
        let document = parse_bounded_xml(envelope, "test envelope").expect("fixture should parse");
        let structure = resolve_soap_envelope(&document).expect("fixture envelope should resolve");
        let security = resolve_security_node(&document, &structure)
            .expect("fixture Security should resolve")
            .expect("fixture should carry a Security header");
        let signature = unique_ns_child(security, XMLDSIG_NAMESPACE_URI, "Signature", "test")
            .expect("Signature")
            .expect("Signature");
        let signed_info = unique_ns_child(signature, XMLDSIG_NAMESPACE_URI, "SignedInfo", "test")
            .expect("SignedInfo")
            .expect("SignedInfo");
        let id_index = DocumentIdIndex::build(&document);
        let mut budget = WorkBudget::for_envelope(envelope);
        plugin
            .verify_reference_digests(
                signed_info,
                security,
                signature,
                &ReferenceDigestDocument {
                    structure: &structure,
                    id_index: &id_index,
                    envelope,
                },
                &mut budget,
            )
            .err()
            .expect("fixture must be rejected")
    }

    /// GHSA-9g4v-h9hm-846r: the Reference ceiling is enforced before any
    /// Reference is resolved, canonicalized, or digested.
    #[test]
    fn too_many_x509_signature_references_are_rejected() {
        let references = std::iter::repeat_n(timestamp_reference(), MAX_SIGNED_REFERENCES + 1)
            .collect::<String>();
        let error = reference_digest_error(&signed_envelope(&references));
        assert!(
            error.contains("too many Signature References"),
            "got: {error}"
        );
    }

    /// GHSA-9g4v-h9hm-846r: two References to one id multiply canonicalization
    /// work over the same subtree and are never meaningful.
    #[test]
    fn duplicate_x509_reference_uris_are_rejected() {
        let references = format!("{}{}", timestamp_reference(), timestamp_reference());
        let error = reference_digest_error(&signed_envelope(&references));
        assert!(
            error.contains("duplicate Signature Reference URI"),
            "got: {error}"
        );
    }

    /// GHSA-9g4v-h9hm-846r (SAML half): exactly one Reference to the enclosing
    /// assertion is supported, so duplicates cannot re-canonicalize it.
    #[test]
    fn duplicate_saml_signature_references_are_rejected() {
        let plugin = timestamp_only_plugin();
        let reference = format!(
            r##"<ds:Reference URI="#assertion-1"><ds:Transforms><ds:Transform Algorithm="{}"/><ds:Transform Algorithm="{}"/></ds:Transforms><ds:DigestMethod Algorithm="{}"/><ds:DigestValue>ZGVhZGJlZWY=</ds:DigestValue></ds:Reference>"##,
            XMLDSIG_ENVELOPED_SIGNATURE, XML_EXCLUSIVE_C14N, XMLDSIG_SHA256
        );
        let envelope = format!(
            r#"<saml:Assertion xmlns:saml="{}" xmlns:ds="{}" ID="assertion-1"><ds:Signature><ds:SignedInfo>{}{}</ds:SignedInfo></ds:Signature></saml:Assertion>"#,
            SAML2_ASSERTION_NS, XMLDSIG_NAMESPACE_URI, reference, reference
        );
        let document = parse_bounded_xml(&envelope, "test assertion").expect("fixture parses");
        let assertion = document.root_element();
        let signature = unique_ns_child(assertion, XMLDSIG_NAMESPACE_URI, "Signature", "test")
            .expect("Signature")
            .expect("Signature");
        let signed_info = unique_ns_child(signature, XMLDSIG_NAMESPACE_URI, "SignedInfo", "test")
            .expect("SignedInfo")
            .expect("SignedInfo");
        let mut budget = WorkBudget::for_envelope(&envelope);
        let error = plugin
            .verify_saml_reference_digests(
                signed_info,
                assertion,
                signature,
                &envelope,
                &mut budget,
            )
            .expect_err("duplicate SAML references must reject");
        assert!(error.contains("exactly one Reference"), "got: {error}");
    }

    /// GHSA-3mwq-c8j6-9xhp: a namespace-confusable second `Body` fails closed
    /// rather than becoming a resolvable alternate referent.
    #[test]
    fn duplicate_namespace_correct_body_is_rejected() {
        let envelope = format!(
            "<soap:Envelope{decls}><soap:Header></soap:Header><soap:Body>\
             <soap:Body></soap:Body></soap:Body></soap:Envelope>",
            decls = TEST_NS_DECLS
        );
        let document = parse_bounded_xml(&envelope, "test envelope").expect("fixture parses");
        // Avoid `expect_err`: SoapEnvelopeStructure is intentionally not Debug.
        let error = match resolve_soap_envelope(&document) {
            Err(error) => error,
            Ok(_) => panic!("duplicate Body must reject"),
        };
        assert!(
            error.contains("duplicate namespace-qualified"),
            "got: {error}"
        );
    }

    /// GHSA-3mwq-c8j6-9xhp: a `wsse:Security` element outside the SOAP Header
    /// is a wrapping attempt, not an alternate policy location.
    #[test]
    fn security_header_outside_soap_header_is_rejected() {
        let envelope = format!(
            "<soap:Envelope{decls}><soap:Header></soap:Header><soap:Body>\
             <wsse:Security></wsse:Security></soap:Body></soap:Envelope>",
            decls = TEST_NS_DECLS
        );
        let document = parse_bounded_xml(&envelope, "test envelope").expect("fixture parses");
        let structure = resolve_soap_envelope(&document).expect("envelope resolves");
        let error = resolve_security_node(&document, &structure)
            .expect_err("misplaced Security must reject");
        assert!(error.contains("outside the SOAP Header"), "got: {error}");
    }

    /// GHSA-9g4v-h9hm-846r: the aggregate budget charges both the source
    /// subtree walk and the complete emitted canonical representation.
    #[test]
    fn canonicalization_budget_refuses_over_budget_work() {
        let xml = "<root>value</root>";
        let document = parse_bounded_xml(xml, "test fixture").expect("fixture parses");
        let root = document.root_element();
        let source_len = root.range().len();
        let mut budget = WorkBudget {
            remaining: source_len.saturating_mul(2).saturating_sub(1),
        };
        let error = exclusive_canonicalize(xml, root, &[], None, &mut budget)
            .expect_err("source plus full canonical output must exceed the budget");
        assert!(
            error.contains("canonicalization work budget"),
            "got: {error}"
        );
    }

    /// GHSA-435h-f785-wmm4: classification is structural, so a parameter value
    /// that merely contains a SOAP essence is not a SOAP request, and a
    /// mislabelled one is refused on a strict route.
    #[test]
    fn media_type_classification_is_structural() {
        assert_eq!(
            classify_soap_media_type("text/xml; charset=utf-8", true),
            Ok(Some(SoapMediaClass::Xml))
        );
        assert_eq!(
            classify_soap_media_type("multipart/form-data; boundary=application/xml", true),
            Ok(None)
        );
        assert_eq!(
            classify_soap_media_type("application/octet-stream", true),
            Ok(None)
        );
        assert_eq!(
            classify_soap_media_type("text/xml\u{7f}", true),
            Err(MediaTypeRejection::MalformedMediaType)
        );
        assert_eq!(
            classify_soap_media_type(
                "multipart/related; type=\"application/xop+xml\"; boundary=MIME_boundary; start=\"<root@example.com>\"",
                true
            ),
            Ok(Some(SoapMediaClass::Mtom {
                boundary: "MIME_boundary".to_string(),
                start: Some("root@example.com".to_string()),
            }))
        );
        assert_eq!(
            classify_soap_media_type(
                "multipart/related; type=\"application/xop+xml\"; boundary=MIME_boundary",
                false
            ),
            Err(MediaTypeRejection::UnsupportedMediaTypeOnProtectedRoute)
        );
        assert_eq!(
            classify_soap_media_type("multipart/related; type=\"application/xop+xml\"", true),
            Err(MediaTypeRejection::MalformedMultipartPackaging)
        );
    }

    // ── RSA public-key DER shape validator ──────────────────────────────────
    //
    // These tests pin the structural framing guard applied before the bare
    // RSAPublicKey reaches `ring::signature::UnparsedPublicKey::new`.

    #[test]
    fn rsa_pk_shape_accepts_short_form_sequence_with_matching_length() {
        // SEQUENCE, content length 3, three content bytes — well-formed.
        let der = [0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_accepts_long_form_two_octet_length() {
        // SEQUENCE, long-form length: 0x82 means "next 2 octets are length";
        // 0x01 0x00 = 256 content bytes. Build a buffer of exactly that size.
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat_n(0xAB_u8, 256));
        assert_eq!(der.len(), 4 + 256);
        assert!(validate_rsa_public_key_der_shape(&der).is_ok());
    }

    #[test]
    fn rsa_pk_shape_rejects_empty_buffer() {
        let err = validate_rsa_public_key_der_shape(&[]).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_non_sequence_tag() {
        // 0x02 = INTEGER tag — refused even with otherwise-valid length.
        let err = validate_rsa_public_key_der_shape(&[0x02, 0x01, 0x00]).unwrap_err();
        assert!(err.contains("SEQUENCE tag"), "got: {err}");
        assert!(err.contains("0x02"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_after_tag() {
        let err = validate_rsa_public_key_der_shape(&[0x30]).unwrap_err();
        assert!(err.contains("length octet"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_indefinite_length_encoding() {
        // 0x80 = "indefinite length" — invalid in DER (only BER allows it).
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x80, 0x00, 0x00]).unwrap_err();
        assert!(err.contains("indefinite-length"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_overlong_length_field() {
        // 0x85 = 5 length octets — refused (a 4-octet length already covers 4 GiB).
        let der = [0x30, 0x85, 0, 0, 0, 0, 0, 0];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length uses 5 octets"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_truncated_long_form_length() {
        // 0x82 promises 2 length octets, but only 1 is present.
        let err = validate_rsa_public_key_der_shape(&[0x30, 0x82, 0x00]).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_trailing_bytes_after_sequence() {
        // Layout: 0x30 0x09 [9 content bytes] [4 extra trailing bytes].
        // 9 + 2 (header) = 11, but the buffer length is 15, so this rejects.
        let der = [
            0x30, 0x09, // SEQUENCE, 9 content bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // 9 content bytes
            0xAA, 0xBB, 0xCC, 0xDD, // trailing extras (would be the inner BIT STRING)
        ];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_shorter_than_buffer() {
        // Header declares 2 content bytes but buffer has 4 content bytes.
        let der = [0x30, 0x02, 0x01, 0x02, 0x03, 0x04];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }

    #[test]
    fn rsa_pk_shape_rejects_declared_longer_than_buffer() {
        // Header declares 100 content bytes but only 2 content bytes follow.
        let der = [0x30, 0x64, 0x01, 0x02];
        let err = validate_rsa_public_key_der_shape(&der).unwrap_err();
        assert!(err.contains("length mismatch"), "got: {err}");
    }
}
