# SQLx verify-ca exclusive root CA and provider-pinned verifier

## Status

Deliberate fork, unfiled upstream. Owner: Ferrum Edge maintainers. This patch
resolves Ferrum issue #5534 and follows the weekly review and stable-release
checkpoint in [dependency policy](../../dependency-policy.md). The directory
and lifecycle ID keep their original `verify-ca-name-context` name; the
hostname-error part of the patch is upstream since SQLx 0.9.1 (see "Retired
change 3" below).

## Patch

The base is the crates.io `sqlx-core` 0.9.1 source (package checksum
`c08f9787cc5aff062567dea2205f8ae37a617b04342633ab4f74944858ea6072`, matching
the crates.io index). This patch changes `src/net/tls/tls_rustls.rs` and the
two Cargo manifests. Every other vendored file is byte-identical to the crate,
plus cargo's own `.cargo-ok` unpack marker. The crate's packaged `Cargo.lock`
(upstream's lock for this package, including the dev-dependency graph removed
below) is not vendored: a `[patch.crates-io]` consumer never reads it, and the
drift guard ignores vendor lockfiles that are not explicitly governed.

The manifests differ in exactly two ways. The rustls dependency floor is raised
to 0.23.46, the version already in Ferrum's locked graph. And upstream's
`[dev-dependencies]` (`tempfile`, `tokio`, and the whole `sqlx` facade with the
postgres/sqlite/mysql/migrate/macros drivers) are removed: they serve doctests
and the `migrate` feature's tests, no module built for the regression run uses
them, and a `[patch.crates-io]` consumer never resolves a dependency's
dev-dependencies — but `cargo test --manifest-path … --lib` does build them,
which would compile three SQL drivers, a bundled SQLite C library, and a
proc-macro crate to run the TLS unit tests below. `cargo test --doc` and the
`migrate` tests on the vendored copy are therefore not supported.

`src/net/tls/tls_rustls.rs` carries two changes.

**1. A configured root CA is exclusive.** Upstream seeds the trust store with
the bundled WebPKI (or native) anchors from `import_root_certs()` and then
*adds* the configured CA to them. `connector()` now builds the store through a
new `root_store_for(Option<&[u8]>)` helper: with a configured CA it starts from
`RootCertStore::empty()` and adds only that CA, and with no configured CA it
returns `import_root_certs()` unchanged. This applies to the whole
non-`accept_invalid_certs` branch, `verify-ca` and `verify-full` alike. It
matches libpq's `sslrootcert` semantics and the repository invariant in
`.claude/rules/tls-security.md` ("custom CA is exclusive and replaces built-in
roots"). It is load-bearing for `verify-ca` in particular: SQLx's
`NoHostnameTlsVerifier` waives the hostname check, leaving the issuer as the
only remaining constraint, so a store that still held the ~150 public roots
would accept any publicly-trusted certificate for any hostname on an
intercepted database connection.

**2. The verify-ca WebPKI verifier is built with the selected provider.**
`WebPkiServerVerifier::builder_with_provider(cert_store, provider.clone())` is
used instead of the provider-less builder, which resolves the process default
from crate features and panics when both `ring` and `aws-lc-rs` are compiled
in and nothing installed a default — the state of a test binary that never
started the gateway.

**Retired change 3.** On the 0.8.6 base this patch also waived rustls's
context-bearing `CertificateError::NotValidForNameContext` beside
`NotValidForName` in `NoHostnameTlsVerifier`. SQLx 0.9.1 handles both variants
upstream (`src/net/tls/tls_rustls.rs`, `NoHostnameTlsVerifier::verify_server_cert`),
so the vendor carries no change there. The same release also contains the
typed-NULL fix the retired [patch 002](../002-typed-float-null-bindings/README.md)
carried.

A gateway-side TLS option cannot replace SQLx Any's internal verifier, so
changes 1 and 2 stay in the vendor.

## Regression coverage

Two tests appended to the in-crate `#[cfg(test)] mod tests` at the bottom of
`src/net/tls/tls_rustls.rs` (beside upstream's own
`flush_and_shutdown_do_not_wait_for_a_silent_peer`) pin change 1 and the
boundary of the upstream name waiver, using two static self-signed test CAs and
a fixed verification instant so neither fixture can expire. The verifier test
builds through change 2's provider-pinned builder:

- `root_store_with_configured_ca_replaces_the_default_trust_store` — the
  default store holds more than one anchor, and a store built from a
  configured CA holds exactly one. The additive store this patch replaced
  produced `defaults + 1` anchors for the same input, so the count is
  decisive.
- `verify_ca_refuses_a_certificate_from_an_unconfigured_ca` — the verify-ca
  verifier refuses a certificate issued outside the configured CA, and the
  refusal is not one of the two waived name errors.

Hosted CI runs them in the `test-vendor-patches` job (**Vendored Patch
Regressions**):

```bash
cargo test --manifest-path vendor/sqlx-core-0.9.1-ferrum-patched/Cargo.toml \
  --no-default-features --features _rt-tokio,_tls-rustls-ring-webpki \
  --lib tls_rustls::tests
```

The filter also runs upstream's `flush_and_shutdown_do_not_wait_for_a_silent_peer`.

The feature list is required: `sqlx-core`'s default feature list is empty, so
the rustls TLS module is not built without an explicit runtime and rustls
backend. The job resolves the single `vendor/sqlx-core-*-ferrum-patched/`
directory rather than naming the version.

`tests/service_integration/db_tls.rs` runs in hosted **Service Integration**:
both SQL dialects accept matching names and verify-ca name mismatches, reject
verify-full name mismatches, reject unrelated CAs, and reject expired leaves.
The same fixtures cover retained trust through rejected reloads and fresh
connections (#5535). Unit coverage pins EnvConfig-to-driver mode mapping for
database, CP, and migrate consumers and primary/failover/replica URLs, and
`EnvConfig::validate` refuses `FERRUM_DB_TLS_MODE=verify-ca` with no
configured CA, which under exclusive-CA semantics would leave an empty trust
store.

## Retirement

Retire when a compatible upstream SQLx release treats a configured root CA as
exclusive, builds the verify-ca verifier with the selected crypto provider (or
otherwise cannot panic on a dual-provider build), and passes the same
handshake controls. Then remove the `[patch.crates-io]` entries (root
`Cargo.toml`, `fuzz/Cargo.toml` and `tests/performance/mesh/Cargo.toml`) and
update the three lockfiles while the vendor copy still exists; then remove the
vendor copy, the inventory row in `docs/dependency-policy.md`, and the entry in
`docs/vendored-patch-lifecycle.json`, and update the drift manifest. Keep all
Ferrum unit and service-integration regressions.
