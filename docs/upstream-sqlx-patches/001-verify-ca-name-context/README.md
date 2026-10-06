# SQLx verify-ca hostname-error compatibility

## Status

Deliberate fork, unfiled upstream. Owner: Ferrum Edge maintainers. This patch
resolves Ferrum issue #5534 and follows the weekly review and stable-release
checkpoint in [dependency policy](../../dependency-policy.md).

## Patch

The base is the crates.io `sqlx-core` 0.8.6 source (package checksum
`ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`).
This patch changes `src/net/tls/tls_rustls.rs` and the two Cargo manifests.
The separate [typed floating-point NULL patch](../002-typed-float-null-bindings/README.md)
changes `src/any/arguments.rs` in the same vendor copy.

The manifests differ in exactly two ways. The rustls dependency floor is raised
to 0.23.45 — the version already in Ferrum's locked graph, and the first that
provides the context-bearing name error. And upstream's `[dev-dependencies]`
(the whole `sqlx` facade with the postgres/sqlite/mysql/migrate/macros drivers,
plus tokio) is removed: it existed only for this crate's doctests, no
`#[cfg(test)]` module uses it, and a `[patch.crates-io]` consumer never
resolves a dependency's dev-dependencies — but `cargo test --manifest-path …
--lib` does build them, which would compile three SQL drivers, a bundled SQLite
C library, and a proc-macro crate (in a feature combination upstream only ever
resolves from inside its own workspace) to run the two unit tests below.
`cargo test --doc` on the vendored copy is therefore not supported.

`src/net/tls/tls_rustls.rs` carries three changes.

**1. A configured root CA is exclusive.** Upstream seeds the handshake trust
store with the bundled WebPKI (or native) anchors and then *adds* the
configured CA to them. `handshake` now builds the store through a new
`root_store_for(Option<&[u8]>)` helper: with a configured CA it starts from
`RootCertStore::empty()` and adds only that CA, and with no configured CA it
returns the bundled/native anchors unchanged. This applies to the whole
non-`accept_invalid_certs` branch, `verify-ca` and `verify-full` alike. It
matches libpq's `sslrootcert` semantics and the repository invariant in
`.claude/rules/tls-security.md` ("custom CA is exclusive and replaces built-in
roots"). It is load-bearing for `verify-ca` in particular: change 3 waives the
hostname check, leaving the issuer as the only remaining constraint, so a store
that still held the ~150 public roots would accept any publicly-trusted
certificate for any hostname on an intercepted database connection.

**2. The verify-ca WebPKI verifier is built with the selected provider.**
`WebPkiServerVerifier::builder_with_provider` is used instead of the
provider-less builder, which resolves the process default from crate features
and panics when both `ring` and `aws-lc-rs` are compiled in and nothing
installed a default — the state of a test binary that never started the
gateway.

**3. Both rustls hostname-error variants are waived under verify-ca.** SQLx
correctly maps PostgreSQL `VerifyCa` and MySQL `VerifyCa` to
`NoHostnameTlsVerifier`. That wrapper waived only
`CertificateError::NotValidForName`; rustls now returns
`CertificateError::NotValidForNameContext` for the same name mismatch. Both
variants are handled after WebPKI has verified the chain and certificate
validity. All other errors propagate, and TLS 1.2/1.3 handshake signature
verification still delegates to the original WebPKI verifier. `verify-full`
does not use this wrapper and keeps hostname verification.

A gateway-side TLS option cannot replace SQLx Any's internal verifier. A
SQLx 0.9 migration would change the database dependency graph beyond this
compatibility fix; the small 0.8.6 patch keeps that graph unchanged.

## Regression coverage

An in-crate `#[cfg(test)]` module at the bottom of
`src/net/tls/tls_rustls.rs` pins change 1 and the boundary of change 3, using
two static self-signed test CAs and a fixed verification instant so neither
fixture can expire:

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
cargo test --manifest-path vendor/sqlx-core-0.8.6-ferrum-patched/Cargo.toml \
  --no-default-features --features _rt-tokio,_tls-rustls-ring-webpki \
  --lib tls_rustls::tests
```

The feature list is required: `sqlx-core`'s default feature list is empty, so
the rustls TLS module is not built without an explicit runtime and rustls
backend.

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

Retire when a compatible upstream SQLx release supports both name-error
variants (or verifies chains separately from names), treats a configured root
CA as exclusive, and passes the same handshake controls. Retain the vendor copy
and its patch entries while [patch 002](../002-typed-float-null-bindings/README.md)
still needs them. Once both patches can retire, remove both
`[patch.crates-io]` entries (root `Cargo.toml` and
`tests/performance/mesh/Cargo.toml`), the vendor copy, the inventory row in
`docs/dependency-policy.md`, and the entry in
`docs/vendored-patch-lifecycle.json`; update both lockfiles and the drift
manifest. Keep all Ferrum unit and service-integration regressions.
