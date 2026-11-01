# Patch 001 — dimpl certificate chains and private-key zeroization

## Status

| Field | Value |
|---|---|
| Patch ID | `001-certificate-chain-and-key-zeroization` |
| Target crate | `dimpl` |
| Target version | 0.6.1 |
| Registry checksum | `ef7eed0cf766b110880acdd89a860061dee42ed5f64df0fa43c80203e4f60916` |
| Upstream source commit | [`37bb0fa83f4167420729de5ea71c61852f82e9ed`](https://github.com/algesten/dimpl/commit/37bb0fa83f4167420729de5ea71c61852f82e9ed) |
| License | MIT OR Apache-2.0 (both license files are retained in the vendor directory) |
| Latest upstream audited | 0.7.2 (`ba6aa42b0c64c3e5311a2afad224b32db1ee129d21c63daaaf8ea747b846cdbc`) |
| State | Applied through `vendor/dimpl-0.6.1-ferrum-patched` and `[patch.crates-io]` |
| Upstream issue / PR | Deliberate fork — unfiled; governed by the [fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla) |
| Owner | `@jeremyjpj0916` |

## Why the patch is required

Published `dimpl` versions through 0.7.2 accept one local DER certificate and
serialize only that certificate in DTLS 1.2 and 1.3. A configured
leaf/intermediate bundle is therefore silently reduced to its leaf before the
dependency sees it, and a peer that trusts only the root cannot build a path.

The published credential type also stores private-key DER in `Vec<u8>`.
Endpoint construction, clone-based configuration caches, auto-negotiation,
protocol fallback, replacement, and shutdown can retain or release ordinary
heap copies without clearing them.

Published 0.6.1 also sends a DTLS 1.3 `CertificateRequest` whose
`certificate_authorities` extension carries a zero-length authorities list.
RFC 8446 §4.2.4 makes the extension optional but requires a non-empty list
(`DistinguishedName authorities<3..2^16-1>`) when it is present, so strict
peers (dimpl 0.8.0+, Chrome/BoringSSL) treat the encrypted flight as malformed
and the required-client-certificate handshake never completes (issue #7000).
Upstream fixed this in
[algesten/dimpl#153](https://github.com/algesten/dimpl/pull/153), first
released in 0.7.0; this copy backports it because the chain and zeroization
changes keep Ferrum on 0.6.1.

No compatible upstream release provides both full-chain transport and
drop-time key clearing, so a gateway-only wrapper cannot establish either
security boundary: `dimpl` itself owns the fallback credential and wire
serializer.

## Patch boundary

The patch:

- adds a validated `DtlsCertificateChain` containing certificates in
  leaf-first order;
- sends every configured entry in DTLS 1.2 and DTLS 1.3 Certificate messages;
- emits both the existing leaf-only `Output::PeerCert` event and a new complete
  `Output::PeerCertChain` event, preserving leaf fingerprint behavior;
- owns the leaf event bytes so an otherwise valid peer certificate larger than
  the caller's poll buffer cannot trigger a production assertion;
- replaces raw retained key vectors with `DtlsPrivateKey`, whose clones clear
  their live allocations before release;
- converts the key owner before fallible chain validation, so failed
  construction also clears key bytes;
- moves that owner through auto negotiation and DTLS 1.3-to-1.2 fallback
  without creating an unprotected retained copy;
- wraps temporary SEC1-to-PKCS#8 encodings in zeroizing storage and uses
  `pkcs8::SecretDocument` for PEM decoding; and
- rejects incoming certificate lists beyond parser capacity instead of
  panicking;
- backports upstream algesten/dimpl#153 verbatim (except its `CHANGELOG.md`
  line): the DTLS 1.3 `CertificateRequest` omits the optional
  `certificate_authorities` extension instead of sending an empty list,
  keeps the required `signature_algorithms` extension, and leaves
  `require_client_certificate` and Ferrum's certificate verification
  unchanged (dimpl has no configured CA names to advertise, so omission is
  the only valid encoding);
- passes a `DtlsCertificateChain` to `Engine::new` in the inline
  `dtls13::engine` test helper, so the crate's `--lib` test target compiles
  against the constructor signature this patch changed; and
- makes documentation-only corrections to the vendored `README.md` /
  `CLAUDE.md` Sans-IO poll-loop illustrations so they cover every current
  `Output` variant and drain to `Timeout` before acting on `CloseNotify`
  (no protocol or code change).

The zeroization guarantee covers DER byte owners managed by `dimpl`.
After parsing, signing keys are opaque objects owned by the selected
cryptographic provider (`aws-lc-rs` or RustCrypto); their internal scalar
storage follows that provider's secret-memory lifecycle and is not observable
through the deterministic byte-owner hook.

Two ownership boundaries sit outside that guarantee:

- **Protocol close is not destruction.** `Dtls::close()` changes protocol
  state while retaining the endpoint/engine in the `Dtls` value; managed
  DER is cleared when that value is dropped. The shutdown zeroization
  regression below therefore exercises `drop(endpoint)`: its guarantee is
  destruction-time erasure, not immediate erasure on a retained endpoint
  after protocol close. Replacing a whole protected `DtlsPrivateKey` owner
  keeps the guarantee, because the displaced owner is itself dropped.
- **The compatibility raw field is caller-owned once mutated.**
  `DtlsCertificate.private_key` is a public `Vec<u8>`; replacing or
  extracting it releases or moves the previous allocation independently of
  the enclosing value's `Drop`. Callers mutating that raw field must clear
  the displaced bytes themselves, or use the protected `DtlsPrivateKey`
  owner through `DtlsCertificateChain`.

`DtlsCertificateChain::new` performs **structural** validation only
(non-empty chain/certificates/private key, wire-length bounds); it does not
parse the private key with the selected crypto provider. An `Ok` chain
therefore does not by itself establish that endpoint construction succeeds:
certificate-authenticated `Dtls::new_12` / `new_13` / `new_auto` parse the
key through the configured provider's key loader and panic if that parse
fails (the PSK-only `new_auto` delegation does not parse the key). The
vendored rustdoc states this prevalidated-key prerequisite on the chain
constructor and in each constructor's "Panics" section. Ferrum's loader
(`src/dtls/mod.rs`) satisfies the prerequisite: it parses the key with the
build-selected signing provider and with dimpl's key provider before
returning a chain, so no Ferrum loader path reaches the constructor panic.

## Provenance and audit artifacts

`vendor/dimpl-0.6.1-ferrum-patched/` is the complete crates.io 0.6.1 package,
including source, tests, README, changelog, both licenses, and
`.cargo_vcs_info.json`. `dimpl-0.6.1-ferrum.patch` is the unified diff against
the unmodified registry package and also creates Cargo's non-source
`.cargo-ok` cache marker, so applying it reproduces the complete governed
vendor directory. The committed crate-local `Cargo.lock` pins the dependency
graph for the hosted standalone credential-security regression (`cargo test
--manifest-path vendor/dimpl-0.6.1-ferrum-patched/Cargo.toml ...`).
`VENDOR_INTEGRITY.sha256` records the LF-normalized digest of every governed
vendored file, including that lockfile via the
`GOVERNED_VENDOR_LOCKFILES` allowlist in
`tests/integration/vendor_integrity_tests.rs`.

To reproduce the vendored tree without executing project code:

```sh
audit_dir="$(mktemp -d)"
curl -fL --proto '=https' \
  https://static.crates.io/crates/dimpl/dimpl-0.6.1.crate \
  -o "$audit_dir/dimpl-0.6.1.crate"
printf '%s  %s\n' \
  ef7eed0cf766b110880acdd89a860061dee42ed5f64df0fa43c80203e4f60916 \
  "$audit_dir/dimpl-0.6.1.crate" | shasum -a 256 -c -
tar -xzf "$audit_dir/dimpl-0.6.1.crate" -C "$audit_dir"
patch -d "$audit_dir/dimpl-0.6.1" -p1 \
  < docs/upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/dimpl-0.6.1-ferrum.patch
diff -rq "$audit_dir/dimpl-0.6.1" vendor/dimpl-0.6.1-ferrum-patched
```

The path patch is intentionally narrow: only `dimpl` is redirected. Existing
dependency features and Ferrum's public DTLS behavior remain intact.
`deny.toml` needs no source exception because path dependencies are already
covered by the repository's documented vendored-source policy; the crate's
MIT/Apache-2.0 license is already allowed.

## Regression coverage

- `vendor/dimpl-0.6.1-ferrum-patched/tests/auto/credential_security.rs`
  exercises full-chain wire output on explicit DTLS 1.2 and 1.3, plus clone,
  failed-construction, auto/fallback, shutdown zeroization, and valid leaf
  certificates larger than the caller's poll buffer. The shutdown case
  (`dtls13_shutdown_zeroizes_retained_private_key_owner`) calls
  `drop(endpoint)`, so it pins the destruction-time guarantee above; it
  does not claim erasure while a closed endpoint is still retained.
- The `test-hooks` feature invokes a post-zeroization observer while the
  allocation is still live. Tests never inspect freed memory.
- `dtls13::server::tests::certificate_request_omits_empty_certificate_authorities`
  (upstream's #153 regression, run by the `Vendored Patch Regressions` CI job
  with `cargo test --manifest-path vendor/dimpl-0.6.1-ferrum-patched/Cargo.toml --lib certificate_request_omits_empty_certificate_authorities`)
  parses the serialized `CertificateRequest` and fails if a
  `certificate_authorities` extension is emitted. Before the backport it fails
  on `!extension_types.contains(&ExtensionType::CertificateAuthorities)`.
  Interoperability was additionally checked out of tree with registry dimpl
  0.8.0 (which rejects an empty list with `LengthValue`) as a DTLS 1.3 client
  against this server with `require_client_certificate(true)` through
  `Dtls::new_auto`: before the backport the client discards the server flight
  and never connects; after it, the client connects, the server receives the
  client certificate, and application data round-trips.
- `tests/integration/dtls_integration_tests.rs` configures
  root → intermediate → leaf, trusts only the root, and completes a real
  Ferrum handshake because the intermediate is transmitted.
- Loader coverage pins configured ordering and leaf/private-key validation.
- UDP logging continues to use the same shared loader and cached chain owner.

## Retirement

Retire the vendor copy only after a compatible upstream release:

1. accepts and transmits complete local chains in DTLS 1.2, DTLS 1.3, and
   auto/fallback paths;
2. exposes the peer chain without changing existing leaf fingerprint
   semantics;
3. clears every dependency-retained private-key byte copy on failed
   construction, clone drop, fallback, replacement of a protected owner,
   and drop of the endpoint (protocol `close()` alone, which retains the
   endpoint, is not required to erase it); and
4. preserves Ferrum's supported ECDSA P-256/P-384 and constructor APIs.

Any such release already contains the #153 `CertificateRequest` fix (0.7.0
and later), so the backport adds no retirement condition of its own.

Then remove the `[patch.crates-io]` rows (root `Cargo.toml`, `fuzz/Cargo.toml`
and `tests/performance/mesh/Cargo.toml`), regenerate the three lockfiles while
the vendor copy still exists, then remove the vendor directory, its
`vendor/VENDOR_INTEGRITY.sha256` entries and `GOVERNED_VENDOR_LOCKFILES`
allowlist entry, the `Vendored Patch Regressions` CI step, the inventory row in
`docs/dependency-policy.md`, and the entry in
`docs/vendored-patch-lifecycle.json`. Keep the Ferrum interoperability tests
against the upstream release.

## Upstream hand-off

`issue.md` and `pr-description.md` are ready-to-file drafts. When upstream work
is filed, record its links here, in `docs/dependency-policy.md`, and in
`docs/vendored-patch-lifecycle.json`.
