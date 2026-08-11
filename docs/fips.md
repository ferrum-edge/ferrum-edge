# FIPS 140-2 / 140-3 Deployment Mode

## Status of this document

**Ferrum Edge is not a validated cryptographic module and is not independently
FIPS-certified. No configuration or build of this binary makes it so.** What the
`fips` build profile does is select the AWS-LC FIPS module implementation,
route Ferrum's cryptography through it, and refuse, fail-closed, anything it
cannot route. A claim that a *deployment* is using a validated module still
depends on matching that artifact to an active CMVP certificate, the certified
module version and operating environment, and the operational controls that
are the operator's to establish — §"The module boundary" enumerates them.

This document describes:

1. the two mutually exclusive build profiles and how to build the FIPS one;
2. the runtime request surface, its precedence, and its fail-closed behaviour;
3. what the mode admits and what it refuses;
4. the module boundary, the self-test and key-management assumptions, and the
   features that are deliberately unsupported inside it;
5. how an operator verifies what is actually running.

## Build profiles

The cryptographic backend is a **mutually exclusive** cargo-feature pair.
Selecting both, or neither, is a `compile_error!`.

| Profile | Build command | Backend | `BUILD_CAPABLE` |
|---|---|---|---|
| Ordinary (default) | `cargo build --release` | `ring` + `rustls/ring` | `false` |
| FIPS | `cargo build --release --no-default-features --features fips` | `aws-lc-fips-sys` via `aws-lc-rs/fips` + `rustls/fips` | `true` |

The ordinary profile retains Ferrum's existing Ring-backed behavior; the
existence of the FIPS profile does not opt an ordinary deployment into a new
provider. `FERRUM_FIPS_MODE=enforce` on an ordinary build refuses to start, with
a diagnostic that names the missing module. It never downgrades to `ring`.

Exclusivity is not stylistic. `sqlx-core`, `quinn-proto`, `tonic`, `ldap3`, and
`hyper-rustls` each gate their aws-lc arm on the *absence* of their ring arm, so
additively "also enabling aws-lc" produces a build that reports a FIPS provider
while several real traffic paths still run `ring`. `src/fips/mod.rs` enforces the
pair at compile time and
[`.github/scripts/check_fips_feature_policy.py`](../.github/scripts/check_fips_feature_policy.py)
re-checks the **resolved** feature graph in CI, because a transitive edge can
re-enable `rustls/ring` without this crate's feature list ever mentioning it.

### Building the FIPS profile

`aws-lc-fips-sys` compiles the FIPS build of AWS-LC from source. Ferrum's CI
keeps that upstream build path intact and verifies the selected profile, but a
successful source build is a functional gate, not CMVP certificate evidence.
An operator making a validation claim must also show that the pinned crate and
resulting module match the version, installation procedure, configuration, and
operating environment in the applicable vendor security policy.

Prerequisites (in addition to Ferrum's usual `protoc`):

- a C/C++ toolchain
- CMake and a generator (`ninja` or `make`)
- Go
- Perl

```bash
cargo build --release --no-default-features --features fips --bin ferrum-edge
```

**Lockfile.** The committed `Cargo.lock` pins both profiles, including the
FIPS-only module package. A lockfile entry does not compile or link that package
into an ordinary artifact; feature selection still controls the build. FIPS
builds use `--locked`, and a FIPS release must retain that lockfile, the exact
toolchain version, and the container base image with its deployment evidence.

**Container images.** The published Ferrum images are ordinary-profile builds.
A FIPS deployment builds its own image; the base image and its kernel must be on
the module certificate's tested-platform list (see §"The module boundary").

## Current capability

| | Status |
|---|---|
| Mutually exclusive `crypto-ring` / `fips` build profiles | **Shipped** |
| AWS-LC FIPS module integration linked by the `fips` profile | **Shipped** |
| Resolved-feature-graph audit in CI (both profiles, and every claimed optional combination) | **Shipped** |
| Hosted compile lane for every claimed optional FIPS combination | **Shipped** |
| Approved key-strength/form admission for certificates and JWKS keys | **Shipped** (`src/fips/keys.rs`) |
| Fail-closed gate on every independently configurable peer-verification opt-out | **Shipped** |
| Request surface (`--fips-mode`, `FERRUM_FIPS_MODE`, `FERRUM_FIPS_REQUIRED_PROVIDER`) | **Shipped** |
| Fail-closed bootstrap, including the module's power-on self-test | **Shipped** |
| Single crypto-provider seam (`crate::fips`) across all rustls construction | **Shipped** |
| Module-backed SHA-2 / HMAC-SHA-2 for security-relevant digests and MACs | **Shipped** (`crate::fips::approved`) |
| Admission policy at `validate`, startup, SIGHUP reload, DB poll apply, CP publication, DP apply | **Shipped** |
| Authenticated status/health metadata, with `certified: false` | **Shipped** |
| Source-level crypto inventory with an empty work register | **Shipped** (`src/fips/inventory.rs`) |
| Ferrum Edge itself certified as a cryptographic module | **No — and it will not be.** Ferrum is an application that calls a module |

## Configuration

Precedence follows Ferrum's standard order: **CLI > environment > `ferrum.conf`
> default**, with one deliberate exception documented below.

| Setting | Values | Default |
|---|---|---|
| `--fips-mode` / `FERRUM_FIPS_MODE` | `off`, `enforce` (also `true`/`false`/`on`/`disabled`) | `off` |
| `FERRUM_FIPS_REQUIRED_PROVIDER` | `aws-lc-fips` | `aws-lc-fips` |

An unrecognized `FERRUM_FIPS_MODE` value is a configuration error, not a silent
downgrade — a typo'd `enfroce` must not quietly run non-FIPS.

`FERRUM_FIPS_MODE` is a *runtime request*; the build profile is what decides
whether it can be satisfied. `enforce` on an ordinary build refuses startup;
`off` on a FIPS build runs the selected AWS-LC FIPS provider profile without
applying Ferrum's admission policy, which is a supported (if unusual)
configuration for staging a rollout. It is not evidence of a compliant
deployment.

`FERRUM_FIPS_REQUIRED_PROVIDER` pins the integration the operator audited. Only
`aws-lc-fips` is supported, so today its only effect is to reject a value that
names something else; its purpose is forward-looking, so a future build that
changed integrations cannot silently satisfy an existing deployment contract.

### The `ferrum.conf` exception

The rustls process-default cryptographic provider must be installed **before any
TLS material is parsed**, which is before `ferrum.conf` can be read (reading the
settings file that early would pin `CONF_FILE_CACHE` to the wrong path — see
`.claude/rules/tls-security.md`). A FIPS request therefore has to arrive through
the CLI flag or the process environment.

A request that appears **only** in `ferrum.conf` is not ignored: after `EnvConfig`
resolution, `fips::verify_resolved_mode` detects the mismatch and fails the
command with an explicit message telling the operator to move the setting. It
never serves under a provider chosen from a stale view of the request.

**The resolved mode is immutable for the life of the process.** The rustls
process-default provider can be installed exactly once, so a reload cannot turn
enforcement on or off; `fips::state()` is established at bootstrap and read
unchanged thereafter. This is enforced, not merely documented: the late-request
path above fails the command on *both* build profiles rather than promoting the
mode after the fact. Changing the mode is a restart. Every *incoming*
configuration document is still validated against the resolved mode at every
admission point, so an immutable mode does not mean an unchecked config.

## What FIPS mode enforces

All of the following run identically during `ferrum-edge validate`, at startup,
and at every rustls policy construction — including after a frontend TLS live
reload, which rebuilds through the same constructor.

**Transport**

- TLS versions restricted to 1.2 / 1.3 (SP 800-52r2).
- Cipher suites and key-exchange groups screened by rustls's own
  `SupportedCipherSuite::fips()` / `SupportedKxGroup::fips()`. Ferrum delegates
  the classification rather than re-deriving an allow-list, so its notion of
  "approved" cannot drift from the module's.
- FIPS defaults drop **ChaCha20-Poly1305** (not an approved AEAD) and **X25519**
  (ECDH over Curve25519 is not an approved SP 800-56A scheme). An explicitly
  configured non-approved suite or group is rejected with a bounded diagnostic
  naming it — never silently dropped from the list.
- Peer certificate verification cannot be disabled on any surface; see
  §"Peer verification" below for the complete list.

**Keys and algorithms**

- JWT/JWS algorithms restricted to HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384 across gateway plugins and CP/DP namespace trust bundles.
  `none` is always rejected. `EdDSA` is rejected — Ed25519 is
  approved by FIPS 186-5 but is not part of the algorithm set Ferrum routes
  through the selected module, so admitting it would be an unbacked claim.
  `ES512` is rejected for a related but distinct reason: ECDSA over P-521 *is*
  an approved FIPS 186-5 scheme, but the `jsonwebtoken/aws_lc_rs` backend this
  profile selects exposes no P-521 JWS path at all, so admitting it would be an
  allow-list entry that fails at first use rather than at admission.
- `FERRUM_ADMIN_JWT_SECRET`, `FERRUM_CP_DP_GRPC_JWT_SECRET`, and
  `FERRUM_BASIC_AUTH_HMAC_SECRET` must be at least 32 bytes (SP 800-107 HMAC
  key strength).

**Key strengths and forms (Ferrum-enforced, not provider-enforced)**

This is a distinct gate, and the distinction matters for an audit. The rustls
FIPS provider refuses a non-approved *algorithm*: it will not negotiate a suite,
group, or signature scheme outside the approved set, and `check_tls_policy`
re-asserts that over the constructed policy. It does **not** uniformly refuse an
approved algorithm used with an under-strength key — an RSA-1024 leaf is
`rsaEncryption` with `rsa_pkcs1_sha256`, both nominally approved, while
SP 800-131A Rev. 2 disallows the 1024-bit *key*. Ferrum therefore enforces key
policy itself, at admission:

- **Certificates** — RSA modulus of 2048–8192 bits with an odd public exponent
  greater than 65536 and at most 256 bits, or ECDSA over the exact named curves
  P-256 / P-384 / P-521 with a matching SEC1 point form. Curve identity is read
  from the certificate AlgorithmIdentifier OID, never inferred from byte length
  (secp256k1 points are the same size as P-256, while P-521 coordinates occupy
  66 bytes). DSA (withdrawn by FIPS 186-5), the GOST curves, and
  Ed25519 / Ed448 / X25519 are refused. Enforced at
  `tls::parse_pem_certificate_bundle`, which is the single PEM loading boundary
  for frontend, admin, backend, mesh, DTLS, CP/DP, health-check, SPIFFE, client
  CA, PKCS#11 leaf, and ACME-issued material. **Every record in a bundle is
  checked, including intermediates and trust anchors** — an approved leaf
  chained to an RSA-1024 issuer is still an RSA-1024 signature verification.
- **JWKS signing keys** — RSA modulus of at least 2048 bits with the same public
  exponent form, and EC keys that explicitly name P-256 or P-384 and carry
  exact-width public coordinates. A missing `crv` never defaults under FIPS
  enforcement. `P-521` is refused here because its only JWS use is `ES512`,
  which is refused above; admitting the curve while refusing every algorithm
  that could use it would only move the failure later. Padding on `n` contrary
  to RFC 7518 §6.3.1.1 is not credited toward the floor.
- The upper RSA bound is not a security floor but a denial-of-service bound: an
  oversized modulus costs every handshake that touches it, and no approved
  profile needs one.

Only **public** key material is inspected — a certificate's
`SubjectPublicKeyInfo`, or a JWK's public components. Private keys continue to
flow through the existing secure loading boundary (`parse_pem_private_key`) and
are never parsed, copied, or logged by this gate. Diagnostics name the surface,
the algorithm family, and the observed bit length, and nothing else.

**Peer verification — every independently configurable opt-out**

An unverified peer defeats the point of an approved key exchange: the module can
perform a perfect ECDHE and it is still a key agreement with whoever answered.
A gate on the *global* switch alone is exactly the hole a per-surface switch
walks through, so all of the following are refused:

| Surface | Setting |
|---|---|
| Global outbound | `FERRUM_TLS_NO_VERIFY=true` |
| Admin API client | `FERRUM_ADMIN_TLS_NO_VERIFY=true` |
| Admin listener transport | `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` |
| CP/DP configuration transport | `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` |
| Injector admission webhook | `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` |
| Mesh stream egress | `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` |
| Mesh identity | `FERRUM_MESH_ALLOW_NO_CA`, `FERRUM_MESH_ALLOW_STATIC_ID`, `FERRUM_MESH_CA_BOOTSTRAP_DEV` |
| Config database | MongoDB config stores are refused in their entirety. For PostgreSQL and MySQL, an explicitly configured `FERRUM_DB_TLS_MODE` of `disable`, `allow`, `prefer`, or `require` is refused — none of them authenticate the server certificate chain — leaving `verify-ca` and `verify-full` as the only admitted values. When `FERRUM_DB_TLS_MODE` is unset, each of `FERRUM_DB_URL`, `FERRUM_DB_FAILOVER_URLS`, and `FERRUM_DB_READ_REPLICA_URL` must itself select a verifying mode (`sslmode=verify-ca`/`verify-full` for PostgreSQL; `ssl-mode=VERIFY_CA`/`VERIFY_IDENTITY` for MySQL); absent or weaker URL parameters are refused |
| Backend, per upstream/proxy | `backend_tls_verify_server_cert: false` (this also covers the mesh `DestinationRule.trafficPolicy.tls.insecureSkipVerify` override, which is projected onto it before admission) |
| `spec_expose` | `tls_no_verify: true` |
| `load_testing` | `gateway_tls_no_verify` — refused when `gateway_tls` is on and it is not explicitly `false`, because it **defaults open** |
| `udp_logging` | `dtls_no_verify: true` |
| `api_chargeback_sink` | `clickhouse.tls.insecure_skip_verify: true`, `clickhouse.tls.verify_hostname: false` |
| `mesh_route_dispatch` | `rules[].destination.backend_tls.verify_server_cert: false` |
| `ai_transcript_audit` | `sink.allow_insecure_loopback: true` |
| `ldap_auth` | `allow_plaintext: true` |
| `ai_federation` | `providers[].allow_plaintext: true` |
| `ai_stream_router` | `providers[].allow_plaintext: true` |

Two entries are deliberately absent, each with a test that keeps the reasoning
honest rather than leaving it as a comment:

- `FERRUM_DP_GRPC_TLS_NO_VERIFY` is already refused **unconditionally**, on every
  build and in every mode, by the ordinary validator. A FIPS rule for it would
  be unreachable, so instead a test asserts that unconditional rejection still
  holds — relaxing it fails a FIPS test rather than silently opening a bypass.
- `kafka_logging`'s `ssl_no_verify` is covered by the refusal of the whole
  plugin (below). A test pins that relationship so removing the plugin-level
  rejection cannot orphan the key.

`backend_tls_verify_server_cert: false` is refused **even where it is currently
inert** — for example on a plaintext backend. That is a deliberate decision, not
an oversight, and it is tested as such: an `Upstream` carries no scheme of its
own, so "inert" is a property of its targets and of every proxy referencing it,
none of which is stable across the hot reload or CP publication this gate exists
to backstop. The remedy is free and unambiguous — `true` is the schema default
and a no-op on a plaintext backend. A plugin key whose *enabling sibling* is off
in the same document (`load_testing` without `gateway_tls`) is not reported,
because there the gate is a value in the document being admitted rather than an
inference about a different one.

Diagnostics name entries by their one-based **position** (`upstreams[#3]`),
never by `id`: an id is operator free text, while a position is enough to find
the entry and discloses nothing.

**Digests, MACs, and stored passwords**

- Security-relevant SHA-2 and HMAC-SHA-2 — request MAC verification
  (`hmac_auth`), stored-password MACs (`basic_auth`), LDAP bind-cache keying,
  DPoP proofs and JWK thumbprints, client-certificate thumbprints, PKCE
  challenges, OIDC session context, AWS SigV4 signing, ACME key
  authorizations, keyed PII redaction, replay partitioning, workload
  attestation, semantic-cache Redis envelope authentication, trust-material
  rotation, duplicate-JSON verdict memoization, policy provenance, and
  identity-bound connection-pool keys — run through `crate::fips::approved`,
  which is backed by the selected module. They were migrated off the RustCrypto
  `sha2`/`hmac` crates for exactly this reason: an approved *algorithm* computed
  by an unvalidated *implementation* is still outside the boundary.
- Ferrum's only stored-password representation is `hmac_sha256:<64 hex>`, an
  approved keyed MAC. A stored hash in any other representation is refused: it
  would be a KDF Ferrum has not classified. The unreferenced `argon2`
  dependency was **removed** from the build rather than policy-gated, so no
  non-approved KDF is linked at all.
- SHA-1 remains present for the RFC 6455 `Sec-WebSocket-Accept` handshake value,
  a non-security cache-poisoning guard over a fixed public GUID that carries no
  key and protects no secret. Non-security content-addressing digests listed in
  the inventory use the selected provider's SHA-256 seam but remain classified
  as `outside-boundary` because they are not security services.
- JWT-SVID trust material (issue #3617) admits an EC authority only after proving
  the published point actually lies on its named curve. That proof is a bounded
  ephemeral ECDH agreement at the provider seam (`fips::ec_point_on_named_curve`
  — `ring` on an ordinary build, the AWS-LC FIPS module on a `fips` build), whose
  peer-public-key acceptance performs the SEC1 point validation; the shared
  secret is discarded. It is routed through the seam rather than through a
  RustCrypto elliptic implementation precisely so a FIPS build gains no second,
  unrouted curve arithmetic on a trust-admission path. The two backends'
  `agree_ephemeral` signatures differ, and that divergence is absorbed in
  `src/fips/mod.rs` alongside every other provider difference rather than being
  cfg-split at the call site.
- Reqwest, Kubernetes, and MongoDB clients have their provider-selecting default
  features disabled. Their rustls transports follow the same mutually exclusive
  `crypto-ring` / `fips` feature pair as Ferrum's frontend, backend, and control
  plane TLS, so none can re-enable Ring transitively in a FIPS build. Reqwest's
  paired internal provider arms also give library/test clients a deterministic
  fallback before the binary bootstrap installs the same process-wide provider.

**Rejected configurations**

- `soap_ws_security` with `rsa-sha1` signature or `sha1` digest selections:
  SHA-1 is disallowed for signature generation and verification (SP 800-131A
  Rev. 2). The `rsa-sha256` / `sha256` selections on the same plugin are
  module-backed and admitted.
- `kafka_logging`: librdkafka performs its TLS through OpenSSL, outside the
  selected module. Use `tcp_logging`, `ws_logging`, or `http_logging`, which are
  rustls-based.
- **Every DTLS surface** — a frontend DTLS listener
  (`FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH`), a `backend_scheme: dtls`
  stream proxy, and a `udp_logging` sink with `dtls: true`. See
  §"DTLS: why the whole transport is refused".
Every diagnostic is bounded — at most 8 offending entries are named, followed by
a count — and carries no secret, key material, path, or free-form
operator-supplied value.

## The module boundary

A FIPS 140-2/140-3 certificate covers a **cryptographic module**, not an
application. When the AWS-LC-FIPS integration ships, the boundary is:

**Inside the module** — block ciphers and AEADs, hashes and HMAC, the DRBG,
signature generation/verification, key agreement, and the TLS/QUIC key schedules
that consume them.

**Outside the module, Ferrum's responsibility** — protocol state machines,
certificate path building and policy, configuration admission, key *storage* and
file permissions, algorithm *selection* (what this mode enforces), and the
correctness with which Ferrum calls the module.

**Outside the module, the operator's responsibility** — and no gateway code can
discharge these:

- **The exact validated module.** A certificate names a module version and the
  conditions under which it is approved. The current NIST listing for the
  AWS-LC 3 static module is
  [CMVP certificate #5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314),
  whose caveat requires installation, initialization, and configuration as
  specified by its security policy. The operator must prove that the pinned
  `aws-lc-fips-sys` release and built artifact match the applicable certificate
  and must record the certificate number, module version, build procedure, and
  operating environment. A green arbitrary source build is not that proof.
- **Build reproducibility.** The binary an auditor examines must be the binary in
  production.
- **Operating environment.** The certificate's tested platform list is part of
  the validation. A container base image, kernel, and CPU feature set outside
  that list is outside the validation.
- **Key management.** Generation, storage, rotation, escrow, and destruction of
  private keys, JWT secrets, and PKCS#11 token credentials.
- **PKCS#11 tokens.** Signing happens inside the operator's HSM, which must carry
  its own validation. Ferrum's mode says nothing about it.
- **Secret delivery.** The cloud secret providers are refused in enforce mode
  (see §"Deliberately unsupported"), so delivering `_FILE`-backed or direct
  environment secrets over a transport the operator has validated is the
  operator's control, not Ferrum's.

## Source-level crypto inventory

`src/fips/inventory.rs` is the machine-readable inventory: every
security-relevant cryptographic operation, the source location that performs it,
the implementing library, and its disposition. `tests/unit/tls/fips_policy_tests.rs`
asserts the invariants that keep it honest — every row carries a rationale, the
rejected-plugin set agrees with the admission policy, every `rejected` row names
the check that refuses it, and the work register is empty.

Dispositions:

- **`module-routable`** — the operation resolves its implementation through
  Ferrum's provider seam (`fips::base_crypto_provider`, `fips::backend`,
  `fips::approved`) or through a dependency backend the `crypto-ring` / `fips`
  feature pair selects. On a FIPS build it reaches the selected AWS-LC FIPS
  module implementation. Applicability of a CMVP certificate remains a
  deployment-evidence question.
- **`rejected`** — cannot reach the module; `src/fips/policy.rs` refuses the
  configuration that would perform it, before serving.
- **`outside-boundary`** — not a security claim Ferrum makes. Either the
  operation is not a security service (a protocol handshake token, a cache key,
  a change-detection digest, scheduling jitter), or the cryptography is performed
  by a separately validated component the operator supplies (an HSM behind
  PKCS#11, a remote KMS).
- **`pending-classification`** — security-relevant and *not* routed. **This set
  must be empty**, and a test fails if it is not. The variant exists so a newly
  discovered surface has an honest place to land while it is being routed or
  rejected, never as a standing residual-work list.

A note on the last two, because the distinction is the whole point of the table:
Ferrum-owned production source no longer imports RustCrypto `sha2` or `hmac`.
Even non-security SHA-256 work such as ETags, telemetry identities,
configuration-drift summaries, and xDS nonces uses the selected-provider seam,
so there is no second Ferrum-owned implementation to misclassify later. Those
operations remain recorded as `outside-boundary`: they carry no key, protect no
secret, and authenticate nothing, so executing them inside the module does not
turn them into a FIPS security service. RustCrypto remains a dev dependency only
for independent test vectors and request-signing fixtures.

## Self-test and key-management assumptions

**Power-on self-tests.** AWS-LC-FIPS runs its integrity check and known-answer
tests when the module initializes. Ferrum asks the module itself
(`aws_lc_rs::try_fips_mode()`) during bootstrap, before installing the provider
and before any TLS material is parsed. A module that does not report approved-mode
operation is a startup failure, not a warning: Ferrum will not serve or publish
configuration behind a module that failed its own tests. The result is reported
as `module_self_test_passed` on the authenticated status surface.

Ferrum does **not** re-implement or re-run the module's self-tests. On-demand
and conditional self-tests are the module's own behaviour.

**Entropy.** The module supplies the DRBG. Its seeding is part of the module's
approved-mode behaviour and depends on the operating environment; a container
with a constrained or virtualized entropy source is an operating-environment
concern the operator must satisfy, not something the gateway can compensate
for.

**Key management is entirely the operator's.** Ferrum stores no long-term keys of
its own. Generation, storage, file permissions, rotation, escrow, and destruction
of TLS private keys, JWT secrets, SVID material, and PKCS#11 credentials are
outside the module and outside Ferrum. The mode enforces *algorithm and key-size
policy* (for example the 32-byte HMAC key floor); it cannot enforce provenance.

## Deliberately unsupported in FIPS mode

Each of these is refused before serving, with an actionable diagnostic, rather
than being allowed to run outside the boundary:

| Capability | Why | Alternative |
|---|---|---|
| MongoDB config database | the driver performs authentication and protocol cryptography through independent HMAC, PBKDF2, SHA-1, SHA-2, and MD5 implementations; its AWS-LC rustls feature routes only TLS | PostgreSQL, MySQL, SQLite, or file mode |
| `kafka_logging` | librdkafka performs TLS through OpenSSL, which Ferrum cannot route onto the module | `tcp_logging`, `ws_logging`, `http_logging` (all rustls-based) |
| **DTLS** (frontend listener, `backend_scheme: dtls`, `udp_logging` `dtls: true`) | the vendored `dimpl` stack draws its handshake and record randomness from the `rand` crate, not the module DRBG | a TLS-terminating listener or a rustls-based sink |
| `soap_ws_security` `rsa-sha1` / `sha1` | SHA-1 is disallowed for signatures (SP 800-131A Rev. 2) | `rsa-sha256` / `sha256` |
| `EdDSA` JWTs | approved by FIPS 186-5, but not in the algorithm set Ferrum routes through the selected module | ES256/384, RS/PS256/384/512, HS256/384/512 |
| `ES512` JWTs | ECDSA over P-521 is approved, but the selected `jsonwebtoken/aws_lc_rs` backend exposes no P-521 JWS path — its `Algorithm` enum has no such variant | ES256 / ES384 |
| ChaCha20-Poly1305, X25519 | not an approved AEAD / not an approved SP 800-56A scheme | AES-GCM suites, secp256r1 / secp384r1 |
| RSA below 2048 bits; DSA, GOST, Ed25519/Ed448/X25519 certificates | SP 800-131A Rev. 2 / FIPS 186-5 | RSA 2048–8192, ECDSA P-256/P-384/P-521 |
| Any peer-verification opt-out | an unauthenticated peer defeats the approved key exchange | pin the peer's CA (see the table in §"What FIPS mode enforces") |
| **External secret providers** (`_VAULT`, `_AWS`, `_AZURE`, `_GCP`, and `vault://`, `aws://`, `azure://`, or `gcp://` TLS-material sources) | their SDKs resolve secrets over their own TLS stacks, which are not built from Ferrum's provider seam and are not selected by the `crypto-ring` / `fips` feature pair | a local file or direct value backed by an operator-validated delivery mechanism (mounted secret, init container, KMS-backed volume) |

### DTLS: why the whole transport is refused

DTLS is the one transport Ferrum terminates outside rustls. It runs on the
vendored `dimpl` stack (`vendor/dimpl-0.6.1-ferrum-patched`), which does select
`aws-lc-rs` for key agreement, signing, hashing, and record AEAD — so cargo
feature unification really does put those primitives inside the selected module
once `aws-lc-rs/fips` is on.

That is not sufficient, and the gap is specifically **randomness**. `dimpl`
exposes a module-backed `secure_random` (`src/crypto/aws_lc_rs/random.rs`) but
uses it only for signing and key-exchange keypairs. Its protocol randomness
comes from `SeededRng` in `src/rng.rs`, which is the `rand` crate's thread RNG:

- the DTLS handshake `Random` (`src/types.rs`, used by both the 1.2 and 1.3
  engines), which feeds the key schedule;
- the DTLS 1.2 `HelloVerifyRequest` cookie secret; and
- the DTLS 1.2 explicit AES-GCM record nonce, whose construction SP 800-38D
  pins to an approved source.

§"The module boundary" places the DRBG **inside** the module. Admitting DTLS
under enforcement would therefore be precisely the "uses a FIPS-capable library"
claim this mode exists to refuse, so `fips::policy` rejects every DTLS surface
before serving — at the environment gate for a frontend listener and at the
gateway-document gate for `backend_scheme: dtls` proxies and `udp_logging`
sinks, so `validate`, startup, reload, and CP/DP publication all agree.

Retiring the refusal means routing `dimpl`'s protocol randomness through its own
`secure_random` provider hook; that is an upstream change, tracked with the rest
of the vendored `dimpl` patch lifecycle in `docs/dependency-policy.md`.

### External secret providers: why this changed to a refusal

An earlier revision of this document recorded the cloud secret backends as
`outside-boundary` — allowed, on the reasoning that secrets resolve once at
startup before the gateway serves. That was an *implicit* claim that a
pre-serving TLS session to a credential store does not matter. It does: that
session carries the gateway's private keys and JWT secrets, and it is the one
connection whose compromise hands over everything else. Ferrum cannot route
those SDK stacks onto the selected module and cannot attest to what they use, so
an enforcing process now refuses them at
`fips::policy::check_external_secret_sources`, called from
`main::resolve_startup_secrets` **before any provider client is constructed**.

The `cloud-secrets` build still compiles under `--features fips` and is audited
in CI for exactly that reason: the refusal is what stands between the
combination and use, rather than a compile error nobody would recognise as
policy. `_FILE` remains supported — it is a local filesystem read that performs
no cryptography and reaches no network peer.

### Optional build profiles

Every optional cargo feature is explicitly claimed or explicitly refused; an
unlisted feature would be an implicit support claim, so
`check_claimed_profiles_declared()` fails the build when one appears without a
decision. The claimed set is enumerated by the checker itself
(`--list-claimed-profiles`), and CI resolves and audits the feature graph for
each, then compiles each against the real module:

| Combination | Status under FIPS |
|---|---|
| `fips` | Supported |
| `fips,acme` | Supported — `instant-acme/fips` + `hyper-rustls/fips`; the resolved-graph audit rejects any surviving `instant-acme/ring` |
| `fips,pkcs11` | Supported — signing happens inside the operator's token, which carries its own validation (`outside-boundary`); Ferrum's local randomness and RSA verification on this path use the selected module, and the PKCS#11 leaf certificate goes through the same key-strength admission |
| `fips,ebpf` | Supported — the eBPF capture path performs no cryptography |
| `fips,cloud-secrets` | **Builds, refused at runtime** (above) |

## Verifying a deployment

An operator confirms the runtime posture through the **authenticated** detail
tier of `/health` or `/status`:

```json
{
  "fips": {
    "mode": "enforce",
    "enforcing": true,
    "build_capable": true,
    "build_profile": "fips",
    "provider": "aws-lc-fips",
    "module_self_test_passed": true,
    "provider_algorithms_approved": true,
    "certified": false,
    "boundary_documentation": "docs/fips.md"
  }
}
```

`certified` is always `false` and is present precisely so that a status scraper
cannot read `enforcing: true` as "certified". This object is never exposed on the
unauthenticated coarse tier (`/live`, or `/health` without credentials), which
continues to return only `status` and `ready`.

`build_profile` is the field to compare against the artifact you intended to
deploy: it is `fips` only when the binary was compiled
`--no-default-features --features fips`.

A build that reports `enforcing: true` has already passed, at startup:

1. the build-capability gate (`BUILD_CAPABLE`),
2. the module's own power-on self-test,
3. rustls's classification of the installed provider as FIPS-approved, and
4. the whole admission policy over the resolved environment and the loaded
   gateway document.

Any one of those failing is a startup refusal, so a serving gateway reporting
`enforcing: true` is evidence that all four held — not merely that the operator
asked for them.

To verify the *build* independently of the running process:

```bash
# The resolved feature graph must carry aws-lc-rs/fips and rustls/fips, and no
# ring arm. This is the same audit CI runs, over the same enumerated set of
# claimed feature combinations — the checker owns that list, so a build cannot
# be audited under one set and documented under another.
python3 .github/scripts/check_fips_feature_policy.py --list-claimed-profiles \
| while IFS=$'\t' read -r label features; do
    cargo tree -e normal,build --prefix none -f '{p}|{f}' --locked \
      --no-default-features --features "$features" > /tmp/tree.txt
    python3 .github/scripts/check_fips_feature_policy.py \
      --tree /tmp/tree.txt --profile fips || echo "FAILED: $label"
  done
```

The gateway's report and the build audit are useful functional evidence, but
neither establishes that a deployment falls under a CMVP certificate.
Deployment compliance additionally requires the exact certified module version,
an applicable active certificate and security policy, a reproducible build, an
approved operating environment, and the operational controls enumerated in
§"The module boundary" — established and recorded by the operator.

**Ferrum Edge makes no certification claim of its own, and `certified` will
remain `false` on every build.**
