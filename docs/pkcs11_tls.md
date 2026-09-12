# PKCS#11 TLS Keys

Ferrum can use non-extractable RSA private keys for frontend TLS, Admin API TLS, and backend mTLS client authentication when the binary is built with the `pkcs11` Cargo feature. The certificate chain is still loaded from a normal TLS cert source, but the private key source is a PKCS#11 signer URI. Ferrum never reads or stores private-key PEM bytes for that source.

```bash
cargo build --release --features pkcs11

export FERRUM_PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export FERRUM_PKCS11_PIN="token-user-pin"
export FERRUM_FRONTEND_TLS_CERT_SOURCE="file:///etc/ferrum/certs/frontend.crt"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="pkcs11://edge-rsa?pin_env=FERRUM_PKCS11_PIN"
```

Backend mTLS uses the same URI form:

```bash
export FERRUM_BACKEND_TLS_CLIENT_CERT_SOURCE="file:///etc/ferrum/certs/backend-client.crt"
export FERRUM_BACKEND_TLS_CLIENT_KEY_SOURCE="pkcs11://backend-rsa?pin_env=FERRUM_PKCS11_PIN"
```

## URI Format

`pkcs11://<label>?module=/path/to/pkcs11.so&pin_env=FERRUM_PKCS11_PIN`

Supported options:

| Option | Description |
|---|---|
| `module` / `module_path` | PKCS#11 shared library path for this source |
| `module_env` | Name of a `FERRUM_*` variable containing the module path |
| `pin_env` | Name of a `FERRUM_*` variable containing the token user PIN |
| `slot` / `slot_id` | Numeric slot id; if omitted, Ferrum uses the first slot with a token |
| `label` | Key label selector; overrides the URI path |
| `id_hex` / `id` | Hex key id selector, with optional `:` separators |
| `key_type` | Currently only `rsa` is supported |

If `module`, `module_path`, and `module_env` are omitted, Ferrum reads `FERRUM_PKCS11_MODULE_PATH`. PIN values are optional for tokens that expose the key without login, but production HSMs normally require `pin_env`.

Module overrides (`module`, `module_path`, and `module_env`) require the operator setting `FERRUM_PKCS11_MODULE_ALLOWED_PATHS`: a comma-separated list of absolute existing directories or exact module files. Ferrum canonicalizes both the module and every allowlist entry, rejects symlink or traversal escapes, and loads the canonical file path. Empty, relative, missing, or unresolvable entries fail closed. With the setting unset, omit **all** module options; only `FERRUM_PKCS11_MODULE_PATH` supplies the module. The default is also checked against the allowlist when one is set.

The policy is checked at configuration admission and again before loading the library. Each DP applies its own operator policy to CP-distributed references; CP approval cannot grant a DP permission to load a module. Install the allowed modules on each admitting node. Keep allowed files and directories, their ancestors, and native-library dependencies writable only by trusted operators; this path policy does not protect against local replacement of trusted library files.

## Runtime Behavior

Ferrum validates the token key at TLS config load by opening a read-only session, logging in when `pin_env` is set, and finding exactly one RSA private key for the configured selector. Each TLS signature opens a fresh read-only session because PKCS#11 sessions are not generally thread-safe.

Supported signature schemes are RSA-PSS SHA-512/SHA-384/SHA-256 and RSA PKCS#1 SHA-512/SHA-384/SHA-256. SHA-1 is intentionally not offered.

### Certificate Pairing Proof

Finding the key is not enough. Before a certified key is published to a frontend/Admin server-certificate resolver or to a backend mTLS client identity, Ferrum proves that the selected token key actually pairs with the leaf certificate from the configured cert source. Without that proof a selector typo or a half-finished HSM/certificate rotation loads cleanly and then fails *every* client handshake, taking a listener or a backend identity out of service.

Two proof paths, in order of preference:

1. **SubjectPublicKeyInfo comparison.** Ferrum reads `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` from the selected private-key object, reconstructs the RFC 5280 SubjectPublicKeyInfo, and hands it to rustls so `CertifiedKey::keys_match()` compares it byte for byte against the leaf certificate. Attribute sizes and DER reconstruction are bounded. This reads only public attributes; no private material is requested.
2. **Bounded sign-and-verify challenge.** If the selected private-key object discloses no usable public attributes, Ferrum has the token sign one 32-byte fresh random challenge with RSA PKCS#1 v1.5 SHA-256 and verifies the signature under the leaf certificate's public key. A separately selected `CKO_PUBLIC_KEY` is not treated as proof because a shared label or id is metadata, not cryptographic evidence that two token objects form a pair. This is a single signing operation performed once at config load, never on the request path. It requires an RSA key of 2048–8192 bits.

A mismatch, a non-RSA leaf certificate, an unparseable leaf, or a missing leaf is a hard error: the resolver or the backend client identity is never published. Errors name only the configured `pkcs11://` source and the label/`id_hex` selector already present in the configuration — never the PIN, token attribute bytes, the challenge, or the signature.

Because the proof runs inside the ordinary TLS config build, a **failed live reload keeps the previous known-good material**: the reload loop treats the error like any other rebuild failure, logs a warning, and leaves the currently published `ServerConfig` (or the cached backend client config) in place.

Live reload treats the PKCS#11 URI as a stable signer selector. Rotating the certificate, client CA, OCSP response, or CRL still reloads normally, and the rotated certificate is re-proved against the token key on each rebuild. Rotating the HSM key behind the same URI requires changing the cert/source config or restarting.

PKCS#11 is supported only on rustls surfaces that accept custom signers: frontend/Admin API server TLS and backend TLS client authentication. Database drivers, tonic CP/DP gRPC TLS, gateway SVID, and DTLS paths still require materializable PEM key sources because those libraries do not expose a signer hook in the current integration.

## Vendor Notes

SoftHSM v2 is the recommended CI and local development target. Initialize a token, import or generate an RSA keypair with a stable label/id, point `FERRUM_PKCS11_MODULE_PATH` at `libsofthsm2.so`, then run the ignored smoke test with `FERRUM_PKCS11_TEST_KEY_SOURCE`. The GitHub Actions `PKCS#11 SoftHSM Smoke Test` job installs SoftHSM v2, imports two distinct RSA token keys plus a certificate that pairs with only one of them, and runs both the signer smoke test and the certificate-pairing tests. The trusted CI planner schedules that job (`run_pkcs11`) on pull requests that touch PKCS#11 TLS sources, the SoftHSM unit tests, or shared compile-graph inputs; unrelated PRs skip it. Pushes to `main`, manual `workflow_dispatch` runs, and fail-closed planner cases still run it, including when `paths_classifiable` is missing or not exactly `true` because CI is executing an older trusted-base planner.

YubiHSM deployments usually expose PKCS#11 through the vendor connector. Configure `module` to the YubiHSM PKCS#11 library, set `slot` when multiple connectors/tokens are visible, and prefer `id_hex` selectors because labels are often reused.

AWS CloudHSM and GCP Cloud HSM deployments require the vendor client daemon/library on each Ferrum node before startup. Use `module` or `FERRUM_PKCS11_MODULE_PATH` for the vendor PKCS#11 library path and inject the PIN through a node-local secret mechanism rather than committing it to `ferrum.conf`.

Thales and other network HSMs follow the same pattern: install the vendor PKCS#11 client, configure the module path, ensure Ferrum's runtime user can access the client config/socket, and select the RSA private key by label plus id when possible.

## Smoke And Pairing Tests

The feature-gated tests are ignored by default because they need real token state:

```bash
export SOFTHSM2_CONF="$PWD/softhsm2.conf"
mkdir -p "$PWD/softhsm-tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $PWD/softhsm-tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
softhsm2-util --init-token --free --label ferrum-ci --so-pin 1234 --pin 123456

# Two software RSA keys so a certificate can be issued for exactly one of them,
# then both are imported into the token.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out edge-rsa.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out edge-rsa-mismatch.key
openssl req -x509 -new -sha256 -days 365 -key edge-rsa.key \
  -subj "/CN=ferrum-pkcs11-ci" -addext "subjectAltName=DNS:localhost" -out edge-rsa.crt
softhsm2-util --import edge-rsa.key --token ferrum-ci --pin 123456 --label edge-rsa --id 01
softhsm2-util --import edge-rsa-mismatch.key --token ferrum-ci --pin 123456 \
  --label edge-rsa-mismatch --id 02

export FERRUM_PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export FERRUM_PKCS11_PIN="123456"
export FERRUM_PKCS11_TEST_KEY_SOURCE="pkcs11://edge-rsa?pin_env=FERRUM_PKCS11_PIN&id_hex=01"
cargo test --features pkcs11 --lib tls::pkcs11::tests::signer_loads_configured_token_and_signs -- --ignored

export FERRUM_PKCS11_TEST_MISMATCHED_KEY_SOURCE="pkcs11://edge-rsa-mismatch?pin_env=FERRUM_PKCS11_PIN&id_hex=02"
export FERRUM_PKCS11_TEST_CERT_PATH="$PWD/edge-rsa.crt"
cargo test --features pkcs11 --test unit_tests tls::pkcs11 -- --include-ignored --test-threads=1
```

Passing the first test proves Ferrum can load the configured token key and produce an RSA signature through PKCS#11. The second run proves that server TLS and backend client mTLS accept the matching token key and reject the mismatched one before publishing any identity.

Run the pairing tests single threaded. PKCS#11 module initialization and token login state are process-global on common providers, so independent test contexts must not race each other.
