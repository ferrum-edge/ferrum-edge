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

## Runtime Behavior

Ferrum validates the token key at TLS config load by opening a read-only session, logging in when `pin_env` is set, and finding exactly one RSA private key for the configured selector. Each TLS signature opens a fresh read-only session because PKCS#11 sessions are not generally thread-safe.

Supported signature schemes are RSA-PSS SHA-512/SHA-384/SHA-256 and RSA PKCS#1 SHA-512/SHA-384/SHA-256. SHA-1 is intentionally not offered.

Live reload treats the PKCS#11 URI as a stable signer selector. Rotating the certificate, client CA, OCSP response, or CRL still reloads normally. Rotating the HSM key behind the same URI requires changing the cert/source config or restarting so the new certificate-key pairing can be validated intentionally.

PKCS#11 is supported only on rustls surfaces that accept custom signers: frontend/Admin API server TLS and backend TLS client authentication. Database drivers, tonic CP/DP gRPC TLS, gateway SVID, and DTLS paths still require materializable PEM key sources because those libraries do not expose a signer hook in the current integration.

## Vendor Notes

SoftHSM v2 is the recommended CI and local development target. Initialize a token, import or generate an RSA keypair with a stable label/id, point `FERRUM_PKCS11_MODULE_PATH` at `libsofthsm2.so`, then run the ignored smoke test with `FERRUM_PKCS11_TEST_KEY_SOURCE`. The GitHub Actions CI workflow installs SoftHSM v2, generates an RSA token key, and runs that smoke test on pull requests.

YubiHSM deployments usually expose PKCS#11 through the vendor connector. Configure `module` to the YubiHSM PKCS#11 library, set `slot` when multiple connectors/tokens are visible, and prefer `id_hex` selectors because labels are often reused.

AWS CloudHSM and GCP Cloud HSM deployments require the vendor client daemon/library on each Ferrum node before startup. Use `module` or `FERRUM_PKCS11_MODULE_PATH` for the vendor PKCS#11 library path and inject the PIN through a node-local secret mechanism rather than committing it to `ferrum.conf`.

Thales and other network HSMs follow the same pattern: install the vendor PKCS#11 client, configure the module path, ensure Ferrum's runtime user can access the client config/socket, and select the RSA private key by label plus id when possible.

## Smoke Test

The feature-gated smoke test is ignored by default because it needs real token state:

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
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 123456 \
  --token-label ferrum-ci --keypairgen --key-type rsa:2048 \
  --label edge-rsa --id 01 --usage-sign

export FERRUM_PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export FERRUM_PKCS11_PIN="123456"
export FERRUM_PKCS11_TEST_KEY_SOURCE="pkcs11://edge-rsa?pin_env=FERRUM_PKCS11_PIN&id_hex=01"
cargo test --features pkcs11 --lib tls::pkcs11::tests::signer_loads_configured_token_and_signs -- --ignored
```

Passing this test proves Ferrum can load the configured token key and produce an RSA signature through PKCS#11.
