### Summary

`dimpl` accepts only one local certificate and retains private-key DER in
ordinary `Vec<u8>` owners. Applications cannot transmit a leaf-first
certificate chain, and dependency-owned credential copies are released without
an explicit clear.

### Certificate-chain impact

Both DTLS 1.2 and DTLS 1.3 serializers create a Certificate message containing
one entry. A server configured with leaf + intermediate therefore sends only
the leaf, and a client that trusts only the root cannot complete path
validation.

### Private-key ownership impact

The endpoint credential, configuration clones, auto-negotiation pending state,
and DTLS 1.3-to-1.2 fallback state can retain private-key byte vectors.
Clearing an application's original input does not clear these dependency-owned
copies.

### Proposed behavior

- Accept a validated leaf-first certificate chain and transmit it in configured
  order in both protocol versions.
- Preserve the existing leaf event and add complete peer-chain output.
- Store every retained key-byte copy in a zeroizing owner.
- Convert to that owner before fallible validation and preserve it through
  clones, fallback, replacement, and shutdown.
- Zeroize temporary key re-encodings used by key providers.
- Add deterministic drop hooks that observe the still-live allocation after it
  has been cleared.

### Compatibility

Existing single-certificate constructors can accept the legacy credential via
`Into` conversion. ECDSA P-256/P-384 behavior and leaf fingerprint semantics
remain unchanged.
