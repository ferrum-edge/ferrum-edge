security: transmit certificate chains and zeroize retained keys

### What

- Add a leaf-first certificate-chain credential accepted by DTLS 1.2, DTLS
  1.3, and auto negotiation.
- Serialize every configured certificate and expose the received peer chain
  while retaining the existing leaf event.
- Replace retained private-key byte vectors with a zeroizing owner whose clones
  also clear on drop.
- Carry that owner through pending/fallback state and zeroize temporary
  key-format conversions.
- Fail safely when an incoming certificate list exceeds parser capacity.

### Security boundary

The guarantee covers byte owners retained by `dimpl`, including failed
construction, endpoint clones, protocol fallback, replacement, and shutdown.
Parsed signing-key objects are opaque provider-owned secrets and follow their
provider's lifecycle.

### Testing

- Explicit DTLS 1.2 and 1.3 full-chain wire tests.
- Deterministic post-zeroization hook for clone and failed-construction drops.
- Auto-server DTLS 1.2 fallback and shutdown ownership regression.

No test reads released memory.
