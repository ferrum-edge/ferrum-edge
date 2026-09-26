# Vendored tungstenite patches: WebSocket takeover and bounded parsing

> Governance: tracked in [docs/dependency-policy.md](../dependency-policy.md). Any
> change to `vendor/tungstenite-0.29.0-ferrum-patched/` or
> `vendor/tokio-tungstenite-0.29.0-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## What this patches

Ferrum vendors patched copies of `tungstenite` and `tokio-tungstenite` so
WebSocket tunnel mode can recover bytes that the backend coalesced with the
`101 Switching Protocols` response before dropping to raw bidirectional relay.
The tungstenite copy also carries Ferrum's early frame-policy enforcement: the
declared payload length is checked before reservation, valid Close frames bypass
the application ceiling, and every control frame is still rejected above RFC
6455's 125-byte limit before allocation. Frame-policy failures retain a
distinct `CapacityError::FrameTooLong` origin so the gateway can select the
correct close reason when frame and reassembled-message ceilings are equal.

## Upstream tracking

| Crate | Upstream PR | Applied commits | Local version |
|---|---|---|---|
| `tungstenite` | <https://github.com/snapview/tungstenite-rs/pull/556> | `117597cbfccf2af44e97561cb2efa713d8454ed2`, `78db146fb240776a3082621ce054927488423e86` | 0.29.0 |
| `tungstenite` frame-limit origin | **Deliberate fork — not yet filed upstream** | Ferrum local | 0.29.0 |
| `tungstenite` optional auto-pong | **Deliberate fork — not yet filed upstream** ([003](003-optional-auto-pong/)) | Ferrum local | 0.29.0 |
| `tungstenite` / `tokio-tungstenite` fragment accounting | **Deliberate fork — not yet filed upstream** ([004](004-fragment-accounting/)) | Ferrum local | 0.29.0 |
| `tungstenite` stray-continuation ordering | **Deliberate fork — not yet filed upstream** | Ferrum local | 0.29.0 |
| `tokio-tungstenite` | <https://github.com/snapview/tokio-tungstenite/pull/380> | `ba1d8f8897a09e4cdf1088456667e8c24ee15832` | 0.29.0 |

Both PRs were open when vendored. The local API names and return types match the
upstream proposals:

- `tungstenite::WebSocket::into_inner_with_read_buffer(self) -> (Stream, Bytes)`
- `tungstenite::WebSocketContext::into_read_buffer(self) -> Bytes`
- `tokio_tungstenite::WebSocketStream::into_inner_with_read_buffer(self) -> (S, tungstenite::Bytes)`

## Local modifications

- Copied the locked crates.io `0.29.0` sources under:
  - `vendor/tungstenite-0.29.0-ferrum-patched/`
  - `vendor/tokio-tungstenite-0.29.0-ferrum-patched/`
- Removed registry packaging files (`.cargo-ok`, `.cargo_vcs_info.json`,
  crate-local `Cargo.lock`, and `Cargo.toml.orig`) to match the existing
  Ferrum vendor layout.
- Applied the substantive upstream changes and tests.
- Added a short `Ferrum local patch` changelog section to each vendored crate
  because the packaged release source does not carry the upstream PR's
  `UNRELEASED` heading.
- Made the frame decoder's pre-reservation policy check opcode-aware. Text,
  Binary, continuation, Ping, and Pong payloads honor the caller ceiling; valid
  Close frames bypass it, while the protocol's 125-byte control-frame maximum
  remains an independent pre-allocation bound.
- Added `CapacityError::FrameTooLong` at that pre-reservation boundary. This is
  a deliberate Ferrum extension, owned by `@jeremyjpj0916`, and must be filed
  upstream or explicitly re-affirmed before the first stable release under the
  dependency-policy SLA. It preserves frame-vs-reassembly attribution without
  weakening either parser ceiling.
- Ordered the stray-continuation opcode/state check ahead of the frame-size
  policy: a Continue frame received with no fragmented message in progress is
  reported as `ProtocolError::UnexpectedContinueFrame` before the declared
  63-bit length is compared to the ceiling. A genuinely oversized frame whose
  63-bit length is above `u32::MAX` but has its high bit clear therefore stays
  a `FrameTooLong` size-policy failure (Close 1009) rather than being misread
  as protocol junk. This is a deliberate Ferrum extension owned by
  `@jeremyjpj0916` under the dependency-policy SLA.
- Added `WebSocketConfig::auto_pong` (default `true`) so the shared H1/H2/H3
  WebSocket relay can disable local auto-Pong while forwarding Ping frames
  (issue #2963). Documented under
  [003-optional-auto-pong](003-optional-auto-pong/). This is a deliberate
  Ferrum extension owned by `@jeremyjpj0916` under the same SLA.
- Added physical-fragment accounting for message reassembly: `FragmentMeter`,
  `set_fragment_accounting()` on `WebSocketContext` / `WebSocket` /
  `WebSocketStream`, `WebSocketConfig::max_incomplete_message_frames`,
  `WebSocketConfig::max_incomplete_message_duration` (both default `None`), and
  the `IncompleteMessageFrameLimitExceeded` / `IncompleteMessageTimeout`
  protocol errors. The reader only ever yields reassembled messages, so
  fragmented — including zero-length continuation — frames were invisible to
  per-message admission policy and unbounded in count and duration. Documented
  under [004-fragment-accounting](004-fragment-accounting/). This is a
  deliberate Ferrum extension owned by `@jeremyjpj0916` under the same SLA.
- Wired both crates through root `[patch.crates-io]`.

## Direct vendor-test commands

```bash
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib into_inner_with_read_buffer
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib size_limit_hit
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib auto_pong
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib fragment
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib incomplete_message
cargo test --manifest-path vendor/tokio-tungstenite-0.29.0-ferrum-patched/Cargo.toml --config 'patch.crates-io.tungstenite.path="vendor/tungstenite-0.29.0-ferrum-patched"' --test into_inner_with_read_buffer
```

The explicit `--config` on the tokio-tungstenite command makes its standalone
manifest use the adjacent patched tungstenite copy.

## Ferrum gateway use

The tunnel-mode fast path calls
`WebSocketStream::into_inner_with_read_buffer()` immediately after the backend
handshake and before any WebSocket-frame operation. That point is a
frame-codec boundary, which satisfies the upstream accessor's documented
precondition. Ferrum writes the recovered backend bytes to the client before
starting the existing raw relay so later backend bytes cannot overtake them.
The parsed relay maps `FrameTooLong` only to the effective frame rule and
`MessageTooLong` only to the effective reassembled-message rule.

`run_websocket_proxy` installs one `FragmentMeter` per direction (client and
backend framer) plus the incomplete-message frame/duration bounds from
`FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_FRAMES` /
`FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_SECONDS`, before the first read and
before `split()`. After each successful read it drains its own direction's
meter and charges the batch through `Plugin::on_ws_reassembly_frames`; the
completing message is charged once by the ordinary `on_ws_frame` chain, so no
wire frame is counted twice. `IncompleteMessageFrameLimitExceeded` /
`IncompleteMessageTimeout` become an RFC 6455 Close 1008 with a fixed,
non-secret reason.

## Retirement condition

Do not retire these vendor directories merely because the PRs merge. Retire
only after **both** upstream takeover changes are present in published
compatible releases consumed by ferrum-edge and the consumed tungstenite
surface preserves an equivalent frame-vs-message capacity origin, an
equivalent opt-out for automatic Ping replies (`auto_pong` or successor),
**and** an equivalent pre-reassembly fragment hook with independent
incomplete-message count/duration bounds. The stray-continuation extension may
retire only when the consumed parser rejects invalid continuation state before
applying caller frame-size policy, or when Ferrum no longer needs distinct
protocol-vs-capacity attribution. If an extension has not shipped upstream, carry forward only that documented
minimal extension until its own retirement condition is met.

At retirement:

1. Bump `tokio-tungstenite` / `tungstenite` dependency versions and update
   `Cargo.lock` through Cargo.
2. Remove these root `[patch.crates-io]` entries and their mirrors in
   `tests/performance/mesh/Cargo.toml`:
   - `tungstenite = { path = "vendor/tungstenite-0.29.0-ferrum-patched" }`
   - `tokio-tungstenite = { path = "vendor/tokio-tungstenite-0.29.0-ferrum-patched" }`
3. Delete both vendor directories, regenerate the drift manifest
   (`scripts/update_vendor_integrity.sh`), and remove the matching inventory
   rows and `docs/vendored-patch-lifecycle.json` entries.
4. Keep the gateway call-site logic using
   `WebSocketStream::into_inner_with_read_buffer()` and
   `WebSocketStream::set_fragment_accounting()`.
5. Re-run the WebSocket tunnel regression and the broad Rust checks for the
   dependency bump.
