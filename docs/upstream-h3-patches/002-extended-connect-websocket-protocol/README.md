# Patch 002 — h3 Extended CONNECT `:protocol = websocket`

## Status

| Field | Value |
|---|---|
| Patch ID | 002-extended-connect-websocket-protocol |
| Target crate | `h3` |
| Target version | 0.0.8 (forward-ports cleanly to master at the time of writing) |
| State | **Applied via vendored crate at `vendor/h3-0.0.8-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled; target branch `feat/extended-connect-websocket-protocol` on `jeremyjpj0916/h3`_ |
| Tracks | Ferrum Edge RFC 9220 (WebSocket-over-HTTP/3 Extended CONNECT) support |

## Why this directory exists

`h3` 0.0.8 already implements the wire-level machinery for HTTP/3 Extended
CONNECT (RFC 9220 mirrors RFC 8441 § 4):

- The server settings frame advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`
  when `Builder::enable_extended_connect(true)` is called
  (`src/config.rs`).
- The HEADERS-frame decoder accepts the `:protocol` pseudo-header on
  `CONNECT` requests and surfaces it as a `Protocol` extension on the
  `http::Request` (`src/proto/headers.rs`, `src/server/request.rs`).
- `RequestStream::recv_data` / `send_data` allow full-duplex DATA framing
  on the CONNECT stream so an application can carry WebSocket frame
  bytes over QUIC.

The one gap: the `Protocol` type only knows two values, `"webtransport"`
and `"connect-udp"`. Its `FromStr` impl returns `InvalidProtocol` for
anything else, and `proto/headers.rs::try_value` turns that into a
`HeaderError::invalid_value`, so an incoming request with
`:protocol = "websocket"` is rejected at the HEADERS-frame layer before
the application ever sees it. That makes RFC 9220 unreachable from
application code on stock `h3` 0.0.8.

This patch adds `Protocol::WEB_SOCKET` (the third standardized value)
and parses registered protocol tokens ASCII-case-insensitively, following
the shape of the existing `WEB_TRANSPORT` / `CONNECT_UDP` constants
without API breaking changes. Once the upstream issue + PR land and a
registry release contains the variant, we retire the vendored crate per
the "Retirement" section below.

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug report for hyperium/h3. Paste into a new GitHub issue verbatim. |
| `pr-description.md` | PR description for the fix. Submit alongside the patch. |
| `h3-ext-rs.patch` | Unified diff against `h3` 0.0.8 (`h3/src/ext.rs`). Should forward-port to master with minimal effort. |

## Hand-off — how to file the upstream issue + PR

The patch is currently shipped via the vendored crate at
`vendor/h3-0.0.8-ferrum-patched/` and wired in via `[patch.crates-io]`
in the workspace `Cargo.toml`. The artifacts in this directory exist so
we can submit the same fix upstream and ultimately retire the vendor
copy. To file the upstream work:

1. **Open the issue.** GitHub → hyperium/h3 → New issue → paste `issue.md`. Capture the issue number.
2. **Update `pr-description.md`** — replace the `Fixes #NNN` placeholder with the real number.
3. **Push the fork branch.**
   ```bash
   git clone https://github.com/jeremyjpj0916/h3.git
   cd h3
   git checkout -b feat/extended-connect-websocket-protocol

   git apply <ferrum-edge>/docs/upstream-h3-patches/002-extended-connect-websocket-protocol/h3-ext-rs.patch

   cargo test -p h3

   git add -A
   git commit -F <ferrum-edge>/docs/upstream-h3-patches/002-extended-connect-websocket-protocol/pr-description.md
   git push origin feat/extended-connect-websocket-protocol
   ```
4. **Open the PR** at https://github.com/hyperium/h3/compare/master...jeremyjpj0916:feat/extended-connect-websocket-protocol — paste `pr-description.md` as the body. Link the issue.
5. **Update this README** with the issue + PR numbers under "Status" so future readers can find them.

## Retirement — when upstream merges

Once `hyperium/h3` releases a version with the variant:

1. **Update the registry floor.** Bump `h3 = "X.Y.Z"` in `Cargo.toml`
   `[dependencies]` to the version that includes the variant.
2. **Drop the vendored crate** — but ONLY if patch 001 has also been
   retired and the vendored copy contains no other Ferrum-only changes:
   - Remove the `h3 = { path = "vendor/h3-0.0.8-ferrum-patched" }` line
     from the `[patch.crates-io]` block in `Cargo.toml`.
   - `git rm -r vendor/h3-0.0.8-ferrum-patched`.
   - `cargo build` — confirm we're now pulling `h3` from crates.io.
   - Run the WS-over-H3 functional harness once it lands in-tree. The
     harness should call `Protocol::WEB_SOCKET` directly and will fail
     to compile if the registry release doesn't include the variant under
     the same name.
3. **Leave the gateway code in place** — the WebSocket-over-HTTP/3
   handler in `src/http3/websocket.rs` doesn't depend on this patch
   structurally, only on the `Protocol::WEB_SOCKET` symbol it adds.
4. **Move this directory** to
   `docs/upstream-h3-patches/_retired/002-extended-connect-websocket-protocol/`
   with a `STATUS.md` noting the merge commit and registry version.

## Changing the patch design before submission

If a reviewer wants a different API shape, two alternatives were
considered and rejected:

- **`Protocol::Other(Cow<'static, str>)`** — fully extensible, but
  expands the public enum and forces every existing match arm in
  downstream crates to add a wildcard. Larger surface area for a
  single-variant addition.
- **Make `Protocol` opaque + add `Protocol::from_str_unchecked`** —
  bypasses the registry-of-known-values model, but reframes
  `InvalidProtocol` as advisory rather than authoritative. Out of scope
  for adding one IANA-registered value.

The chosen shape — add `WEB_SOCKET` as a new const alongside the existing
`WEB_TRANSPORT` / `CONNECT_UDP` — is the smallest possible change that
unblocks RFC 9220 implementations without touching API surface for
existing callers.
