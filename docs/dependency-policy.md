# Dependency & Vendored-Crate Governance

This document is the single policy for how Ferrum Edge manages third-party
dependencies and, in particular, the **vendored, patched copies** of upstream
crates it carries in `vendor/**`. It is the human half of the governance; the
machine half is `deny.toml`, [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json),
the scheduled `.github/workflows/dependency-audit.yml` workflow,
`scripts/check_vendored_patch_lifecycle.py`, and the drift guard in
`tests/integration/vendor_integrity_tests.rs`.

> TL;DR — vendored patches must be **auditable** (pinned + drift-tested),
> **tracked** (an upstream PR — or a governed [deliberate-fork record](#deliberate-fork-policy-and-sla)
> — plus a retirement trigger, recorded and polled weekly), and
> **covered** (behavioral regression tests). Security advisories in the
> dependency tree are gated on every PR and re-checked weekly, so a fix landing
> in the reqwest/h3 lineage cannot be missed silently.

## Why we vendor

The HTTP/3, QUIC, and WebSocket stacks are young enough that we occasionally hit
upstream bugs (or need a not-yet-merged API) faster than upstream releases.
Vendoring a patched crate via `[patch.crates-io]` is an accepted, **last-resort**
tool when:

- the fix/feature is required for correctness or a documented Ferrum capability,
  and
- the change has been (or will be) proposed upstream, and
- a written retirement plan exists so the vendor copy does not become orphaned.

Vendoring without a retirement plan is not allowed. Prefer a dependency bump, a
feature flag, or a gateway-side workaround first.

## Direct pins of otherwise-transitive crates

Some crates are already pulled in transitively but are also listed directly in
`Cargo.toml` when Ferrum calls their API itself (not only through a parent
crate). Keep the version aligned with the transitive copy already in
`Cargo.lock` unless an intentional bump is part of the change.

| Crate | Why pinned directly |
|---|---|
| `crossbeam-utils` | `CachePadded` on hot overload atomics |
| `crossbeam-queue` | lock-free MPMC ring for router-cache eviction samples |
| `crc32fast` | AWS Bedrock event-stream prelude/message CRC32 validation before lengths or usage payloads are trusted |
| `unsafe-libyaml` | API-spec YAML event composition + bounded alias expansion (#3307); already transitive via `serde_yaml` |

## Vendored crate inventory

Each row is the authoritative human summary. The **Lifecycle ID** column is the
stable identity shared with
[`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json); CI
requires the exact set of IDs (duplicates fail closed). Keep this table, the
machine inventory, the `[patch.crates-io]` block in `Cargo.toml`, the per-patch
docs, and `scripts/check_vendored_patch_lifecycle.py` in sync. CI fails when any
surface drifts.

| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |
|---|---|---|---|---|---|---|---|---|
| `reqwest-001-per-request-connect-timeout` | `reqwest` | 0.13.3 | Per-request `RequestBuilder::connect_timeout` | [seanmonstar/reqwest#3017](https://github.com/seanmonstar/reqwest/pull/3017) (OPEN) | Ferrum Edge maintainers | Pool keys exclude request-only connect/read timeouts, so sibling proxies can share one client; without per-request connect timeout the first proxy's timeout leaks to all | PR #3017 merges and ships in a release we consume | [docs/upstream-reqwest-patches/001-…](upstream-reqwest-patches/001-per-request-connect-timeout/README.md) |
| `reqwest-002-selectable-rustls-provider` | `reqwest` | 0.13.3 | Selectable Ring/AWS-LC rustls fallback | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | Library/test reqwest clients run before binary bootstrap; upstream's only built-in fallback hard-wires AWS-LC and cannot preserve Ferrum's mutually exclusive backend pair | Reqwest ships a provider-neutral selectable fallback, or the vendored crate is retired | [docs/upstream-reqwest-patches/002-…](upstream-reqwest-patches/002-selectable-rustls-provider/README.md) |
| `reqwest-003-connection-admission-hook` | `reqwest` | 0.13.3 | `ClientBuilder::connection_admission` physical-connection admission hook | **Deliberate fork** — unfiled upstream | Ferrum Edge maintainers | DestinationRule `connectionPool.tcp.maxConnections` is a physical-connection ceiling; reqwest owns its socket pool and exposes no connection-lifetime hook, so no public API can admit a new socket and release on its close | Reqwest exposes a connection-lifecycle/admission hook (or a non-sealed connector connection type a `connector_layer` can wrap), or the vendored crate is retired | [docs/upstream-reqwest-patches/003-…](upstream-reqwest-patches/003-connection-admission-hook/README.md) |
| `h3-001-recv-frame-drain-on-quic-close` | `h3` | 0.0.8 | Drain buffered frames before propagating QUIC `CONNECTION_CLOSE` | issue [hyperium/h3#338](https://github.com/hyperium/h3/issues/338), PR [hyperium/h3#339](https://github.com/hyperium/h3/pull/339) | Ferrum Edge maintainers | io_uring batching of `STREAM(FIN)` + `CONNECTION_CLOSE(H3_NO_ERROR)` dropped a buffered HEADERS frame → false 502 on graceful close | Fix ships in an `h3` release **and** patches 002/003/004 are also retired | [docs/upstream-h3-patches/001-…](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md) |
| `h3-002-extended-connect-websocket-protocol` | `h3` | 0.0.8 | Add `Protocol::WEB_SOCKET` (RFC 9220 Extended CONNECT) | **Deliberate fork** — unfiled upstream; branch `feat/extended-connect-websocket-protocol` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock `h3` 0.0.8 rejects `:protocol=websocket` at the HEADERS layer, making WebSocket-over-HTTP/3 unreachable | Upstream files + merges the variant **and** patches 001/003/004 are also retired | [docs/upstream-h3-patches/002-…](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md) |
| `h3-003-peek-buffered-trailers-before-fin` | `h3` | 0.0.8 | Add `RequestStream::peek_recv_trailers()` for already-buffered trailers before FIN | **Deliberate fork** — unfiled upstream; branch `feat/peek-buffered-trailers-before-fin` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `poll_recv_trailers` buffers trailer HEADERS but waits for terminal FIN; gateway trailer-timeout collapse dropped trailers delivered before delayed FIN | Upstream files + merges the API **and** patches 001/002/004 are also retired | [docs/upstream-h3-patches/003-…](upstream-h3-patches/003-peek-buffered-trailers-before-fin/README.md) |
| `h3-004-send-stream-stopped-watch` | `h3` | 0.0.8 | Add `SendStreamStopped` so peer `STOP_SENDING` is observable as a `&self` + `'static` return-position `impl Future` without exclusive send-stream access | **Deliberate fork** — unfiled upstream; branch `feat/send-stream-stopped-watch` on `jeremyjpj0916/h3` ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | After request HEADERS the gateway may block on backend headers without polling H3 frames; a client can cancel one multiplexed stream and leave destination `http2MaxRequests` held until the backend answers | Upstream files + merges the API **and** patches 001/002/003 are also retired | [docs/upstream-h3-patches/004-…](upstream-h3-patches/004-send-stream-stopped-watch/README.md) |
| `h3-quinn-001-stop-sending-during-in-flight-read` | `h3-quinn` | 0.0.10 | Own `quinn::RecvStream` inline so `stop_sending` works while a read is in flight | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | `RecvStream` parks its `quinn::RecvStream` in a `ReusableBoxFuture` while a read is pending, so `stop_sending` unwraps a `None` and aborts exactly when a full-duplex H3 server must send `STOP_SENDING(H3_NO_ERROR)` after its response completes | `h3-quinn` ships a release whose `stop_sending` is correct while a read is in flight **and** patch 002 is also retired | [docs/upstream-h3-quinn-patches/001-…](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/README.md) |
| `h3-quinn-002-send-stream-stopped-watch` | `h3-quinn` | 0.0.10 | Implement `h3::quic::SendStreamStopped` via Quinn `&self` + `'static` `stopped()` as a return-position `impl Future` | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | Ferrum Edge maintainers | Stock h3-quinn does not forward Quinn's `SendStream::stopped`, so a header wait cannot observe per-stream `STOP_SENDING` without exclusive send-stream access | `h3-quinn` ships a release with an equivalent watch **and** patch 001 is also retired | [docs/upstream-h3-quinn-patches/002-…](upstream-h3-quinn-patches/002-send-stream-stopped-watch/README.md) |
| `tungstenite-001-lossless-takeover` | `tungstenite` | 0.29.0 | `WebSocket::into_inner_with_read_buffer()` (lossless raw takeover) | [snapview/tungstenite-rs#556](https://github.com/snapview/tungstenite-rs/pull/556) | Ferrum Edge maintainers | Tunnel mode lost backend bytes coalesced with the `101` response when dropping to raw relay | **Both** this and tokio-tungstenite#380 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-002-frame-limit-origin` | `tungstenite` | 0.29.0 | Distinct `FrameTooLong` origin for pre-reservation frame policy | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Equal frame/message ceilings otherwise lose which parser boundary rejected input and can emit the wrong configured close reason | Upstream ships equivalent frame-vs-message capacity attribution, or the gateway no longer needs distinct policy reasons | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-003-optional-auto-pong` | `tungstenite` | 0.29.0 | `WebSocketConfig::auto_pong` opt-out for transparent Ping relay | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Stock framer auto-answers Ping while the gateway also forwards it, so one Ping yields two Pongs and a hung backend still looks healthy | Upstream ships equivalent default-true auto-Pong opt-out, or the gateway no longer needs transparent Ping/Pong | [docs/upstream-tungstenite-patches/003-…](upstream-tungstenite-patches/003-optional-auto-pong/README.md) |
| `tokio-tungstenite-001-lossless-takeover` | `tokio-tungstenite` | 0.29.0 | `WebSocketStream::into_inner_with_read_buffer()` | [snapview/tokio-tungstenite#380](https://github.com/snapview/tokio-tungstenite/pull/380) | Ferrum Edge maintainers | Same lossless-takeover gap on the async wrapper | **Both** this and tungstenite#556 ship in compatible releases | [docs/upstream-tungstenite-patches/README.md](upstream-tungstenite-patches/README.md) |
| `tungstenite-004-fragment-accounting` | `tungstenite` | 0.29.0 | `FragmentMeter` + `max_incomplete_message_frames` / `max_incomplete_message_duration` (physical-fragment accounting and bounds) | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | The reader only sees reassembled messages, so fragmented (including zero-length continuation) frames bypass per-message admission policy and are unbounded in count and duration | Upstream ships an equivalent pre-reassembly fragment hook **and** independent incomplete-message count/duration bounds | [docs/upstream-tungstenite-patches/004-…](upstream-tungstenite-patches/004-fragment-accounting/README.md) |
| `tokio-tungstenite-004-fragment-accounting-delegator` | `tokio-tungstenite` | 0.29.0 | `WebSocketStream::set_fragment_accounting()` | **Deliberate fork** — unfiled upstream ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Same accounting gap on the async wrapper, which hides the codec behind `SplitStream` after `split()` | Upstream ships the equivalent delegator alongside the tungstenite hook | [docs/upstream-tungstenite-patches/004-…](upstream-tungstenite-patches/004-fragment-accounting/README.md) |
| `dimpl-001-certificate-chain-and-key-zeroization` | `dimpl` | 0.6.1 | Full leaf-first certificate-chain transport and zeroizing private-key ownership | **Deliberate fork** — unfiled upstream; base commit `37bb0fa83f4167420729de5ea71c61852f82e9ed` ([policy](#deliberate-fork-policy-and-sla)) | `@jeremyjpj0916` | Published releases expose only one local certificate and retain endpoint/fallback credential bytes in ordinary `Vec<u8>` owners | Upstream ships compatible full-chain DTLS 1.2/1.3 transport, peer-chain output, and drop-time key zeroization on all ownership paths | [docs/upstream-dimpl-patches/001-…](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/README.md) |

> Ownership note: `vendor/`, `deny.toml`, this doc, `docs/vendored-patch-lifecycle.json`,
> `docs/upstream-*-patches/`, and the vendored-patch scripts are owned via
> [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`). Upstream `h3`
> work is staged from the `jeremyjpj0916/h3` fork referenced in the h3 patch
> docs. Patches carried without an upstream PR, including the tungstenite frame
> error-origin extension, the tungstenite `auto_pong` opt-out, the tungstenite /
> tokio-tungstenite fragment-accounting extension, and the dimpl
> credential-security patch, are governed by the
> [Deliberate fork policy and SLA](#deliberate-fork-policy-and-sla) below.

### Deliberate fork policy and SLA

Most vendored patches ride an **open upstream PR** (reqwest #3017, h3 #339,
tungstenite #556 / tokio-tungstenite #380); the weekly
`scripts/check_vendored_patch_status.sh` (backed by
`docs/vendored-patch-lifecycle.json`) polls those and goes red when one
merges. Fork-only patches currently include **h3 002** (Extended CONNECT
`:protocol=websocket`), **h3 003** (`peek_recv_trailers`), the tungstenite
frame-limit origin extension, **tungstenite `auto_pong`** (transparent Ping
relay), **tungstenite / tokio-tungstenite 004** (fragment accounting and
incomplete-message bounds), and **dimpl 001** (DTLS certificate chains and private-key
zeroization). They are not untracked TODOs; they are carried as
**deliberate, time-boxed forks** and are governed as follows:

- **Owner.** The dependency-governance owner in
  [`.github/CODEOWNERS`](../.github/CODEOWNERS) (`@jeremyjpj0916`) — the same
  owner for `vendor/`, `deny.toml`, this doc, `docs/upstream-*-patches/`, and
  the vendored-patch scripts.
- **Review cadence (SLA).** Every weekly `dependency-audit` run lists each
  fork-only patch as `NOT YET FILED`. At each run the owner either (a) files the
  upstream issue/PR and records the numbers in the inventory table, the per-patch
  `README.md` Status block, **and**
  [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json), or (b) leaves it as a conscious
  re-affirmation that the fork is still the right call.
- **Hard checkpoint — no unfiled fork ships in a stable release.** A fork-only
  patch (no upstream PR link) may **not** survive the first tagged stable release
  (the schema-freeze milestone in
  [migrations.md → Stability & Upgrade Contract](migrations.md#when-v002-migrations-start-the-schema-freeze))
  without either a filed upstream issue/PR link recorded in the inventory table,
  or an explicit dated re-affirmation
  (`Deliberate fork — re-affirmed YYYY-MM-DD by <owner>: <reason>`) in the
  patch's `README.md`, mirrored into the `reaffirmation` object of the matching
  `docs/vendored-patch-lifecycle.json` entry. A reaffirmation is a
  deliberate-fork record only: CI rejects one on a patch whose `upstream.filing`
  is `filed`, so reaffirming a fork that shares a `README.md` with filed patches
  (as `tungstenite-002-frame-limit-origin` does) does not drag them in. This
  keeps "not yet filed" from silently becoming permanent in a released product.
- **Retirement is unchanged.** Whether upstreamed via PR or carried as a fork,
  each patch retires per its `README.md` retirement plan and the co-vendoring
  rule (all four h3 patches retire together — see the inventory `Removal
  trigger` column).

## Enforcement controls

### 1. Blocking advisory gate (`deny.toml` + CI)

`cargo deny check advisories bans sources` runs on **every PR**
(`dependency-audit` job in `.github/workflows/ci.yml`) and is **blocking**: any
RUSTSEC advisory in the resolved tree that is not explicitly time-boxed in
`deny.toml` fails CI. `unmaintained`/`unsound` are set to `all` (not the 0.19
default of `workspace`) so transitive advisories are blocking too, and
`unused-ignored-advisory = "deny"` forces a stale exception to be deleted once
its advisory is fixed/removed. `bans` (duplicate-version visibility) and
`sources` (crates.io-only) run alongside. License checking is intentionally
**not** in the gate yet — see the `deny.toml` header.

Run locally:

```bash
cargo install --locked cargo-deny
cargo deny check advisories bans sources   # the gate
```

### 2. Advisory exceptions are time-boxed

Every `[advisories.ignore]` entry in `deny.toml` carries a rationale and an
`[expires:YYYY-MM-DD]` token **inside its table `reason` string**.
`scripts/check_advisory_expiry.sh` (run by the per-PR gate **and** the weekly
workflow) fails once any date passes — or if an entry uses the string form or a
comment-only token, both of which would dodge the time-box — so an exception
cannot silently become permanent. A maintainer must re-fix the advisory or
consciously extend the window.

Current exceptions are all transitive and either no-fix-available or semver-pinned
by a transitive parent (e.g. `mongodb` pins `hickory ^0.25`; the old AWS SDK
chain pins `rustls-webpki ^0.101.7`, only present under the optional `secrets-aws`
feature). Each entry documents the confinement and the upstream we are waiting on.

### 3. Vendor drift guard

`tests/integration/vendor_integrity_tests.rs` hashes every governed file under
`vendor/` and compares it to `vendor/VENDOR_INTEGRITY.sha256`. Known text paths
(allowlisted source/docs/config extensions and basenames) use LF-normalized
SHA-256 (`\r` stripped) so CRLF checkouts stay stable; binary artifacts and any
unrecognized path are hashed byte-for-byte so CR bytes in `.der` / `.bin` (and
similar) cannot change unnoticed. Incidental crate-local `Cargo.lock` files
created by documented standalone vendor tests are ignored by default; intentionally
committed lockfiles that pin a standalone regression graph (currently
`vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock`) are allowlisted in
`GOVERNED_VENDOR_LOCKFILES` and must appear in the manifest. The guard runs in
the normal integration suite (the `protocols-data-plane` shard), so a PR that
changes any governed vendored byte without regenerating the manifest **fails CI**.
This keeps the vendored diff reviewable: an unexpected edit to upstream code
cannot slip in unnoticed.

Regenerate only as part of an intentional, documented patch change:

```bash
scripts/update_vendor_integrity.sh
# i.e. UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity
```

### 4. Scheduled `dependency-audit` workflow

`.github/workflows/dependency-audit.yml` runs weekly (Mon 05:30 UTC) and on
demand:

- **advisories** — re-runs the `cargo deny` gate against the freshly-fetched
  advisory DB (catches new advisories with no PR), runs the expiry check, and
  runs `cargo audit` as an independent second opinion.
- **upstream-patch-status** — two steps. *Vendored-patch lifecycle parity* runs
  `scripts/check_vendored_patch_lifecycle.py`, which self-tests its validators
  and then verifies that every patch in `docs/vendored-patch-lifecycle.json`
  matches `Cargo.toml`, `vendor/`, the inventory Lifecycle ID set and upstream
  PR/issue numbers here, the upstream-status wrapper delegation, and per-patch
  READMEs. *Check upstream status* then runs
  `scripts/check_vendored_patch_status.sh`, which delegates to the same checker's
  `--upstream-status` mode and queries each tracked upstream PR. The run goes
  **red when an upstream PR has merged** (a retirement signal — run the
  compatible-release test before deleting vendor copies) and reports each crate's
  latest crates.io release plus deliberate-fork reaffirmation gaps.

The per-PR `dependency-audit` job in `ci.yml` runs the same parity gate. Because
that job is required to stay behind `mode == 'full'`,
`.github/scripts/pr_ci_plan.py` keeps `docs/dependency-policy.md`,
`docs/vendored-patch-lifecycle.json`, and `docs/upstream-*-patches/` on full CI —
a governance-doc-only pull request cannot skip the gate that guards it.

### 5. Behavioral regression tests for the patched behaviors

The patches fix runtime behavior; these tests guard that behavior independently
of the vendor copy and must keep passing after retirement:

- Per-request connect timeout across shared pool keys —
  `tests/integration/connection_pool_tests.rs`
  (`test_connect_timeout_does_not_fragment_pool`,
  `test_pooled_client_exposes_per_request_connect_timeout`).
- HTTP/3 graceful close with a buffered response is not a false 502 —
  `tests/integration/http3_integration_tests.rs`
  (`h3_buffered_response_survives_graceful_close_race`,
  `h3_goaway_after_complete_body_is_treated_as_graceful`,
  `h3_stream_reset_after_partial_body_is_not_treated_as_graceful`), plus
  `tests/functional/scripted_backend_h3_tests.rs`.
- HTTP/3 per-stream `STOP_SENDING` releases destination `http2MaxRequests`
  while the multiplexed QUIC connection stays open —
  `tests/unit/gateway_core/http3_server_dispatch_tests.rs`
  (`h3_plain_header_wait_races_per_stream_stop_sending_not_only_connection_close`,
  `h3_quinn_vendored_send_stream_stopped_is_shared_and_static`) and
  `tests/functional/functional_destination_active_requests_h3_test.rs`
  (same-connection cancellation, including streaming upload).
- The h3 frame-drain unit tests live in the vendored crate
  (`vendor/h3-0.0.8-ferrum-patched/src/frame.rs::tests`) and on upstream PR #339;
  run them with
  `cargo test --manifest-path vendor/h3-0.0.8-ferrum-patched/Cargo.toml --lib frame`.
- The tungstenite pre-reservation frame-origin regression lives in the vendored
  crate (`protocol::frame::tests::size_limit_hit`) and runs alongside the
  raw-takeover regression in the vendored-patch job.
- The tungstenite `auto_pong` opt-out regressions live in the vendored crate
  (`protocol::tests::auto_pong_*`) and in
  `tests/unit/gateway_core/websocket_auto_pong_tests.rs`, with end-to-end
  coverage in `tests/functional/functional_websocket_test.rs`
  (`test_*websocket_ping_*`).
- The tungstenite / tokio-tungstenite fragment-accounting regressions live in
  the vendored crate (`protocol::tests::fragment_*`,
  `protocol::tests::incomplete_message_*`) and in
  `tests/unit/gateway_core/websocket_fragment_metering_tests.rs`.
- The dimpl credential regressions live in
  `vendor/dimpl-0.6.1-ferrum-patched/tests/auto/credential_security.rs`. They
  cover DTLS 1.2 and 1.3 chain transmission plus deterministic clone,
  failed-construction, fallback, and shutdown zeroization observations. The
  Ferrum integration suite separately verifies a root-only client completes a
  handshake because the configured intermediate is transmitted.

CI gates these vendored-patch contracts in the `Vendored Patch Regressions`
job in `.github/workflows/ci.yml`. Keep that job in sync with this list when
adding, retiring, or changing a vendored patch.

## Procedures

### Adding a vendored patch

1. Confirm a dependency bump / feature flag / gateway workaround can't do it.
2. Copy the locked crates.io source into `vendor/<crate>-<ver>-ferrum-patched/`,
   apply the minimal upstream-proposed diff, and keep the diff reviewable (no
   private Ferrum-only API beyond the proposed surface).
3. Wire it through `[patch.crates-io]` in `Cargo.toml` with a comment block.
4. Add `docs/upstream-<crate>-patches/NNN-…/` with `README.md` (status, upstream
   links, retirement plan), the unified `.patch`, and issue/PR drafts.
5. Add a behavioral regression test for the fixed behavior and wire it into the
   `Vendored Patch Regressions` CI job when it lives outside the normal root
   test matrix.
6. Add a row to the inventory table above (with a unique Lifecycle ID) and a
   matching entry to
   [`docs/vendored-patch-lifecycle.json`](vendored-patch-lifecycle.json).
7. Regenerate the drift manifest: `scripts/update_vendor_integrity.sh`.
8. File the upstream issue/PR and record the numbers.

### Refreshing a vendored patch (upstream review changes)

1. Re-fetch the upstream diff, re-apply over the pinned base version, copy the
   sources back into the vendor directory.
2. Update the per-patch `.patch` and README notes.
3. **Regenerate the drift manifest** (`scripts/update_vendor_integrity.sh`) and
   review the diff — the manifest change is the audit trail.
4. Run the behavioral regression tests.

### Retiring a vendored patch

Trigger: the upstream PR merges **and** ships in a release we consume (for `h3`
and tungstenite, *both* co-vendored patches must be ready — see the table).

1. Bump the registry version in `Cargo.toml` `[dependencies]` to the release
   containing the fix; update `Cargo.lock`.
2. Remove the crate's line from the `[patch.crates-io]` block.
3. `git rm -r vendor/<crate>-<ver>-ferrum-patched/` (and `vendor/` if empty).
4. Move `docs/upstream-<crate>-patches/NNN-…/` to `…/_retired/NNN-…/` with a
   `STATUS.md` (merge commit + registry version), or delete per that crate's
   README.
5. Remove the inventory row (Lifecycle ID) and the matching `docs/vendored-patch-lifecycle.json`
   entry.
6. Regenerate the drift manifest (now smaller) and keep the gateway call sites —
   they use the upstream API by design.
7. Run the behavioral regression tests; they must still pass.

### Emergency security update for a vendored crate

A vendored crate masks its upstream from a normal `cargo update`, so a CVE in the
reqwest/h3/tungstenite lineage needs an explicit path:

1. **Triage** which version fixes it and whether our patch applies cleanly to
   the fixed source.
2. **If a fixed release exists and we can retire:** follow "Retiring a vendored
   patch" immediately (bump + drop the vendor copy).
3. **If we must keep the patch:** re-vendor on top of the *fixed* upstream
   version — copy the patched-fixed source into a new
   `vendor/<crate>-<fixedver>-ferrum-patched/`, re-apply our minimal diff,
   update `[patch.crates-io]`, the per-patch docs, the inventory row, and
   **regenerate the drift manifest**.
4. **If neither is possible yet (no fix upstream):** add a time-boxed
   `[advisories.ignore]` in `deny.toml` with a rationale documenting the
   confinement and a near-term `[expires:]` date, and open a tracking issue.
5. Land the change on an expedited review per `SECURITY.md` severity timelines.
6. Never silence an advisory without an expiry and a rationale — the expiry
   check will fail the weekly run otherwise (by design).

## CI Actions and Kubernetes tooling

GitHub Actions and the kind / kubectl / Helm binaries used by live Kubernetes
jobs are a separate supply-chain surface from Rust crates. Policy:

1. **Pin every external action** to a full 40-character commit SHA, with an
   accurate version comment (for example
   `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`).
   Mutable tags (`@v7`, `@v7.0.1`), branches (`@main`), and short SHAs are
   forbidden. `docker://` action references require an explicit
   `@sha256:<64-hex>` image digest. Local composite actions under
   `./.github/actions/...` and reusable workflows directly under
   `./.github/workflows/` are allowed without a SHA pin; local Docker actions
   must also digest-pin every non-`scratch` `FROM` image.
2. **Install kind, kubectl, and Helm only through**
   [`.github/actions/setup-kubernetes-tools`](../.github/actions/setup-kubernetes-tools/action.yml).
   That composite action downloads from official versioned release URLs, verifies
   each artifact against repository-pinned SHA-256 digests **and** the matching
   official published checksum file for that exact version, then installs into
   the runner PATH. It never pipes remote content to a shell and fails closed on
   download or verification errors.
3. **Do not** use `azure/setup-helm`, `curl … | bash` installers, or
   `raw.githubusercontent.com/helm/helm/main` (or any other mutable-branch
   install script).
4. **Static enforcement.** The `ci-plan` job runs the trusted base branch's
   `.github/scripts/pr_ci_plan.py --self-test` on every CI run (including
   lightweight documentation PRs). Its checker rejects mutable action refs,
   pipe-to-shell installers, mutable-branch install scripts, and direct
   kind/kubectl/Helm downloads outside the composite action. Repository-local
   actions are allowed, but dynamic or matrix-generated `uses` references are
   rejected because the checker cannot prove that every generated value is a
   full immutable SHA. The head-executed required-CI verifier also runs a pull
   request's proposed planner self-tests without consuming planner outputs, so
   new policy code is exercised before merge while the base branch remains the
   sole authority for job gates.

   This is deliberately static enforcement, not a shell interpreter. It catches
   known direct URLs and folded/continued installer commands, but cannot prove
   the destination of a URL assembled indirectly from shell variables or other
   obfuscation. Reviewers must treat such construction as unverified and require
   a literal, versioned URL plus repository-pinned checksum (or the centralized
   installer) before approving it.

### Refreshing GitHub Actions (Dependabot)

`.github/dependabot.yml` already schedules weekly `github-actions` updates.
When reviewing an actions Dependabot PR:

1. Confirm the PR pins a full commit SHA (Dependabot for GitHub Actions should
   produce SHA pins when the repo already uses them).
2. Keep the trailing version comment accurate for the tag the SHA corresponds
   to.
3. Do not accept a PR that reintroduces a mutable tag ref.

The ARM64 Cross build and publication contracts are deliberately frozen by the
trusted `pull_request_target` verifier. Existing checkout uses on the guarded
workflow surfaces still carry the historical `# v6` annotation, although their
pinned `3d3c42e5...` SHA resolves to v7.0.1. The verifier treats an adjacent
annotation change as a change to that executable surface, so an ordinary pull
request cannot normalize those comments. Correct them only as part of an
authorized, coordinated rotation of the trusted policy; do not copy the legacy
annotation onto new uses.

#### Scope of the repository-script (automation) freeze

The same verifier also freezes repository scripts, and it does so bluntly: once
a file is judged Cross-sensitive, its surface is a single
`file:<sha256-of-the-whole-file>`, so **no pull request may change a single byte
of it** — not a comment, not whitespace, not a retry loop.

Sensitivity is inferred from text, so it false-positives. A Gateway API lab
harness that never invokes `cross` or `cargo` earned it purely by containing
fixture strings (`/cross` as an HTTPRoute path prefix, `blackbox-cross` as a
backend name), which permanently blocked a CI flake fix in that file.

The freeze is therefore scoped to automation **reachable from the trusted ARM64
cross-build jobs** (`build-arm64-cross`, `build-release-arm64-cross`), which is
the property the policy actually protects: a pull request must not alter
anything that executes with elevated trust inside that build. Reachability is
seeded from those job blocks plus every local composite action — actions are
included wholesale because a protected job may `uses:` any of them, and seeding
a partial set would under-approximate and silently release a file that really
does run in the trusted build.

The narrowing fails closed. If either revision's protected job cannot be located
or parsed, or the reachability walk reports an error, the scope is treated as
unknown and **every** automation file is compared exactly as before. A file
reachable on *either* revision stays in scope, so a pull request cannot drop the
reachability edge and edit the file in the same commit. Newly reaching an
already-Cross-sensitive script from a protected job is still rejected.

#### Retired `fips-build.yml` generation transition (issue #3888 / PR #3889)

PR #3889 landed on `main`. The temporary whole-file SHA-256 admission that let
that rewrite pass the Cross surface scan is **retired and non-operational**.
Ordinary `.github/workflows/fips-build.yml` edits are compared by the normal
fail-closed Cross surface scan with no special case. The generic SHA-256
generation digest helper remains because CI-job and local-action finite
transitions still use it. Full description: `docs/ci_cd.md` → "Retired
`fips-build.yml` generation transition".

The same verifier still carries temporary SHA-256 generation pairs for
Cross-sensitive `ci.yml` jobs and for `setup-rust-ci/action.yml`
(`CI_JOB_GENERATION_TRANSITIONS`, `LOCAL_ACTION_GENERATION_TRANSITIONS`). Both
ends are exact, path- or job-bound, one-way, and decided entirely by the trusted
base. `setup-rust-ci` now has exactly one pair: current-main
`fc4e41818dffdea880c057c8dfa0881a629cd01c917b43f69a9f2e5e9bd90dda` moving to the
combined #3911 destination
`57a99a179ddc2935af187f518a803bf167eb9e33593c37b7b29f7151ec994da2`. See
`docs/ci_cd.md` → "Admitted CI job SHA-256 generation transitions" and
"Admitted `setup-rust-ci` generation transition".

### Refreshing kind / kubectl / Helm versions and checksums

Versions and digests live as defaults on the
`setup-kubernetes-tools` composite action inputs. To bump a tool:

1. Choose the new official release tag (kind GitHub release, Kubernetes
   `dl.k8s.io` release, or Helm release on `get.helm.sh`).
2. Fetch the **official** published checksum for that exact version and
   architecture (`linux/amd64`):
   - kind:
     `https://github.com/kubernetes-sigs/kind/releases/download/<tag>/kind-linux-amd64.sha256sum`
   - kubectl:
     `https://dl.k8s.io/release/<tag>/bin/linux/amd64/kubectl.sha256`
   - Helm:
     `https://get.helm.sh/helm-<tag>-linux-amd64.tar.gz.sha256sum`
     (optionally cross-check the detached signature assets on the Helm GitHub
     release before trusting a new digest).
3. Update the matching `*-version` and `*-sha256` defaults in
   `.github/actions/setup-kubernetes-tools/action.yml`.
4. Leave workflow jobs calling `uses: ./.github/actions/setup-kubernetes-tools`
   unchanged unless a job must pin an override input for a temporary skew.
5. Land the change via PR; the trusted CI planner policy and the live suites that
   path-filter on the composite action will exercise the new pins.

`Helm Chart` proves `.github/actions/setup-kubernetes-tools` against the trusted
revision before `uses:`, so a pull request that edits that action is rejected
unless `verify_trusted_local_action.py` already admits that exact
source→destination generation pair. Issue #3904's predecessor transition binds
the current `action.yml`
(`6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08`,
non-executable, sole governed file) moving to the PR #3910 cached-installer
generation
(`41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9`, same path
set and mode). Future installer edits need a new frozen pair, or must match the
trusted tree byte for byte. Do not treat a working-tree digest or a mutable
allowlist as admission. After #3910 is the trusted base, retire the predecessor
constants so the old generation cannot remain an admitted source.

Never refresh a checksum by copying a digest from an unpinned adjacent path
without official release provenance, and never pipe a remote install script to
a shell as a shortcut.

## FIPS build profile

Ferrum ships two mutually exclusive cryptographic-backend cargo features
(issue #3510). Exactly one must be selected; both or neither is a
`compile_error!` in `src/fips/mod.rs`.

| Feature | Backend | Lockfile |
|---|---|---|
| `crypto-ring` (default) | `ring` + `rustls/ring` | the committed `Cargo.lock` |
| `fips` | `aws-lc-fips-sys` via `aws-lc-rs/fips` and `rustls/fips` | the committed `Cargo.lock` |

Rules:

- **The backend is never selected inline on a dependency.** `rustls`,
  `tokio-rustls`, `reqwest`, `sqlx`, `ldap3`, `quinn`, `rcgen`, `x509-parser`,
  `jsonwebtoken`, `hyper-rustls`, and `instant-acme` all take their crypto arm
  from the feature pair. An inline selection would win on both profiles.
  `rustls`, `tokio-rustls`, `quinn`, and `rcgen` carry
  `default-features = false`, because their default sets select a provider;
  reqwest uses `rustls-no-provider` plus vendored `__rustls-ring` /
  `__rustls-aws-lc-rs` fallback arms for the same reason. Because Cargo unifies
  dependency features, Ring takes precedence if a transitive reqwest consumer
  also enables the upstream AWS-LC default in the ordinary profile; the hosted
  resolved-graph audit rejects Ring entirely from the FIPS profile.
- **Additive is not sufficient.** `sqlx-core`, `quinn-proto`, `tonic`, `ldap3`,
  and `hyper-rustls` each gate their aws-lc arm on the *absence* of their ring
  arm, so "also enable aws-lc" produces a build that looks switched and is not.
  This is the whole reason the features are exclusive rather than layered.
- **The declared contract is not the audited one.**
  `.github/scripts/check_fips_feature_policy.py` reads what cargo actually
  resolved (`cargo tree -e normal,build --prefix none -f '{p}|{f}'`) for
  *both* profiles and
  fails on any surviving ring selection in the FIPS graph. It runs in the
  required `FIPS Feature Policy` job of `.github/workflows/fips-build.yml`.
  The `normal,build` edge filter is load-bearing: test fixtures pin `ring` and
  `rustls/ring` as dev-dependencies so the suite can verify both profiles
  without those edges entering a shipped binary. Package-row feature output is
  used because cargo's feature-edge view can retain dev-only root feature
  unification even when the dev dependency edge itself is hidden.
- **Both profiles are pinned in the committed `Cargo.lock`.** A lockfile entry
  does not compile or link the FIPS-only package into an ordinary artifact;
  feature selection still controls the build. Both resolved-graph audits and
  the hosted FIPS build therefore use `--locked`, and a FIPS release retains
  that exact lockfile as deployment evidence — see `docs/fips.md`.
- **`aws-lc-sys` may still be compiled next to `aws-lc-fips-sys`.** `dimpl` and
  rustls's `aws_lc_rs` arm request it unconditionally. `aws-lc-rs` binds
  `aws-lc-fips-sys` whenever its `fips` feature is on, so the validated module
  is what the API reaches; the policy check asserts the `fips` selection rather
  than the absence of the non-FIPS sys crate.
- **A new TLS-consuming dependency must declare its crypto arm in the feature
  pair** and add its ring/aws-lc selections to `REQUIRED_FEATURE_PAIRS` and
  `FORBIDDEN_RESOLVED_FIPS` in the policy script. A dependency whose backend is
  unselectable belongs in `src/fips/inventory.rs` as `rejected` or
  `outside-boundary`, with a matching admission rule in `src/fips/policy.rs`.
- **A new optional cargo feature must be explicitly claimed or explicitly
  refused.** `CLAIMED_FIPS_PROFILES` (supported and audited) and
  `CLAIMED_FIPS_PROFILES_UNSUPPORTED_AT_RUNTIME` (builds, refused before use)
  in the policy script are the inventory; `check_claimed_profiles_declared()`
  fails when a declared optional feature appears in neither. An unlisted feature
  would be an implicit FIPS support claim, which is exactly what this gate
  refuses. CI enumerates the same table through `--list-claimed-profiles`, so
  the audited set and the compiled set cannot drift apart.
- **Each feature list must name a dependency's crypto arm exactly once.** A
  duplicate entry, or a `dep:x` beside an `x/<feature>` edge for the same
  optional dependency (the `dep/feature` edge already activates it), breaks the
  position-for-position correspondence the two lists are read under. The
  manifest check rejects both spellings.

`aws-lc-fips-sys` compiles the FIPS build of AWS-LC from source under a fixed
recipe (CMake + Go + Perl). That recipe is part of what the module's validation
covers, so it must not be replaced with a prebuilt artifact.

## See also

- `docs/fips.md` — the FIPS deployment mode, module boundary, and operator
  verification procedure.
- `docs/vendored-patch-lifecycle.json` — machine-readable owner/upstream/retirement
  inventory enforced by `scripts/check_vendored_patch_lifecycle.py`.
- `deny.toml` — the gate configuration and current exceptions.
- `SECURITY.md` — vulnerability reporting and severity timelines.
- `docs/upstream-reqwest-patches/`, `docs/upstream-h3-patches/`,
  `docs/upstream-tungstenite-patches/`, `docs/upstream-dimpl-patches/` —
  per-patch detail and retirement plans.
- `Cargo.toml` `[patch.crates-io]` — the active vendored patches.
