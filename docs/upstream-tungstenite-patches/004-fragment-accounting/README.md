# Patch 004 — physical-fragment accounting and incomplete-message bounds

## Status

| Field | Value |
|---|---|
| Patch ID | 004-fragment-accounting |
| Target crates | `tungstenite`, `tokio-tungstenite` |
| Target version | 0.29.0 |
| State | **Applied via vendored crates at `vendor/tungstenite-0.29.0-ferrum-patched` and `vendor/tokio-tungstenite-0.29.0-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — not yet filed_ |
| Tracks | Ferrum Edge private advisory `GHSA-qq94-2gv2-phh6` — physical WebSocket fragment bypass of `ws_rate_limiting` |

## Why this exists

This section describes the **stock, message-only codec** that motivated the
patch; the applied local controls are described separately below.

In the stock reader API (`WebSocket::read`, `WebSocketStream::poll_next`),
non-final **data** frames are hidden until a logical data message is fully
reassembled. The initial non-final Text/Binary frame and every Continuation
frame before the final one are consumed inside the codec and are invisible
to the caller. Interleaved control frames are not hidden that way: the read
APIs can still return Ping/Pong or Close while a data message remains
incomplete.

That makes a per-message admission policy that charges **only returned
logical message counts**, with no physical-fragment accounting — Ferrum's
historical `ws_rate_limiting` among them — bypassable by fragmentation: a
peer sends one non-final frame followed by an unbounded stream of
Continuation frames and pays for at most one logical message. (A policy
that also accounts for physical fragments is not bypassable this way; the
bypass is a property of message-count-only charging, not of every possible
per-message policy.) Zero-length continuations make it worse: they
accumulate no bytes, so `max_message_size` never fires either, and nothing
in the stock codec bounds how many frames or how long a message may stay
incomplete. That historical Ferrum bypass is tracked by #3404 /
GHSA-qq94-2gv2-phh6; the controls below are the applied local extension,
described on their own terms rather than as that advisory.

This patch adds the missing visibility and the missing bounds, without changing
any default:

- `FragmentMeter` — a shared, lock-free counter of physical data frames folded
  into an incomplete message. It is an `Arc` so it survives
  `StreamExt::split()`, which otherwise hides the codec behind a `SplitStream`.
- `WebSocketConfig::max_incomplete_message_frames` and
  `WebSocketConfig::max_incomplete_message_duration` — two **independent**
  ceilings on the in-flight reassembly (count and wall-clock), neither of which
  is expressible with the existing byte ceilings. Both default to `None`
  (upstream behavior). The duration ceiling is an observation-point check,
  not an autonomous timer: elapsed time is compared only after the codec
  decodes a subsequent non-Close frame while a data message is still
  incomplete — including the final continuation and interleaved Ping/Pong —
  and a peer Close is exempt. A silent peer, or one that has not yet
  completed its next physical frame, does not trigger the check merely
  because time passes; callers still need their own idle, session, or
  physical-frame deadlines for those conditions. The count ceiling is
  unaffected by this qualification and is enforced on each consumed
  non-final data frame.
- `WebSocketContext::set_fragment_accounting()` /
  `WebSocket::set_fragment_accounting()` /
  `WebSocketStream::set_fragment_accounting()` — one setter that installs the
  meter and both bounds before the first read.
- `ProtocolError::IncompleteMessageFrameLimitExceeded` and
  `ProtocolError::IncompleteMessageTimeout` — distinct failure origins so a
  caller can map them to a policy Close rather than a size Close.

Two different lifetimes are involved, and only one of them resets at a
message boundary:

- The codec's **per-message bounds state** — the incomplete-message frame
  counter and its start time — resets at every message boundary, so a
  long-lived connection of legitimately fragmented messages is unaffected
  by the ceilings above.
- The public **`FragmentMeter`** is a shared pending count that message
  completion does **not** drain. It keeps accumulating across messages
  until a caller invokes `FragmentMeter::take_reassembly_frames()`, which
  atomically swaps the pending count to zero.

The completing frame is *not* metered — it becomes the returned message.
Exactly-once wire-frame accounting therefore holds only conditionally: a
caller must drain the meter (charging the consumed non-final data-frame
count) **and** charge the returned completing data message once. A read
that returns an interleaved control frame (Ping/Pong) during reassembly is
also a drain opportunity. Error and peer-Close teardown paths need not
perform admission charges for the abandoned incomplete message.

## Files

| File | Purpose |
|---|---|
| `tungstenite-fragment-accounting.patch` | Unified diff against the vendored 0.29.0 base (both crates) |
| `README.md` | This status / retirement record |

## Hand-off — how to file upstream

1. Open an issue on [snapview/tungstenite-rs](https://github.com/snapview/tungstenite-rs)
   describing the fragmentation-bypass problem for proxies and per-message
   policy layers, and proposing the accounting hook plus the two bounds.
2. Push a fork branch with the patch applied and open a PR; open the matching
   `tokio-tungstenite` PR for the `WebSocketStream` delegator.
3. Record the issue + PR numbers here, in `docs/dependency-policy.md`, and in
   `docs/vendored-patch-lifecycle.json`.

## Retirement

Retire when an upstream release consumed by ferrum-edge exposes an equivalent
way to (a) observe physical fragments before reassembly completes and (b) bound
incomplete-message frame count and duration independently of byte size, **and**
the co-vendored tungstenite / tokio-tungstenite patches are also ready to
retire (see the parent [README](../README.md)). Until then this remains a
deliberate, time-boxed fork owned by `@jeremyjpj0916` under the
dependency-policy SLA.

## Behavioral regressions

- Vendored: `fragment_meter_counts_zero_length_continuations`,
  `fragment_meter_ignores_unfragmented_messages`,
  `incomplete_message_frame_limit_fails_closed`,
  `incomplete_message_duration_limit_fails_closed`,
  `incomplete_message_duration_zero_arms_on_initial_frame`,
  `incomplete_message_duration_rejects_final_continuation_bypass`,
  `incomplete_message_duration_rejects_interleaved_ping_pong`,
  `incomplete_message_close_bypasses_duration_bound`,
  `fragment_accounting_resets_between_messages`, and
  `fragment_bounds_default_to_unbounded` in
  `vendor/tungstenite-0.29.0-ferrum-patched` (`--lib fragment` /
  `--lib incomplete_message`).
- External unit: `tests/unit/gateway_core/websocket_fragment_metering_tests.rs`
  (metering, no-double-charge, both directions, observer exclusion, parser
  bound → policy Close mapping, duration bound on final continuation and
  interleaved Ping/Pong, peer Close exemption).
