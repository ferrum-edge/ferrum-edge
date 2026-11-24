# Mesh Sidecar Optimization — Findings (2026-10-18)

Follow-up to [`benchmark_mesh_runtime_2026_10_17.md`](benchmark_mesh_runtime_2026_10_17.md).
Question: where does Ferrum's mesh sidecar spend the per-request CPU that
puts it behind the static Envoy control and the Consul-generated pair at
small payloads, and what change closes the gap?

**Short answer:** no single knob or hotspot closes it. Every black-box
tuning lever and the one code change below measured within noise under
interleaved A/B. The cost is diffuse — Ferrum executes a full gateway
request path (plugin chain, header/metadata maps, transaction summary)
on both sidecars, where the compared Envoy filter chains do materially
less per request. This page records what was tried, how it was measured,
and what to try next, so the work is not repeated.

## Method (and a false positive worth recording)

Experiments used the mesh-runtime harness topology unchanged (loadgen →
client sidecar → H2/mTLS → server sidecar → echo) in the same Colima
Arm64 VM as the benchmark report. Knob experiments used the published
`main-ee8c0e59` Ferrum image; code experiments used locally built
binaries (thin LTO, symtab preserved) run as native VM processes.

**Measurement lesson:** sequential single-run A/B across a rebuild
boundary produced a false +22% "win" (baseline 25,784 RPS in one VM
state vs patched 31,5xx in another). Interleaved back-to-back pairs of
the two exact binaries in one session showed both moving together
(31.6k/31.4k, 31.4k/31.4k, 28.6k/28.9k baseline/patched @1KiB). All
verdicts below use same-session comparisons; treat single-run deltas
under ~10% on this rig as unproven.

## Profile evidence (symbolized, 1KiB conc-100, both sidecars)

`perf record` (dwarf call-graph, 52K samples) against a symtab build —
flat self-time, Ferrum userspace only, top entries:

| Share | Symbol |
|---:|---|
| 5.4% | `core::hash::sip::Hasher::write` (all instantiations) |
| ~4.5% | jemalloc alloc/free/tcache (`_rjem_malloc`, `_rjem_sdallocx`, flush/fill) |
| ~2.6% | arm64 atomic ops (`__aarch64_ldadd*`, `__aarch64_cas*`) |
| 2.0% | `proxy::handle_proxy_request_inner` (self) |
| 1.9% | `RandomState::hash_one` (+ `TrustDomain` hashing 0.5%) |
| 0.4% | `HashMap::insert` |
| 0.3% | h2 HPACK encoder; `proxy_to_backend*`; `SpiffeId::path_segments`; tokio `TimerEntry::poll_elapsed` |

No Ferrum function exceeds ~2% self time. HashMap operations
(`HashMap<String, String>` headers + metadata with the std SipHash
hasher) and allocation churn are the largest *classes*, at roughly
7–8% and 4–5% respectively.

## What did not work

Baseline for all rows: published image, harness rig, 31,995 RPS @1KiB,
11,656 @70KiB, 1,275 @1MiB (same session).

| Experiment | 1KiB | 70KiB | 1MiB | Verdict |
|---|---:|---:|---:|---|
| Frontend H2 windows/frame ↑ (8MiB / 32MiB / 1MiB) | 32,592 | 12,234 | 1,355 | noise (+2–6%) |
| Pool connections/host = 1 | 30,236 | 8,856 | 875 | worse at bulk |
| Pool connections/host = 16 | 32,006 | 11,712 | 1,277 | no change |
| Pool windows ↓ to frontend (256KiB / 2MiB) | 32,277 | 11,786 | 1,250 | no change |
| All metric families disabled (Telemetry) | 29,766 | 12,049 | 1,321 | no change |
| Tracing sampling 0% (Telemetry) | 32,798 | 11,852 | 1,308 | no change |

Hypotheses refuted: mesh-mTLS pool width/flow-control asymmetry,
frontend window starvation, metrics emission cost, tracing cost
(access logging had already been excluded in the benchmark bring-up —
that one *did* matter, vs mesh defaults, and is recorded in the
benchmark report).

## Code change tried: metadata restamp skipping (neutral)

`workload_metrics::annotate_http_context` runs twice per request
(request-received and before-proxy) and unconditionally re-inserted
~20 metadata keys (fresh `String` key + value allocations and SipHash
writes), including clearing and re-stamping the four SPIFFE source
labels. The change on this branch:

- `insert_metadata_if_changed`: borrowed lookup first; allocates only
  when the value actually changes. Applied to all fixed-key stamps in
  the annotate path (common labels, SPIFFE source/destination labels,
  workload/app/service labels, custom tags, direction, protocol,
  connection-security-policy).
- The source-label clear is skipped only when the identity this call
  will stamp (resolved with the same direction logic as the stamping
  match below it) already matches the stamped labels exactly —
  including segment absence. Any identity change, including to/from
  `None`, still clears first. Final metadata is unchanged in all cases.
- Focused unit test
  (`source_spiffe_labels_match_gates_clear_and_restamp`) pins the
  match/clear semantics, including segment-loss clearing.

**Measured effect: none distinguishable from noise.** Interleaved
native-binary pairs @1KiB (baseline / patched): 31,629/31,426,
31,371/31,393, 28,627/28,881. The change strictly removes redundant
allocations and preserves semantics, so it is kept as code hygiene —
but it is **not** a competitiveness fix and this report does not claim
it as one. (49/49 `workload_metrics` unit tests pass locally; PR CI is
the regression gate.)

## What to try next (ranked by profile evidence)

1. **Fast hasher for hot context maps.** SipHash classes total ~7–8%
   self time. `ctx.headers` / `ctx.metadata` are
   `HashMap<String, String>` (std `RandomState`); `ahash` is already a
   dependency. Expect low-single-digit percent; blast radius is the
   plugin-facing map type, so this needs its own PR and interleaved
   A/B. DoS posture: these maps are keyed by header/metadata names
   (bounded cardinality), not attacker-chosen key floods — evaluate
   explicitly in that PR.
2. **Header representation.** Converting hyper `HeaderMap` →
   `HashMap<String, String>` per request (both sidecars, both
   directions) allocates per header. A mesh fast-path that keeps
   `HeaderMap` until a plugin actually needs the map form is the
   largest structural lever and the largest change.
3. **Transaction summary construction.** Built per request even when
   no consumer logs it; audit which fields can be lazy.
4. **Per-request timers.** `TimerEntry::poll_elapsed` is visible;
   count timers armed per mesh request (backend, pool, plugin
   deadlines) and consider coalescing.
5. **Re-profile after each** with the symtab build recipe below; judge
   only by interleaved pairs.

## Reproducing the profile

The published image is stripped. A symtab build that fits a 13 GiB
VM (host swap recommended): rust container over a host-mounted
checkout with `CARGO_BUILD_JOBS=2`,
`CARGO_PROFILE_RELEASE_DEBUG=0`, `CARGO_PROFILE_RELEASE_STRIP=false`,
`CARGO_PROFILE_RELEASE_LTO=thin`, `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=8`,
then run the binary as native VM processes and
`perf record -F 997 -g --call-graph dwarf -p <svc>,<client>`.
Note the locally built binary (thin LTO) is ~20% slower than the
published fat-LTO image in absolute terms — only same-build A/B
comparisons are meaningful.
