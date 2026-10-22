# Baseline-only HTTP/2 POST upload diagnostic

This experimental, default-off observer starts at common baseline
`7bddb58ae8cf547c9bb875f597557dd842bcb786` (only the Azure lint repair over
`4a7be250e45a367314e3dec872ecbd512220558e`). It retains the unconditional
cancellation oneshot and autonomous SendWhen. It includes neither the lazy
channel candidate nor response groups. Earlier diagnostic `9babf81715b3b1804b9eb1a915191d1c056225cb`
remains preserved; that diagnostic extended lazy candidate `cf671bc`.

Root `bench-h2-upload-profile` enables only Hyper's non-default
`ferrum-h2-upload-diagnostic`. Default/full/cloud features do not enable it.
One fixed atomic increment classifies each actual POST reaching poll_pipe as
EOS, eager Ready(Ok), eager Ready(Err), or Pending. No request content, IDs,
labels, clock, logging, allocator observer, or per-request allocation is added.
The global atomic can perturb scheduling: these are instrumented-baseline
frequencies, not exact uninstrumented frequencies or throughput predictions.

Authorized `/metrics` appends twelve label-free integers under
`ferrum_h2_upload_diagnostic_`: `schema` (2), namespace `pid`,
`post_eos_total`, `post_ready_ok_total`, `post_ready_err_total`,
`post_pending_total`, sticky `counter_overflow`, `native_state_present`,
`native_finalized_total`, `native_status200_present`, `native_status200_total`,
and `native_active_requests`. Native values read state already maintained by
Ferrum. Finalized response status is recorded before streaming body EOF; the
loadgen's validated full echo is the independent completion evidence. Missing
state/status must not be interpreted as a zero count. Reads occur after the
registry render cache and are individually atomic, not transactional. The
native/diagnostic fields have no publication cache; the unrelated registry
render cache remains five seconds. No cache invalidation or new auth is added.

## Fixed remote experiment

Use one release image with `cloud-secrets,bench-h2-upload-profile`, the unchanged
Dockerfile/toolchain/dependency graph and crypto, and workers=4. Two serial
same-mTLS-fixture cells only: 1024 and 1048576 bytes, 3s warmup, 30s measurement,
configured concurrency100 (bulk effective50), rate0. The actual production body
is Incoming-backed through the upload pump, not the loadgen's Full body.
Keep readiness/auth probes outside the counter epoch. Each cell has its own
output directory. Snapshot before loadgen launch and after complete drain;
require quiescence with at most6.5s/15 attempts at0.5s, preserving all attempts.
Bind snapshots to container ID, image ID, host PID/start time, namespace PID and
restart count. Require all twelve fields exactly once, schema2, no overflow or
reset, and positive classified source traffic.

For a valid zero-error cell, branch deltas sum to
`warmup_requests + cohort_requests = warmup_requests + total_requests + drained_requests`.
Both proxy native finalized and200 deltas equal that population; destination
H2 POST delta is zero for the plaintext H1 backend. Retain errors and failed
conservation; do not retry application traffic to obtain a passing observation.
ReadyErr remains a separate bin. All-Pending shows no observed lazy-channel
opportunity in this instrumented fixture; Ready only establishes reachability.
Every diagnostic receipt has `performance_eligible=false`; no ranking or RPS claim.

## Verification and retirement

All Rust execution and fixture work is remote GitHub Actions. First run
`scripts/update_vendor_integrity.sh`, review its generated manifest-only artifact,
and commit that artifact before definitive checks. Never handwrite the manifest.
Reconstruct all seven ordered patches from the checksum-pinned Hyper archive.
Run the two `ferrum_h2_upload_diagnostic_tests` in an isolated Hyper workspace
with `full,ferrum-h2-upload-diagnostic` and patched h2=0.4.20. The standalone
vendored tests alone may use `RUSTFLAGS=--cap-lints=warn`; root checks/builds may
not. Run feature-enabled admin observability regression and strict root clippy.
The harness tests reject missing/stale/reset counters, identity changes,
nonconservation, errors, and malformed output. Keep generated manifest and
build/compiler/source/feature/image provenance with every result.

Owner: Ferrum Edge maintainers. Experimental unfiled diagnostic; remove after
these two cells, including both features, cold admin rendering, patch007,
documentation/lifecycle entries and reconstruction metadata. This is not a
permanent public API. Publication would require ferrum-contracts coordination.
