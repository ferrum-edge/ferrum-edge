# Fixed baseline upload diagnostic

This controller accepts only the pinned observer source, or a descendant whose
only additional tree change is the remotely generated vendor integrity manifest.
The source starts at maintenance baseline7bdd, preserves the original unconditional
oneshot and SendWhen, and contains no lazy-channel or response-group candidate.
Earlier diagnostic9bab (which included lazy cancellation) is preserved separately.

The workflow has two explicit phases. First dispatch `h2-upload-vendor-preflight`
with the reviewed exact `candidate_sha`. It runs only the repository-supported
manifest generator, records source/harness/toolchain provenance, and checks that
exactly the five diagnostic Hyper source rows changed and match source hashes.
Review the uploaded `checks/vendor-manifest.patch`, commit that generated patch,
then dispatch `h2-upload-diagnostic` with the resulting exact SHA. Do not use
`candidate_kind` or baseline reuse inputs for this diagnostic.

The second phase reconstructs the complete Hyper patch stack, runs exactly two
isolated patched-h2 counter tests, root integrity, strict Clippy, and the existing
admin auth regression with the explicit diagnostic feature. It builds one image
from the unchanged Dockerfile using `cloud-secrets,bench-h2-upload-profile` and
release. Standalone Hyper tests alone use `--cap-lints=warn`; root checks and the
release image do not. It builds the existing tested load-tools image and starts
exactly two serial isolated mTLS fixture cells, 1024 and1048576 bytes,30s measured
plus3s warmup,workers4,rate0,configured concurrency100 (bulk effective50).
No gateway/Envoy comparison, sampling, allocator observer or feature-disable run
is added. The two cells continue independently after ordinary failures, but no
cell repeats. Ordinary ranking guards and decisions remain unchanged.

The collector records every boundary attempt under `upload-epoch/before` and
`after`; at most15 attempts/6.5s, spaced0.5s, with0.5s maximum subprocess waits.
Readiness/auth probes are before the first boundary. Two equal cold snapshots
with active requests0 establish each boundary. Identity includes container and
image IDs, host PID/start time, namespace PID, start timestamp and restart count.
The four H2 branch fields plus native finalized/status200 totals are read after
the registry cache; their publication cache is0s. The registry cache stays5s.
No stale/missing family becomes a zero and no application request is retried.

Successful whole-epoch population is warmup_requests+cohort_requests, equal to
warmup_requests+total_requests+drained_requests. Source branch deltas and each
proxy's native finalized/status200 deltas must equal that positive population;
destination H2 branch deltas must be0 for the H1 backend. Nonempty echo requests
must have no eager EOS/error. Loadgen validates complete body echoes. Native
finalized status is recorded before body EOF, so it is never represented as an
independent EOF counter. Errors, all bins and failed conservation remain in raw
receipts; no frequency is qualified for failed cells.

Every diagnostic decision receipt is `performance_eligible=false`. Atomic
contention can change scheduling; observed frequencies belong only to this
instrumented baseline. Ready means a branch is reachable, not that avoiding an
allocation improves RPS. All-Pending means no observed lazy-channel opportunity
in these cells. No RPS/CPU/allocation-saving claim or expanded campaign follows
automatically. Full identity-bound workload telemetry remains separately
unqualified in this localized fixture; normal operational telemetry is retained.

Artifacts use a256MiB public allowlist with per-file hashes and exclude runtime
fixtures, keys, build trees and binaries. The initial manifest run and later
observation run are distinct exact-SHA receipts. No local Rust/runtime execution.
