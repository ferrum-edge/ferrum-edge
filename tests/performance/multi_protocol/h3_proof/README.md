# Hosted H3 proof and corrected-image comparison

This directory implements the finite `corrected-v1` follow-up for #5588 after
merged PR #5615. It changes the benchmark/observer, not production forwarding. Committing
it does not assert a passing verifier, workload result, performance gain or issue
closure. Execute this code only on GitHub-hosted Linux amd64 runners.

The original `16a981d5` capability evidence is retained **unchanged** in
[the preflight report](../../../../docs/benchmark_h3_preflight_2026_09_18.md) and
[its extraction](../../../../docs/benchmark_h3_preflight_2026_09_18_results.json).
That report describes its original source, including preassigned fixture cookies,
excluded recvmmsg, both earlier failures, and absent classic execution helper.
The new implementation must acquire its own hosted evidence. Do not relabel the
old observations with these new capabilities.

## Fairness repair and bounded hosted gate

Run **35420498077**, source **e1407c60997670e0820d0670ae891056b6270e39**, retains
its original verdicts: 31/240 campaign rows rejected, all Envoy upstream-limit-4;
627 upstream sockets disappeared before the right capture, with observed 4 MiB
buffers throughout. Of these, 539 had zero backend echo work. The traced 346 had
actual retirements/final zero drops; the untraced 281 had **unknown final drops**.
All 20 observer calibrations remained unaccepted. The four short smoke rows do
not establish long-window coverage. Nothing here reprocesses those 244 rows,
changes an old verdict, imports diagnostic proof into a baseline, or establishes
a performance win or a causal production defect.

New captures label their admission contract `socket-lifetime-v2`. Three separate
fields describe observed buffer equality, observed lifetime/drop coverage, and
their conjunction (`equal_socket_budget_verified`, retained for the fail-closed
sample gate). Per-socket `complete_bracket` still means a passive full-window
bracket; an admitted retirement instead has `lifetime_covered:true` and
`lifetime_status:witnessed_retirement_with_final_drop`. It requires all of:

- A definite initial passive boundary and continuous observations until close.
- One actual birth and one actual `udp_destroy_sock` retirement, with the same
  cookie, process start tick, owner cgroup, endpoint, boot and held netns lifetime.
- Supported, finalized birth/destroy streams from this exact invocation, without
  identity/read/map/ring loss, omitted lifecycle records or forced termination.
- Actual final buffer sizes and a nondecreasing final socket-drop counter. The
  drop delta spans the selected initial capture through retirement, with its
  boundary slack retained. It is not an exact measurement-only packet total.

`socket_evidence_issues` distinguishes `wrong_buffer`, `missing_role:<role>`,
`missing_initial_boundary`, `missing_capture`, `cookie_or_owner_reuse`,
`boot_or_namespace_changed`, `unobserved_disappearance`, `missing_final_drop`,
and incomplete/mismatched retirement capture. A cookie seen only by tracing but
without passive identity is a gap, not an ignored row. Sockets born during the
measurement without the initial passive boundary still fail. Unobserved short
lifetimes remain a population-coverage limitation even in admitted rows. No
collector hooks, privilege grants, buffer caps or lifecycle caps are expanded.

**Untraced retirement remains unresolved.** Passive disappearance, backend close
records and Envoy idle counters do not supply a final kernel drop value. Such a
row keeps `drops:null`, precise failure reasons and `socket_budget_incomplete`.
Clean application traffic cannot override it. Calibration and whole-matrix
failure propagation remain unchanged; one rejected pilot/diagnostic still fails
the campaign. These fixtures do not authorize another full dispatch.

Both gateway configurations now dial **127.0.0.1:3445**, send **localhost** SNI,
verify the generated CA chain and require the **localhost DNS identity**. Ferrum
uses the existing upstream `backend_tls_sni` field, resolved by
`BackendTlsConfig::from_upstream` and consumed by both native H3 constructors'
`backend_tls_server_name` calls. Direct proxy fields do not support that override;
the config therefore references one numeric upstream target. There is no new
production TLS option. Envoy retains `sni: localhost` and adds
`match_typed_subject_alt_names: [{san_type: DNS, matcher: {exact: localhost}}]`.
This is the pinned d7809ba2
[CertificateValidationContext API](https://github.com/envoyproxy/envoy/blob/d7809ba2b07fd869d49bfb122b27f6a7977b4d94/api/envoy/extensions/transport_sockets/tls/v3/common.proto).
The pinned
[QUIC verifier](https://github.com/envoyproxy/envoy/blob/d7809ba2b07fd869d49bfb122b27f6a7977b4d94/source/common/quic/envoy_quic_proof_verifier.cc)
also checks the leaf hostname; neither source inspection nor SNI alone substitutes
for the following actual behavior gate. Client frontend verification remains the
existing explicitly insecure harness policy, separately from upstream identity.

The dedicated workflow's **H3 actual TLS identity and long idle-retirement
fixtures** job runs on PRs, uses the same hashed build/image artifacts as smoke,
and is a dependency of the manual campaign. `fairness.py` runs exactly:

| Fixture | Required actual evidence |
| --- | --- |
| TLS, Ferrum / Envoy-100 / Envoy-4 | Each gateway first returns HTTP 200 and exact 10 KiB echo through H3. The same live backend then presents a same-CA leaf with only `wrong.invalid` DNS SAN (still with the connect IP SAN), closes its old connections and requires a new failed H3 handshake plus 502/503, no backend echo, and no TCP fallback. Observed valid-handshake SNI must be localhost. |
| Long load, all three gateways | 200 workers, 21 client connections, 10 KiB, **40 seconds measured**, then **40 seconds** of idle observation before any workload teardown. Original stream/buffer/idle settings remain unchanged. Strict sample admission and actual role operation/birth/destruction evidence are required. |
| Envoy-4 idle lifetime | Both actually used and actually unused backend connections must close and join to owned kernel socket retirements before teardown, with final buffers/drops. Retain actual idle-timeout and local-destroy counters, raw backend closes and all sockets. Absence fails; there is no retry-until-reproduced loop. |
| Evidence negatives from that new invocation | Copies of real evidence inject a missing capture, wrong buffer, inode/cookie reuse, namespace change, missing initial boundary, missing final drops, missing client role, foreign invocation, and trace-off evidence. Each must reject for its precise reason. A copied client observation with an early retired worker must also reject. These are labelled evidence fault injections, not additional live kernel retirements. |

Ferrum shares UDP endpoints across upstream QUIC connections. Its actual socket
teardown is required, but a QUIC idle close is never called a socket retirement
unless the kernel event exists. The fixture records zero or absent idle events
without fabricating an Envoy-shaped Ferrum pool.

The TLS helper is a dedicated harness binary under this directory; it uses the
existing pinned Rust dependencies, generates two real leaves under one CA, and
exports only public certificates plus raw request/handshake logs. It performs
one request per identity, no retry or fallback. Its backend has a 120-second cap
and requests a 20-second cap. Startup TCP capability probes remain visible;
TCP attempts during the behavioral request cases fail. The whole fairness driver
has a 900-second hosted wall cap and a 20-minute job cap. The long samples retain
the existing 300-second observer and 64 MiB per-arm artifact bounds. Failure
records and the full negative matrix are uploaded even when a fixture rejects.
Build, rustfmt, targeted clippy, Python semantic tests, real verifier/collector
fixtures, smoke and this behavioral gate run **only on GitHub-hosted CI**. Their
registration is not a claim that this revision has passed them.

## Fixed comparison

`live_campaign.json` declares all experimental inputs before dispatch:

- Official Envoy Linux amd64 image
  `docker.io/envoyproxy/envoy@sha256:79c4e987d386b176721638187b511fb4d7041695f7a78e422ed27edd707b3eeb`,
  source `d7809ba2b07fd869d49bfb122b27f6a7977b4d94`, as approved in root's plan.
  No Envoy compilation or source-build comparison occurs.
- Direct, Ferrum, Envoy upstream 100 and **the same** Envoy upstream 4; actual
  downstream listener admission and HCM settings stay at 100. A parsed semantic
  config comparison requires exactly one changed upstream admission field.
- Payloads 10240/71680/512000/1048576/5242880, workers 200/200/200/100/50,
  client connections 21/21/21/11/6, 30 seconds, four counterbalanced pairs:
  **80 main samples** across five shards, one payload and one boot per shard.
- Effective kernel receive/send buffers 4194304. Envoy requests half that value
  because Linux doubles explicit requests. Cookie-joined readback of actual
  owned sockets is required for comparison acceptance. Missing brackets remain
  incomplete. SNI `localhost`, upstream CA validation, both H3 hops, strict
  HTTP 200/exact body, no retry/fallback, phase and endpoint-drain contracts stay
  in force. Existing client frontend TLS verification remains explicitly insecure.

The new `.github/workflows/h3-live-comparison.yml` has read-only permissions and
pinned actions. PR checks compile features, run semantic contracts and real
fixtures, a short real four-arm gateway smoke, and the bounded fairness gate. Its manual job reuses that
same workflow's compiled and hashed Ferrum/harness/observer artifacts after the
smoke. Ferrum is packaged once as an image; its image configuration ID, source
revision, binary/build ID and artifact hashes are retained. The local packaged
image ID is not represented as a registry manifest digest. The approved Envoy
manifest/config IDs, actual binary SHA/build ID, generated config and effective
runtime response are retained separately.

Root owns review and any future manual dispatch after the bounded gates pass. The ordinary
`experiment.json` stays disabled; frozen workflows, gates, policies and the
existing H1/H2 paths are unchanged. The runner's only new selector is:

```text
run_gateway_protocol_bench.sh http3 --h3-live corrected-v1 {smoke|10240|71680|512000|1048576|5242880} --output-dir PATH
```

The privileged entrypoint admits only hosted Linux amd64. All launches resolve
through literal `live_commands.sh` commands; user data never supplies executable
text. Fresh root-owned staging rejects reuse and checks source/object hash parity.
Native workloads run as UID/GID 65534 without capabilities and with no-new-privs;
both Docker gateways additionally use the same default seccomp, read-only root
and host network. They have no Docker socket or writable observer maps. Only the
provisioner/observer is privileged. Process privilege records are retained and
checked. Socket budgets are set on the disposable runner before workload birth.

The proof launcher selects `proto_backend --h3-only`: it generates the usual
certificates and serves QUIC on UDP 3445 plus readiness on TCP 3010, with both
listeners supervised for startup/runtime failure. No UDP echo or DTLS listener
is started in this mode. Invoking `proto_backend` without arguments retains all
ordinary protocol listeners. Every owned UDP socket still requires an assigned
proof role; unexpected sockets invalidate admission rather than being ignored.

Command metadata converts path arguments to their launcher text before spawning.
Serialization or initial artifact errors therefore create no child; wait errors
and timeouts kill and reap the owned process group before cgroup cleanup. TLS
fixture cleanup also retains ownership of an attempted container creation through
metadata errors and continues stop/removal if log collection fails. Hosted
semantic regressions cover these error paths; the real smoke and TLS/idle jobs
remain required to establish behavior at the new head. No historical failed
sample or retirement evidence is reclassified by these fixture repairs.

## Calibration and raw retention

For each payload/arm, two paired off/on pilots reverse treatment order. Both
retain the same passive sampler. Predeclared tolerances are 2% useful RPS and 5%
p99; paired log-ratio Student-t intervals (df=1) retain the very large uncertainty
possible with two pairs. Every arm must resolve within both tolerances to use
active observation in the main comparison. Missing metrics, invalid traffic or
failed observers never pass calibration.

The harness retains a Linux `CLOCK_MONOTONIC` bracket around the actual
measurement-start `Instant`. Its process-local `measurement_start_monotonic_secs`
is never compared with kernel or observer timestamps. The driver verifies an
unshifted host clock and matching workload time namespaces, retains paired
realtime/monotonic reads, and requires captures before and after measurement.
Clock reads wider than 1 ms, missing/reversed bounds, observed realtime steps
beyond 1 ms plus 1000 ppm slew, and inconsistent phase realtime fail closed.
Live H3 passive socket/buffer/drop and process CPU/I/O boundaries use the entire
retained monotonic capture interval, not its opening realtime timestamp. The
left capture must finish at or before the measurement start's lower bound; the
right must begin at or after the end's upper bound. An earlier completed capture
is selected when present. Otherwise the bracket remains incomplete and the raw
observations remain retained. Missing, malformed, reversed or overlapping capture
intervals cannot authorize admission. Selected raw timeline indices, read bounds,
bracket-duration bounds and boundary-slack bounds expose the uncertainty without
assigning a midpoint. Every intervening capture still participates in process
generation/socket population continuity and buffer/process-counter checks.
Deltas span the selected captures and may include work outside measurement.
RSS is labelled
as observations from captures possibly overlapping measurement, not an exact peak.
The client's own phase-boundary CPU snapshots remain authoritative. This strict
path is confined to live H3; shared historical point-sampled process/transport
helpers are unchanged and are never a fallback for missing live intervals.
Witnesses in either uncertain boundary band remain uncorrelated; errors whose
capture interval might overlap measurement, including untimed errors, invalidate
provenance. An empty matching witness set makes no absence or performance claim.

This repairs review F1's reachable successful-capture boundary crossing. The
retained `e00f0a91` smoke did not exercise that counterexample: its selected
predecessor captures completed before measurement. It remains evidence for its
original revision. The added boundary regressions and this repair require fresh
hosted validation; no rerun or new performance result is asserted here.

Otherwise all four main pairs run without the active observer, followed after
each pair by a matched traced diagnostic pair. Proof belongs to those diagnostic
samples only. No observer overhead is subtracted. Every raw failed/malformed
benchmark output, stderr, readiness record and partial snapshot remains in its
original file; derived metadata is separate. Failure metadata exists before
startup and workflows always upload results. A timeout is never replaced with
an `rps: 0` benchmark. Useful-traffic validity and proof completeness are separate.

## Observer contract

- Native amd64 IPv4 recvmsg and recvmmsg only. Runtime syscall formats and
  msghdr/mmsghdr/cmsghdr sizes/offsets are checked. Native syscall numbers reject
  compat/x32 decoding. Recvmmsg vectors are bounded at 32 in map values, never
  a 32-entry BPF stack array. Larger vectors are explicitly excluded.
- Entry captures original control pointer/capacity per slot and syscall
  generation. UDP entries associate one consistent actual cookie; matching
  inner errors and abandoned/nested/mismatched calls remain counted.
- Only the outer syscall's successful returned prefix is decoded. Per-message
  `msg_len` is separate from the batch count (`RX_BATCH` stores requested vlen
  in `length`, kernel entries in `segment`, returned message count in `result`).
  Zero/error/restart returns never decode stale slots. Read failures in later
  slots do not erase earlier valid deliveries. Timeout-copyout EFAULT is an
  error even when the kernel consumed a datagram.
- The returned ancillary decoder reads at most 256 bytes/eight headers, and only
  UDP_GRO's native four-byte integer. Pointer/capacity/length/alignment/duplicate
  checks, truncation, peek, error queue and zero datagrams are explicit.
  A positive witness requires returned bytes greater than positive stride and
  successful delivery. No packet payload or CID is read.
- Typed tracing contexts and direct BTF field access supply
  `bpf_get_socket_cookie(sk)`. A scalar reconstructed by probe-read is not used
  as a helper argument. Fixtures leave cookies unassigned before first observed
  bind/attachment/traffic, then compare actual observer cookies with SO_COOKIE
  and sock-diag. Verifier rejections are errors, not unsupported successes.
  CO-RE declarations preserve field kinds as well as names: `sin_addr` is a
  nested `struct in_addr` and `bpf_prog.type` is `enum bpf_prog_type`. Endpoint
  reads relocate kernel fields directly rather than a partial stack structure.
- Birth/bind, TX/RX, retirement, process fork/exec/exit, reuseport attachment,
  membership and classic execution load independently. The attach family does
  not require `run_bpf_filter`. Exact classic execution remains unavailable on
  the retained Azure kernel; an outer selector hit is insufficient. No guessed
  JIT offsets, steering replacement or alternate kernel is introduced.
- Successful attachment retains a bounded original-classic instruction FNV-1a
  digest (at most 64 instructions; explicitly noncryptographic), type and an
  observer generation. Missing original instructions leave an invalid digest,
  not invented bytes. Actual group add/alloc/detach operations carry member
  cookies; postprocessing does not infer groups from common ports. Replacement
  and detach remain separate from instruction execution.
- An owned cgroup subtree exists and every family reports readiness/capability
  before backend/gateway/client creation. Process start generation, host PID/TID,
  cgroup, boot and held netns lifetime accompany cookies. Frontend requires the
  owned process and successful full-endpoint bind. Upstream requires actual
  connected/sendmsg destination and owned backend connection peer evidence.
  First-send autobind updates the tuple without changing identity. A cookie can
  carry multiple QUIC connections. Softirq CPU is never labelled as a worker.
- `udp_destroy_sock` retains final buffers/drop metadata where observed. A closed
  alias, process exit or disappearance from a diagnostic dump is not retirement.
  Missing birth uses first-observed time; missing retirement/end counters stay
  null. Descriptor numbers remain annotations, not socket identity.

The upstream references for these contracts are Linux v6.17
[returned-prefix and copyout logic](https://github.com/torvalds/linux/blob/v6.17/net/socket.c),
[typed cookie helper](https://github.com/torvalds/linux/blob/v6.17/net/core/filter.c),
and [reuseport lifecycle](https://github.com/torvalds/linux/blob/v6.17/net/core/sock_reuseport.c).
The running hosted BTF/verifier/fixtures, rather than a source version assumption,
determine availability.

### Attachment load diagnostics after `5c8cb5bf`

Both hosted [preflight 35409593353](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35409593353)
and [live prepare 35409593373](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35409593373)
failed loading `a_attach` with `-28` (`ENOSPC`) on `6.17.0-1022-azure`.
The retained attachment fixtures successfully attached/replaced/detached the real
classic filter. The observer reached 4254 processed instructions, 150 total
states and 133 peak states; only the verifier statistics remained in stderr.
The existing `verifier_log_truncated=false` described the libbpf print callback,
not the kernel log's maximum size during verification. It did not establish that
the kernel log fit. Neither filesystem exhaustion nor unsupported attachment is
established by this failure.

Linux v6.17's [log implementation](https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/log.c)
keeps `len_max` across log rewinds and returns `ENOSPC` when that maximum exceeds
the supplied buffer. The [verifier](https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/verifier.c)
rewinds successful paths at level 1, then appends statistics; log finalization can
also replace an earlier error. Thus a short final log can still overflow.
[libbpf 1.3](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.c), matching the
retained package, leaves a caller-supplied buffer fixed and does not expose
`log_true_size` through its object API. This is the source-backed explanation to
test on the next head, not a claim that the Azure kernel's exact maximum was
measured or that every subsequent verifier/JIT/attach stage passed.

Only `a_attach`, in either family that loads it, now requests `BPF_LOG_STATS`
(`4`): errors and verification/stack statistics without instruction-path logs.
The 256 KiB buffer, probe bytecode, typed cookie context, subprograms, 64-instruction
digest bound, maps and fixture remain unchanged. The loader retains the selected
logging mode, object load result, final-buffer byte count and final kernel log on
success as well as failure. There is no added load retry. A successful real
attachment fixture after this single logging change supports the log-overflow
diagnosis; a remaining rejection retains its errno and diagnostic text. No
instruction bytes from the observed classic program or packet payload are exported.

`ENOSPC` now conservatively marks verifier diagnostics incomplete, even when the
final string is short; this flag is not an errno reclassification. Snapshot
validation requires the emitted boolean, and fixture/live admission rejects
incomplete final diagnostics. Contract regressions retain error readiness and
the original load errno alongside successful fixtures. These changes still need
hosted compilation, real fixtures, Python contracts and the full four-arm smoke.

## Bounds and remaining evidence limits

The subsequent d19 live smoke passed prepare/preflight but lost required
retirements to backend peer churn. The [smoke failure report](../../../../docs/benchmark_h3_smoke_2026_09_18.md)
retains exact counts and sites. The shared observation predicate now treats
both fixed listeners (3445 and 8443) alike: a send destination change alone is
not a new listener identity. Listener peers are representative metadata;
backend connection logs still supply the upstream peer join. Hosted metadata
regressions exceed the unchanged lifecycle cap with rotating peers, while the
real four-arm smoke still requires kernel births and retirements. Lifecycle
output omissions and ring loss explicitly invalidate admission. Repaired
hosted execution remains pending.

A live arm is limited to 300 seconds, at most 64 snapshots including final, and
10-second checkpoints plus explicit phase boundaries. Stop detaches writers
before final stable map iteration; signals/parent death, missing final, forced
stop and snapshot failure are explicit. Each independently loaded family has
bounded maps (1024 identities, 256 pending operations, 4096 bucket rows/witnesses).
Eight 512 KiB lifecycle rings share a 4 MiB ring reservation. Exact witnesses are
limited to 128 per 10-second window, so startup cannot consume every later window.
Fixed outcome/segment-count buckets exclude exact lengths and CPU from live keys.
Sampling omissions, map/ring/read loss and unknown identity are retained.

The 64 MiB arm artifact cap is enforced after collection and each observer stream
has a 10 MiB cap. Observer RSS is sampled against a 32 MiB reservation, with the
other half of the proposed 64 MiB budget reserved for bounded kernel maps. This
is a conservative allocation design to validate on hosted load, not a measured
kernel allocator capacity claim. Kernel allocation overhead is not directly
measured. Concurrent checkpoints are non-atomic; only final snapshots are stable.
No absence or exact-total claim follows even from zero reported map loss.

Real fixtures include mixed and partial 32-entry recvmmsg, EAGAIN/EINTR/EBADF,
zero datagrams, WAITFORONE, peek then consumption, data/control truncation,
protected header/control/sockaddr/flags/controllen/msg_len/timeout copyout faults,
a fault after a successful prefix, attachment replacement/detach, surviving dup,
real FD reuse, count-map saturation, missing-BTF/symbol and denied-privilege paths.
Process/netns generations and final socket lifetimes are also retained in the
live smoke. This does not implement a general FD emulator or certify every
close_range/namespace/restart interleaving. Short process/FD lifetimes between
passive samples and unobserved retirement remain partial coverage; supported
hooks with missing records are not relabelled as host capability failures.

The live smoke requires supported TX/RX/birth/retirement observers, both traffic
directions and actual socket birth/retirement events for every required role.
Malformed readiness, rows or final diagnostics, missing families, capture/resource
errors and artifact limits invalidate admission before calibration or comparison.
Unavailable classic execution remains a distinct capability result; a malformed
or failed fixture is still an error. Hosted prepare runs the common-clock Rust
regression, formatting and targeted lint, plus the Python clock/admission tests
and real verifier/fixture checks. No local execution substitutes for these gates.

Both off/on treatments retain process/thread CPU/RSS, capture cost, host CPU and
softirq snapshots. PMU opening in the original preflight is only event availability;
no sampled CPU stacks or hardware contention claim is made here. Envoy's corrected
cumulative counter semantics stay separate from kernel/socket drop deltas. Root
owns hosted result review, final integration of #5602, workflow dispatch and the
artifact audit. #5588 remains open.
