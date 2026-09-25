# UDP internal profiling (#5588)

`bench-udp-profile` is a default-off, dependency-free diagnostic feature. It
does not optimize session lookup, change forwarding policy, or close #5588.
The H1 feature, allocator, and schema are unchanged. UDP does not install an
allocator. With both features selected, H1 continues to forward to Jemalloc.
The FIPS inventory explicitly includes UDP alone and UDP with H1; these
features introduce no crypto providers or runtime-policy exemptions.

## Fixed authenticated contract

The existing gated `/metrics` response gains `ferrum_udp_profile_*` fields only
in feature builds. Admin JWT, metrics bearer token, and allowed source CIDR
checks are unchanged. There are no dynamic labels, addresses, namespaces,
destination identities, credentials, or payloads in this family. The literal
allowlist is `tests/performance/multi_protocol/udp_profile_schema.json` and
`src/udp_profile/schema.rs`; hosted tests require exact parity.

Counters accumulate per OS thread in fixed TLS storage. At most 128 slots are
claimed once and never reused, including after thread exit. Ordinary updates
use no profiling locks, global atomics, allocation, or logging. Every 2048
update groups, the owner publishes cumulative fields through per-slot atomic
storage with a bounded sequence-checked read. A dirty marker is written once
per interval, not once per packet. Exceptional registration exhaustion, TLS
reentry/teardown, or sequence overflow increments `lost_events`. Counter and
aggregate overflow saturate and remain explicit. Missing snapshots are never
substituted with zero. Publication overhead must be calibrated.

Thread exit publishes its tail when TLS destructors run; abrupt process exit
can lose it. Scraping flushes only the scraper's current thread. Other dirty
slots contribute 2048 each to `unpublished_event_bound`. This bounds local
update groups at each slot's capture in the absence of loss, **not packets, bytes, nanoseconds, or
global point-in-time skew**. Idle workers can leave tails indefinitely. Nonzero
tails, missing slots, loss, overflow, or a reset prevent complete-profile status;
published deltas remain useful partial observations. No remote worker flush,
per-packet publication, or global barrier is added to forwarding.

`sample_every=64` means the first and every 64th call of each operation on each
OS thread receives two monotonic `Instant` reads. Sampling is deterministic,
not random; task migration changes the sample sequence. Timers enclose only
synchronous calls and never cross `.await`. Nested timers are inclusive. Clock
resolution is platform dependent and timer/observer overhead is not subtracted.
Disjoint timing bins end at 100, 500, 1000, 5000, 20000, 100000, 1000000 ns,
then infinity. Occupancy bins are 0, 1, 2–4, 5–8, 9–16, 17–32, 33–64, 65+.

## Attribution and limits

| Observation | Meaning and coverage |
|---|---|
| Metadata decode / destination resolve | Existing authenticated envelope decode when enabled, then exact route resolution; ordinary echo has no metadata/NodeWaypoint workload. |
| Pending / last-client / established lookup | Attempts and hit/miss outcomes, plus sampled synchronous time. Cache expiry is counted at the original expired check; established expiry is a feature-only observation of the returned entry's flag. A hit does not imply later policy admission. These are software lookup outcomes, not hardware cache misses. |
| Second pending race gate | Existing occupied/vacant/error outcomes and sampled insertion-call time; the defensive follow-up lookup has separate attempt/hit/miss timing fields. Pending entries have no independent expiry field. |
| Pending queue | Accepted/tail-dropped datagrams, retained bytes, batches removed for FIFO drain, empty gate removal and aborted queue residuals. Drained means removed for processing, not successfully forwarded. Residuals already moved into a drain batch and later refused are not separately enumerated. |
| Shared updates | Calls at request-size/budget publication, finite amplification charge, fast-path activity/byte updates, queue admission charges, normal listener and reply metric publication. These are source-level operations, not successful CAS counts, retries, contention time, or every shutdown/rollback/hook/DTLS counter update. |
| Borrowed / queued send | Successful borrowed backend sends and returned bytes, WouldBlock/errors, egress enqueue/drop/dequeue, and successful authorization-aware queued commits. Queue admission is not a send. Setup/hook asynchronous backend sends remain outside these send totals. |
| Poll / readiness / notify | Egress receiver/commit polls, reply receive polls, Pending/Ready outcomes, frontend `readable()` returns, drain WouldBlock outcomes, reply-stop/hook notify calls. No scheduler wake, context switch, or CPU-contention claim. Egress poll totals combine queue receive and commit; they are not whole-task poll counts. |
| `ingress_rx_*` | Actual frontend `recvmmsg` requested/returned occupied slots; error/WouldBlock counts; raw returned bytes; logical packets from parsed GRO segment sizes. Parsing failure, payload/control truncation and invalid GRO segment size are explicit and leave logical-packet coverage incomplete. Zero-length datagrams count as packets. Tokio's cached not-ready path does not count as an actual syscall. |
| `reply_tx_*` | Actual `sendmmsg` occupied input slots, accepted slots/bytes, partial calls/remainders, error slots, and explicit discard/oversize outcomes. Retries count the remaining requested slots again. Errors clear the original queue; partial sends retain it in original order. |
| `reply_gso_*` | Occupied segments/bytes/segment-size sum, full accepted segments and returned bytes, errors/short results, fallback segments handed to sendmmsg or direct send, explicit discards. A fallback handoff is not acceptance; final mmsg/direct outcomes are separate. Single-segment success alone does not prove batching. Kernel acceptance does not prove NIC offload. |
| `reply_direct_*` | Logical Tokio send futures or explicit pktinfo attempts, accepted bytes and errors. Tokio internal syscall retries are opaque. A canceled future can leave calls without a terminal outcome. |

Directions are attached to batch owners and survive task migration. `other_*`
isolates shared batch helpers used by mesh capture/DTLS instead of pretending
those calls belong to the plain UDP listener. Plain UDP backend receives are
individual `recv`/`try_recv`, and borrowed client-to-backend sends do not use
sendmmsg/GSO. Thus reply recvmmsg and ingress mmsg/GSO are unexercised in this
path, not evidence of missing syscalls in those directions. Quinn HTTP/3,
DTLS crypto drivers, mesh identity revalidation, native allocations, complete
copy traffic, queue delay, whole-task scheduling, and CPU stacks are opaque.
GRO logical counts describe ancillary-derived packets before later admission;
they are not useful-work totals. Unused operation hit/miss/error fields remain
zero and are not additional coverage claims.

The pending map still precedes last-client and established lookup. Session
publication still occurs before the pending FIFO drain finishes; established
first would permit overtaking. No lock, authorization, generation/namespace,
destination ownership, expiry/revocation, amplification, pktinfo source,
queue, retry, or notification ownership rule is relaxed.

## Hosted checks and bounded campaign

The `UDP Internal Profile` workflow has a feature-on lane (pull requests that
edit the UDP profiler itself, and a daily run on the `main` tip; see
`docs/ci_cd.md` -> "Optional PR lanes and post-merge validation") for
formatting, clippy, build, attribution/publication/batch tests, and existing
setup/FIFO/auth/source/amplification/generation regressions. It also checks the
observer-off path, combined H1 build and parent collector contracts. All
execution is hosted. No workflow was dispatched by this implementation.

Manual dispatch builds symbolized observer off/on twins from the same checked
out revision, retaining release optimization, fat LTO, one codegen unit,
crypto-ring and Jemalloc. It archives source/lockfiles, flags, binary hashes,
build IDs/debug files, image identities, runner CPU/kernel/boot ID, effective
Ferrum configs, per-process resource records, and all raw samples/errors.
Prerequisites include `libcurl4-openssl-dev`.

The independent manifest declares two campaigns, each with four same-host,
counterbalanced pairs and a fresh direct control per pair:

1. **Calibration:** observer-on Ferrum versus same-revision observer-off Ferrum.
2. **Profile:** observer-on Ferrum versus unchanged `kong/kong-gateway:3.10.0.0`.

Both use existing UDP 1024-byte echo, 200 offered workers, and 15-second
measurement phases. Equal offered work means the same workers, payload, and
timed closed-loop workload, not equal completed packet counts. Client socket
lifetime gauges must show 200 throughout measurement. The report keeps raw
errors/bytes/phase/process validity independent from profile completeness.
No throughput result or optimization benefit is asserted.

`udp_internal_profile.py` validates every fixed metric, schema/sample rate,
capture clock/sample sequence, `/proc` host PID/start ticks mapped to namespace
PID, unchanged processes, cumulative counter monotonicity, and measurement
brackets (at most two seconds total slack). Scrapes retain raw family text,
response hash/size, malformed/truncated data and HTTP failure status. An append
JSONL companion retains each scrape even if the sampler later fails; it is not
promoted to a complete campaign. Failed/missing repetitions stay in the full
expected matrix. All-zero lookup deltas cannot produce a profile success.
The CLI fails invalid traffic; complete-profile eligibility is a separate
explicit report field and is expected to remain false when worker tails exist.

Ordinary `experiment.json` stays disabled. H1, H2/gRPC and H3 schema/manifests
and the frozen benchmark workflow remain unchanged. Locality, burst and churn
scenarios are **not implemented**: the manifest records the required fixed or
seeded send schedule, socket creation/retirement hooks, equal offered packet
counts/rate, and observed socket lifetime requirements. Existing echo does not
exercise controlled churn or establish a prescribed cache miss rate.

## Kong provenance and session comparability

The baseline remains **`kong/kong-gateway:3.10.0.0` Enterprise**. Historical
hosted jobs [35071334026](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35071334026/job/104713326026)
and [35195212169](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35195212169/job/105116713056)
record the following index digest on x86_64 and image ID prefix `68e9b130e6bd`.
Retained registry response bodies hash to these immutable identities:

| Historical object | SHA-256 |
|---|---|
| [OCI index](https://registry-1.docker.io/v2/kong/kong-gateway/manifests/sha256:ad58cd7175a0571b1e7c226f88ade0164e5fd50b12f4da8d373e0acc82547495) | `ad58cd7175a0571b1e7c226f88ade0164e5fd50b12f4da8d373e0acc82547495` |
| [Linux amd64 manifest](https://registry-1.docker.io/v2/kong/kong-gateway/manifests/sha256:e1967ecf9db5a0a1692ea4f3feb10892b4c4ac1a7878320005add0b1180a6719) | `e1967ecf9db5a0a1692ea4f3feb10892b4c4ac1a7878320005add0b1180a6719` |
| [Config / Docker image ID](https://registry-1.docker.io/v2/kong/kong-gateway/blobs/sha256:68e9b130e6bddc7f96ef830bcfd4e27eff1def615165404bed0100389f498852) | `68e9b130e6bddc7f96ef830bcfd4e27eff1def615165404bed0100389f498852` |

The config labels declare enterprise revision
`c63eec2527a05aa87a73ee2debdb18d5bfacc9e2` in `Kong/kong-ee` and creation
`2025-03-26T03:53:44.644Z`. These are publisher assertions, not build
attestations. The [official release changelog](https://github.com/Kong/developer.konghq.com/blob/92db4e301277a62218c88d88b24e770e61f5561c/app/_changelogs/gateway.json)
declares **OpenResty 1.27.1.1**; that upstream release declares
[NGINX 1.27.1](https://github.com/openresty/openresty/blob/8c37412c31621225e7aa7e825b5b50106c9c71c4/util/ver).
These are vendor/release declarations, not yet observed executable output.

The [vendor 3.10.0.0 SBOM archive](https://packages.konghq.com/public/gateway-310/raw/versions/3.10.0.0/security-assets.tar.gz)
was 26,526,982 bytes, SHA-256
`7cf9d16417b85b265f246b694dc177063a2b30c2e4ae1122340d9c98206b875b`.
Its amd64 subject is a development image, not the production manifest. Its
package layer ID matches the production config's second uncompressed layer
ID; this is partial metadata correspondence. It inventories these useful
hosted readback targets:

| Inventoried file | SHA-256 |
|---|---|
| `/usr/local/openresty/nginx/sbin/nginx` | `a37e42bc2b09e508b76ead4f77966541de629b9308b892bca3694d179b7a7590` |
| `/usr/local/share/lua/5.1/kong/templates/nginx_kong_stream.lua` | `aaaf8b810e55587686c62be9c0bf0d53dd7e9a52d39c85346892cf976a794819` |

Do not reuse these content claims if the hosted image differs. The exact
private OpenResty/NGINX/Kong-module patchset, ordered patches, dependency
archive/commit hashes, build flags and native stream timeout implementation
remain an **external vendor provenance gap**, bound to that enterprise revision,
manifest and binary hash. Executable versions and matching file hashes alone
cannot close it. The [known public pooling correction](https://github.com/openresty/lua-nginx-module/commit/18ce5fbd58171a5faec966a5f7099ce930c812c2)
changes the HTTP Lua balancer keepalive cache; it is not UDP cause proof and
does not justify replacing the baseline.

### Bounded hosted readback

After the existing UDP readiness probe succeeds, `start_kong` runs
`kong_udp_readback.sh` against only the full CID returned by its own `docker run`,
bound to the pinned image ID. This runs before measurement in each of the four
profile pairs, with no per-packet observation or workload/config change. It
requires GitHub-hosted Linux and creates no replacement gateway. The existing
OCI metadata remains retained; the new container inspection selects identity
and state fields without dumping environment variables.

Each `pairs/pair_NNN/diagnostics/kong-readback/` contains an initial manifest,
numbered raw stdout/stderr files and per-command JSON status records, and a
final summary. The 22 fixed queries retain selected OCI identity fields,
`kong version -a`, `nginx -V`, package version/inventory, binary SHA-256, seven
allowlisted generated configs (including stream injection), and eight exact
template/runtime Lua files. The latter include Kong's handler/balancer and
`ngx/balancer.lua` timeout paths. Each text-file read has a native full-file
SHA-256 header, checked against the captured body. The manifest hashes the
capture scripts, runner, workload YAML and profile manifest as source provenance.

Each command retains at most **256 KiB**, with **2 MiB aggregate raw output per
fixture** (8 MiB across four pairs), plus bounded fixed-count JSON metadata.
The include index is capped at 128 candidates and 1024 characters per operand,
with truncation recorded separately and the raw config retained within its cap.
Docker transport has a 12-second deadline and two-second kill grace; commands
inside the container have eight seconds plus one-second grace. Thus the 22
queries have at most 308 seconds of command deadline/grace per fixture. The
reader stops after the cap plus one detection byte; the retained hash then
identifies only the prefix. Exit codes (including timeout/SIGPIPE), reader
failures, truncation, missing files, hash mismatches and interrupted/unattempted
queries remain explicit. An identity failure prevents further queries and that
arm's measurement. Other diagnostic failures stay in the ledger without
retrying or modifying traffic. Existing always-upload steps preserve partial
artifacts if the runner stops before a summary is written.

There is no `nginx -T`, directory recursion, arbitrary include following,
`.kong_env`/secret/certificate-content read, or package-inventory path execution.
The fixed config set retains the known stream includes; the summary indexes
include candidates and marks references outside the successfully captured set
as unresolved. This index is deliberately not an NGINX/Lua parser. Root must
review the raw main/stream/server config and every relevant include, resolving
unexpected includes in a subsequent bounded change if necessary. Optional
absent generated files remain failed queries, never invented empty configs.

The existing hosted `Registered collector, Kong readback and parent measurement
contracts` step checks shell syntax and discovers `test_kong_udp_readback.py`.
Contracts exercise the actual reader's byte budgets, failures/interruption,
identity binding, source-hash mismatch, stream-include gaps and fixed runner
registration. They do not substitute for the manual campaign's actual image
readback. Neither tests nor campaign were executed locally or dispatched by
this implementation.

### Interpretation remains incomplete

The existing four-pair, 200-worker, 1024-byte, one-reply echo uses persistent
**client sockets**; it does not establish persistent Kong sessions. In reference
[NGINX 1.27.1](https://github.com/nginx/nginx/blob/e06bdbd4a20912c5223d7c6c6e2b3f0d6086c928/src/stream/ngx_stream_proxy_module.c#L1806),
`proxy_requests 0` plus `proxy_responses 1` can finish a session after one echo
and drained buffers. The upstream default for responses is unlimited, not
zero; `proxy_responses 0` means no expected replies. These reference semantics
do not establish the enterprise implementation's effective values.

Review exact inherited/server `proxy_requests`, `proxy_responses`,
`proxy_timeout`, `listen ... udp reuseport`, and runtime Lua timeout overrides.
The checked-in Kong service's connect/read/write values of 5000/300000/300000 ms
do not by themselves establish the native session timeout; Ferrum's YAML has
30 seconds. Inter-packet gaps and actual session retention also remain to be
established. The report therefore retains readback evidence independently of
traffic/profile validity, with `kong_session_comparability.complete=false`,
`effective_values=null`, and no fully measured comparison eligibility for the
Kong campaign. No inherited effective value, session reuse, native source
correspondence, or causal performance finding is fabricated.

Root owns final provenance, syscall/CPU tracing, hosted dispatch, parent
integration, and any subsequent decision about optimization or tracker closure.
