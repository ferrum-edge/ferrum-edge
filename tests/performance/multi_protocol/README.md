# Multi-Protocol Performance Tests

Performance test suite that benchmarks Ferrum Edge across all supported protocols: HTTP/1.1, HTTP/1.1+TLS, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, TCP, TCP+TLS, UDP, and UDP+DTLS.

Each test runs a **three-tier setup**: `proto_bench` (load generator) &rarr; `ferrum-edge` (proxy) &rarr; `proto_backend` (echo backend), then a direct baseline without the gateway for comparison.

## Quick Start

```bash
cd tests/performance/multi_protocol

# Run a single protocol test
./run_protocol_test.sh http2

# Run all protocol tests sequentially
./run_protocol_test.sh all

# Custom parameters
./run_protocol_test.sh grpc --duration 60 --concurrency 200

# JSON output (for CI / scripting)
./run_protocol_test.sh tcp --json

# Compare Ferrum Edge vs Envoy (requires envoy in PATH)
./run_protocol_test.sh all --envoy

# Compare a single protocol against Envoy
./run_protocol_test.sh http2 --envoy --duration 30 --concurrency 200
```

## Port conflicts and cleanup ownership

`run_protocol_test.sh`, `run_gateway_protocol_bench.sh`, and
`run_connection_saturation_bench.sh` refuse to start if any of their fixed
ports (8000, 8443, and the backend/gateway/Envoy/Redis ports) is already bound,
printing the port and an `lsof` command to inspect the listener, instead of
`SIGKILL`-ing whatever is listening there. During the run, cleanup terminates
only the PIDs and Docker container IDs that run recorded — sending `SIGTERM`,
waiting a bounded interval, and then `SIGKILL` only if the process is still
alive — and removes certificates/results only when that run actually created
them. An early failure (for example, a port conflict) therefore cannot kill an
unrelated local service or another test's listeners.

## Supported Protocols

| Protocol | Client &rarr; Gateway | Gateway &rarr; Backend | Gateway Port | Backend Port |
|----------|----------------------|----------------------|--------------|--------------|
| HTTP/1.1 | HTTP (POST /echo)    | HTTP (echo)          | 8000         | 3001         |
| HTTP/1.1+TLS | HTTPS (ALPN http/1.1, POST /echo) | HTTP (echo) | 8443   | 3001         |
| HTTP/2   | HTTPS + ALPN h2 (POST /echo) | HTTPS + H2 (echo) | 8443     | 3443         |
| HTTP/3   | QUIC / HTTP3 (POST /echo) | QUIC / HTTP3 (echo) | 8443     | 3445         |
| WebSocket| ws:// upgrade        | ws://                | 8000         | 3003         |
| gRPC     | h2c (HTTP/2 clear)   | h2c                  | 8000         | 50052        |
| TCP      | raw TCP              | raw TCP              | 5010         | 3004         |
| TCP+TLS  | TLS &rarr; gateway terminates | raw TCP       | 5001         | 3004         |
| UDP      | raw UDP              | raw UDP              | 5003         | 3005         |
| UDP+DTLS | DTLS &rarr; gateway terminates | raw UDP      | 5004         | 3005         |

## Architecture

```
                ┌───────────┐         ┌───────────────┐         ┌──────────────┐
                │proto_bench│ ──────► │ferrum-edge  │ ──────► │proto_backend │
                │(load gen) │         │(reverse proxy) │         │(echo server) │
                └───────────┘         └───────────────┘         └──────────────┘
                                           │
                proto_bench ───────────────►│ (direct baseline, no gateway)
```

### proto_backend

Multi-protocol echo backend that starts all servers on fixed ports:

| Server       | Port  | Description                         |
|-------------|-------|--------------------------------------|
| HTTP/1.1    | 3001  | HTTP/1.1 with keep-alive            |
| HTTP/2 h2c  | 3002  | Cleartext HTTP/2 with prior knowledge|
| HTTPS/H2    | 3443  | HTTP/2 over TLS (ALPN negotiated)    |
| WebSocket   | 3003  | WS echo (text + binary)             |
| gRPC h2c    | 50052 | Protobuf BenchService (UnaryEcho)   |
| TCP echo    | 3004  | Bidirectional byte echo             |
| TCP+TLS     | 3444  | TLS-wrapped TCP echo                |
| UDP echo    | 3005  | Datagram echo                       |
| HTTP/3      | 3445  | QUIC/HTTP3 server                   |
| DTLS echo   | 3006  | DTLS-wrapped datagram echo          |

Self-signed TLS certificates are generated at startup into `./certs/` (gitignored).

### proto_bench

Load testing binary with subcommands for each protocol:

```
proto_bench <http1|http2|http3|ws|grpc|tcp|udp> [OPTIONS]

Options:
  --target <URL|ADDR>     Target URL or address
  --duration <SECS>       Test duration (default: 30)
  --concurrency <N>       Concurrent connections (default: 100)
  --payload-size <BYTES>  Payload for echo tests (default: 64)
  --tls                   Use TLS/DTLS for TCP/UDP tests
  --json                  Output JSON instead of text
```

## Configuration

Gateway configs are in `configs/`. Each protocol has its own YAML file that configures the appropriate `backend_scheme` and ports.

Configs that terminate or verify TLS to a backend use a `CA_PATH` placeholder for
`backend_tls_server_ca_cert_path`. `run_protocol_test.sh` rewrites it to
`certs/ca.pem` before starting the native gateway (same pattern as Envoy's
`prepare_envoy_config`). Docker benchmark scripts substitute
`/etc/ferrum/tls/ca.pem` at container mount time.

Key environment variables set by the test runner:

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `file` | File-based config |
| `FERRUM_LOG_LEVEL` | `error` | Minimize logging overhead during benchmarks |
| `FERRUM_ADD_VIA_HEADER` | `false` | Skip Via header to reduce per-request overhead |
| `FERRUM_ADD_FORWARDED_HEADER` | `false` | Skip Forwarded header construction |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | `0` | Disable request body size checking (no plugins = safe) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | `0` | Take fastest streaming path (no size limit checks) |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | `0` | Disable slowloris timer (avoids per-connection timer overhead) |
| `FERRUM_MAX_CONNECTIONS` | `0` | Disable connection semaphore (unlimited) |
| `FERRUM_MAX_HEADER_COUNT` | `0` | Disable per-request header count check |
| `FERRUM_MAX_URL_LENGTH_BYTES` | `0` | Disable per-request URL length check |
| `FERRUM_MAX_QUERY_PARAMS` | `0` | Disable per-request query param count check |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `200` | Prevent connection churn |
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Pre-establish backend connections at startup |
| `FERRUM_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |
| `FERRUM_POOL_HTTP2_*` | (tuned) | H2 flow control: 8 MiB stream, 32 MiB conn windows |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Server-side H2 stream limit |
| `FERRUM_HTTP3_*` | (tuned) | H3/QUIC: 8 MiB stream, 32 MiB conn, 8 MiB send, 1000 max streams |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | default `4` | QUIC connections per backend; override with `FERRUM_EXTRA_ENV` for experiments |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 pool idle eviction timeout |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Pool cleanup sweep interval (all pools) |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Max concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | `64` | Batched UDP recv (Linux only, falls back to try_recv_from on macOS) |

## Metrics Output

Text output (wrk-like format):

```
Running 30s test @ https://127.0.0.1:8443/api/users
  Protocol: HTTP/2
  100 concurrent connections

  Latency     Avg         Stdev       Max         +/- Stdev
              1.23ms      456.78us    12.34ms     72.31%

  Latency Distribution
     50%    1.05ms
     75%    1.45ms
     90%    2.10ms
     99%    5.80ms

  158340 requests in 30.00s, 22.45MB read
  Errors: 0

Requests/sec:  5278.00
Transfer/sec:      0.75MB
```

JSON output (`--json`):

```json
{
  "protocol": "HTTP/2",
  "target": "https://127.0.0.1:8443/api/users",
  "duration_secs": 30,
  "concurrency": 100,
  "total_requests": 158340,
  "total_errors": 0,
  "rps": 5278.0,
  "latency_avg_us": 1230,
  "latency_stdev_us": 456,
  "latency_max_us": 12340,
  "p50_us": 1050,
  "p75_us": 1450,
  "p90_us": 2100,
  "p99_us": 5800,
  "total_bytes": 23534280,
  "throughput_mbps": 6.28
}
```

## Benchmark Results

### Phases and observed concurrency (tracker #5588, section 1)

Every throughput protocol uses the same five phases:

1. **Setup:** establish all client transports, including the sequential H2,
   gRPC and H3 pools. Register workers before spawning them so setup failures
   and panics release the barrier and remain errors.
2. **Warmup:** each surviving worker sends one echo with the measured payload
   and the same strict status/body validation. Warmup work is reported separately.
3. **Measurement barrier:** wait until every surviving worker has finished its
   warmup response. Publish one common monotonic start and exclusive deadline.
4. **Measurement:** offer closed-loop requests until that deadline. Only exact,
   validated echoes completed before it enter `total_requests`, `total_bytes`,
   latency histograms and RPS. A worker error is retained even during warmup/drain.
5. **Drain:** stop new offers, finish outstanding exchanges, and join workers.
   Successful late echoes enter `drain_requests`/`drain_bytes`, never nominal
   throughput. Preflight allows 30 seconds plus one second per started 128 KiB
   of payload (70 seconds at 5 MiB), naming stalled worker IDs/states on timeout;
   the outer client kill-switch scales by the same payload allowance. Worker
   results are collected concurrently with a shared 30-second drain bound;
   completed workers remain accounted when a hung worker is aborted. Failed or
   aborted workers invalidate the sample. H3 endpoints then explicitly close
   and wait for idle, reported as `transport_close_secs` and
   `transport_close_timed_out`; a close timeout does not change echo errors.

TCP/TLS previously ran an unbounded pipelined writer. Both TCP variants now
offer one full-duplex echo per worker, using chunked writes and concurrent reads
to retain large-payload progress. This changes the TCP workload; old TCP rates
are not a paired reference for this harness. Offered work, connection topology,
payload scaling and warmup are identical for every gateway within a new pair.
The separate `saturate` command is unchanged.

Raw samples add these fields without removing the existing scalar report:

| Field | Meaning |
|-------|---------|
| `phases` | `setup_secs`, `warmup_secs`, `barrier_secs`, `measurement_secs` (nominal), `measurement_elapsed_secs` (actual), `measurement_start_unix_secs`, `client_usage`, `drain_secs`, `transport_close_secs`, `transport_close_timed_out`, `preflight_bound_secs`, `stalled_workers`, `timed_out` |
| `warmup_requests` | Validated warmup echoes, excluded from throughput |
| `drain_requests`, `drain_bytes` | Validated completions after the exclusive deadline |
| `observed.active_workers` | Sampled live workers: `min`, `max`, arithmetic sample `mean` |
| `observed.active_connections` | Sampled actual client transport lifetimes, counted by connection drivers/socket owners; UDP counts connected sockets |
| `observed.active_streams` | Sampled locally admitted exchanges still awaiting complete validation; TCP/WS/UDP count echo exchanges |
| `observed.queued_requests` | Sampled offered requests waiting for client admission |
| `observed.queue_time_ns`, `admissions` | Total client admission wait and admitted request count for measured offers (including offers admitted during drain) |
| `observed.workers_at_barrier`, `workers_retired_before_deadline` | Actual barrier participants and early retirements, including setup/warmup failures |
| `observed.samples`, `sampling_interval_ms` | Observation count and requested 10 ms cadence; scheduler delays are possible |
| `pair`, `host_id`, `gateway_order`, `order_position` | Same-host pair identity and executed order |
| `process_usage` | Client boundary CPU deltas and lifetime peak RSS; passive CPU/RSS samples for backend and gateway PIDs discovered with `docker top` |

H1/H2/gRPC admission is observed at the first request-body frame polled by the
transport; H3 uses successful stream opening. These are **client-local** streams
and queues, not server active-request counters or a measurement of kernel/QUIC
flow-control queues. `active_connections` includes idle pooled transports.
Worker/stream gauges are sampled, not exact extrema or time-weighted averages.
No requested count is substituted for an observation. `effective_concurrency`
continues to mean the **offered** worker count.

Gateway/backend process sampling uses Linux `/proc` at 500 ms. Linux hosted
runners enable it by default; `--no-process-usage`, or absent `/proc`, produces
`process_usage.available: false` and diagnostic samples that are **invalid for
paired comparison**, while allowing the runner to continue off Linux. Docker
host-network prerequisites still apply. The runner launches `proto_bench`
directly under `timeout`/`gtimeout`. A passive sampler discovers the client among
its children and never launches commands. The runner waits for sampler readiness,
then signals and reaps it after the load. The full series remains in
`diagnostics/*_process_usage.json`.

The client now calls `getrusage(RUSAGE_SELF)` at measurement publication and at
the end boundary, before drain. `phases.client_usage` carries its CPU delta,
complete bracket, measured elapsed time and process-lifetime peak RSS at that
boundary. This replaces the passive client bracket in `process_usage.measurement`,
so client exit cannot erase its ending observation. RSS is a lifetime high-water
mark, not an estimate of peak memory exclusively during measurement. The measured
elapsed duration must be between the nominal duration and nominal + max(100 ms,
5%); later coordinator wakeups invalidate the sample.

`process_usage.measurement` requires a complete bracket for **every required
role** (client/backend, plus gateway for proxied samples). Gateway/backend records
must remain observable at every sampler tick between their boundary snapshots.
A PID that was never observable remains in `missing_pids` for diagnosis without
invalidating a healthy sibling. At least one gateway PID must be observed, and
every observed gateway PID must span the measurement window; even a PID observed
once that exits mid-window invalidates the sample. PID identity includes start
time to prevent reuse from bridging a gap. Sampled records report
`boundary_slack_secs`, `bracket_secs` and sampled RSS.
Sampler-lifetime counters include setup, warmup and drain. The sampler adds
shared-runner overhead; throughput and direct ratios do not isolate proxy CPU
cost. External dependencies such as Tyk's Redis are not in gateway PID accounting.

### Paired comparison procedure

`run_gateway_protocol_bench.sh` accepts only EVEN `--pairs` counts from 2 through
12, default **2 per invocation**. Each pair includes direct and every supported
gateway, with a fresh backend per arm. Successive orders reverse; each two-pair
block rotates its first gateway. Any even count balances mean position exactly
by reversal for any number of arms; it need not visit each individual position
equally often. `position_balance.json` and the combined summary show every arm's
positions and mean. The frozen workflow's `iterations` repeats the entire suite;
its historical `--skip-direct` flag is ignored so every pair has a fresh direct
baseline. Two pairs are a budget-conscious diagnostic default (Student-t with
one degree of freedom); predeclare at least **four** pairs for performance claims
and budget that experiment separately.

For a revision experiment, make both images available on the **same hosted
runner**, pin their digests, and run, for example:

```bash
FERRUM_IMAGE=ferrum-edge@sha256:<candidate-digest> \
  bash tests/performance/multi_protocol/run_gateway_protocol_bench.sh http3 \
  --baseline-image ferrum-edge@sha256:<baseline-digest> \
  --gateways 'ferrum envoy' --payload-sizes '10240' \
  --duration 30 --pairs 6 --skip-build --output-dir results/http3/run_1
```

The reference appears as `ferrum-baseline`. Keep configuration identical except
for the stated experiment; `images.txt` records immutable image IDs and labels.
Never compare separate hosted VMs as revision pairs. Without a baseline image,
the suite compares direct/gateway and Ferrum/competitor pairs; it does **not**
claim a revision A/B. The existing frozen workflow has no baseline-image input;
revision experiments require a runner with both images provisioned separately.

`paired_comparisons.json` uses matched per-pair log throughput ratios and a
two-sided Student-t 95% interval, requiring an even count of at least two clean pairs with equal
host, payload, duration and offered concurrency. An invalid or missing pair
invalidates the comparison; no observations are dropped. Adaptive extension is
**off by default** and requires `--adaptive`. If enabled and an interval overlaps
no gain, the runner considers one extra block of the same number of pairs with
**double duration for every arm**. It projects total wall time from Bash `SECONDS`
and measured base seconds per pair: elapsed + 2 × base-pair cost × added pairs ×
1.25 + 60 seconds. It extends only within `--wallclock-budget-seconds` (default
4200, per invocation); otherwise the manifest records `extension_skipped: budget`
and the projection. Disabled/not-needed decisions are also recorded. Set this
budget to the remaining outer job allowance when calling the runner repeatedly.
If uncertainty still overlaps, report inconclusive and schedule a longer
predeclared experiment. Optional stopping does not make this exploratory interval
a confirmatory test. Inspect every sample's p99 as well as RPS.

#### Same-image environment experiments (#5588 section 4)

The runner reads the branch-committed `experiment.json` before any build or
startup. An enabled manifest adds named `ferrum-exp-*` arms for its declared protocols
when Ferrum is selected. Its first arm is the `ferrum` reference; every arm uses
the same image, configuration, startup function, payloads, offered concurrency,
phases and strict validity rules. Environment experiments vary `FERRUM_EXTRA_ENV`;
the H2 campaign below also materializes the matching route override. Values are
literal public benchmark settings, never shell source or credentials. Image
overrides, duplicate names/keys and shell syntax are rejected. Ambient
`FERRUM_EXTRA_ENV` and `--baseline-image` cannot be combined with an active
manifest. The resolved arm names enter the ordinary expected matrix and paired
comparisons; the exact experiment manifest is copied into the run artifact.
Disable the manifest after an experiment so later default runs do not silently
acquire extra arms.

The cutoff manifest is archived, disabled, at `experiments/5588-h1-cutoff.json`.
See [audit section 4](../../../docs/benchmark_audit_2026_09_17.md#section-4--same-image-http11-framing-experiment)
for the measured revision, retained raw observations and inconclusive intervals.
Copy it to `experiment.json` and commit `enabled: true` before repeating that scope.
The combined aggregate
accepts the download action's flat single-protocol layout and displays every
declared arm; ambiguous flat downloads fail instead of guessing a protocol.
The frozen per-protocol workflow summary still lists only built-in gateways;
use the raw paired files and combined aggregate for extra experiment arms.

The cutoff experiment compares `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` against
`1` at 10240, 71680, 512000, 1048576 and 5242880 bytes. A scoped hosted dispatch
uses duration 30, concurrency 200, iterations 1, skips `envoy kong tyk krakend`
and skips `http2 http3 grpcs wss tcp-tls udp udp-dtls`. The default two pairs give
30 samples (direct plus two Ferrum arms, five sizes). Orders are direct/0/1
then 1/0/direct. Estimated benchmark envelope: `2 × 15 × (30 + 15) / 60 + 5 =
27.5 minutes`, within the 75-minute step. Two pairs are exploratory and have a
wide Student-t interval; they cannot establish a general performance claim.

Passive `/proc/<pid>/io` snapshots add `rchar`, `wchar`, `syscr`, `syscw`,
`read_bytes`, `write_bytes`, and `cancelled_write_bytes`. The same measurement
bracket and slack as CPU apply. Missing, decreasing or discontinuous counters
produce `io_error`, never fabricated zeros. On hosted Linux, passwordless sudo
runs only the passive sampler so it can read container PIDs across UIDs; a stop
file terminates and reaps it. Without sudo, permission failures remain explicit.
`rchar`/`wchar` and `syscr`/`syscw` are Linux read/write accounting, **not** total
network bytes, every socket syscall, copied bytes, allocations, or TLS records.
`read_bytes`/`write_bytes` are storage I/O and may be zero for busy sockets.

H1 samples also contain `phases.h1_profile`, measured as client counter deltas
at the common boundaries. Per-worker counters avoid cross-worker atomic
contention. `tls_records` counts complete received TLS wire records below
rustls, and `tls_record_bytes` includes their five-byte headers. The parser
handles split/coalesced socket reads without retaining payloads or changing
writes/flushes. Encrypted TLS 1.3 control messages cannot be distinguished from
application records. Handshake/warmup/drain are excluded by boundary snapshots;
records and requests spanning a boundary need not share attribution. Parser
errors invalidate the **TLS profile**, even when useful-work validation passes.
`body_data_frames`/`body_data_bytes` count client Hyper response data frames,
not upstream Ferrum frames or H1 chunks. `chunked_responses` and
`content_length_responses` observe framing headers. All counters include
in-flight work at the boundary; normalize them as approximate diagnostics, not
exact per-completed-request costs. Instrumentation is identical across arms
and adds client CPU overhead. The existing full-body echo validation remains.

Allocation counts, internal copies and adapter CPU require a separate profiling
build or permitted tracing/sampling; these passive counters cannot identify
them. Do not infer a zero-copy production path or restore Content-Length from
this echo experiment. See the audit for evidence and keep/reject dispositions.

#### Maximum safe dispatch inputs (ordinary matrix)

For the full `http1-tls` matrix (direct + five gateways, five sizes), budget
`iterations × pairs × 30 × (duration + 15) / 60 + 5` minutes. This conservative
planning envelope allocates 15 seconds overhead per call and five minutes fixed
headroom; slow starts, warmups, or failures can still exceed it. Keep at least ten
minutes below the frozen 75-minute step. The frozen dispatcher cannot set pairs
or adaptive flags and therefore uses **2 pairs, adaptive off**.

| Duration × iterations × pairs | Projected minutes | Dispatch guidance |
|---|---:|---|
| 10 × 1 × 2 | 30 | Default |
| 15 × 1 × 2 | 35 | Within envelope |
| 15 × 2 × 2 | 65 | Maximum at 15 seconds |
| 5 × 3 × 2 | 65 | Maximum for three iterations |
| 15 × 3 × 2 | 95 | Unsafe; reduce iterations |
| 15 × 1 × 4 | 65 | Separately provisioned four-pair experiment |

#### Known limitations

- Measurement-start skew: watch-channel wakeups shorten individual workers'
  effective windows; barrier-parked workers count as active, so the worker gauge
  cannot reveal this skew, and longer durations reduce its relative effect.
- Passive CPU bracket slack: gateway/backend boundary samples can include up to
  roughly one sampler interval on either side (plus scheduling delay), which is
  material at five seconds; client self-snapshots remove the client exit gap but
  still expose coordinator wakeup slack.
- Mixed-duration pooling: an enabled extension pools D and 2D pairs in one
  log-ratio interval, so heteroscedasticity can change interval coverage/width
  even though both arms within each pair share their duration.
- Extension trigger rate: any uncertain reference × arm × size comparison can
  request the full-matrix extension; its real-world frequency remains unmeasured.
- Unmodelled order effects: equal mean position does not model drift or varying
  separation between compared arms; ratio noise can still vary across pairs.

### H2/gRPC transport observation campaign (#5588, section 3)

The [completed four-pair campaign](../../../docs/benchmark_h2_grpc_2026_09_18.md)
reproduces adaptive H2 and gRPC failures; the exact triggering counter and a
production repair remain unproved. Earlier hosted run
[35348523042](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35348523042)
measured `cdac4e06b09416f531935d429c1ccfeec2dad39f`, including #5598 and #5599,
with an unconditional `FERRUM_LOG_LEVEL=warn` overlay. Three H2/70 KiB samples
failed with 170/178/186 errors; one was clean. The 534 failures comprise 417
body errors, 115 HTTP 502s and two send errors. Their displayed H2 reason does
not prove the originating hop, GOAWAY versus RST, initiator, or flood subtype.
The four clean native gRPC samples at each measured size do not resolve the
historical 10/70 KiB failures. The later `d302bfb05` refusal-body snippet and
`0aaa56b9a` WS send-error diagnostic were **not measured** by that run. The old
overlay and its duplicate parser are removed; its artifact provenance remains
part of this history.

`experiment.json` is disabled after preserving the campaign results. To
reproduce the controlled observation on a diagnostic branch, explicitly enable
that manifest and use the existing
`gateways-protocol-benchmark.yml` dispatch inputs:

| Input | Exact value |
|---|---|
| `duration` | `15` |
| `concurrency` | `200` |
| `iterations` | `1` |
| `skip_gateways` | `envoy kong tyk krakend` |
| `skip_protocols` | `http1-tls http3 wss tcp-tls udp udp-dtls` |
| `skip_payload_sizes` | `512000 1048576 5242880` |

The validated campaign selects **four pairs**, overriding the ordinary two-pair
default, and narrows H2 to **71680 bytes**, while native gRPC retains **10240 and
71680 bytes**. It rejects changed duration/concurrency, omitted required sizes,
extra gateways, ambient environment overlays, revision-baseline images and
adaptive duration extension. Each pair includes direct, `ferrum` (adaptive on)
and `ferrum-exp-fixed` (adaptive off); the existing rotated/reversed order is
recorded in `position_balance.json`. There are 12 H2 and 24 gRPC observations.
All arms of each protocol use the same image and hosted VM, with a fresh backend
per arm and repeated direct controls. The workflow uses separate VMs for H2 and
gRPC: **cross-protocol rates are not paired**. A conservative envelope is about
11 minutes for H2 and 17 for gRPC, excluding image/build time; the existing
4200-second harness budget and 75-minute workflow step remain in force.

For each Ferrum arm, `diagnostics/<arm>_config.yaml` is the actual mounted route
file. Materialization requires exactly the expected window/frame/stream and
keepalive fields, changes its explicit `pool_http2_adaptive_window` value, and
reads the result back. An environment-only flag cannot override the route YAML.
`manifest.json.effective_h2_arms` records the route SHA-256, exact arm environment
and effective builder inputs. The runner pins the resolved image ID, verifies
the running containers' relevant environment (including absence of a shadowing
`RUST_LOG`) and records their image IDs; `images.txt` also retains image identity. The route
files differ only in the adaptive flag. Both retain 5/30/30-second backend
connect/read/write timeouts, 8/32 MiB configured window inputs, 1 MiB maximum
frames, 1000 streams and configured pool width 16. Adaptive-on resets Hyper's
initial windows to 65,535 bytes; fixed retains 8/32 MiB. These are derived builder
settings verified against the pinned source and generated inputs, **not observed
negotiated windows**. The client's and echo backend's window settings are held
constant. No admission, pool scheduling, flood/reset protection, retry, response
buffering, timeout, status/body/trailer or offered-concurrency policy is varied.

H2 observations require `--ca-cert`, enabling CA and server-name verification
equally for direct and both Ferrum arms. This tightens the historical H2 client's
insecure verifier, so old/new rates are not a controlled comparison. Native
gRPC keeps its CA/localhost SNI verification and 8 MiB message limits. Exact
HTTP 200/body equality and tonic's status/trailer processing plus exact protobuf
payload equality remain mandatory. A clean RPC is not an independent wire
trailer audit.

The campaign supplies `--h2-observe` to each client and `BENCH_H2_OBSERVE=1` to
the benchmark backend. Events extend #5601's `TransportEvent` and `PhaseReport`:
monotonic process-relative timestamps, actual coordinator boundaries for setup,
warmup, measurement, drain and transport close, operation, worker, channel and
physical connection identity. `connection_id=0` means unknown. gRPC attributes
an RPC error to a nonzero physical socket only when the same association is
present before and after the RPC. Every connector attempt invalidates it before
the connect future is polled; failed or cancelled attempts leave it unknown.
Only the latest attempt can publish a successful connection, and dropping an
older socket cannot clear a newer identity. Socket retirement clears its own
current association. Channel IDs remain available independently. This observes
TCP socket ownership, not a per-stream wire ID or proof of TLS/H2 readiness;
Tonic still owns those handshakes and its detached driver. An RPC spanning a
reconnect or retirement is conservatively unknown even if it used the old
socket. Client H2 driver results are joined after worker drain with a
five-second **observation** bound. This is not proof of graceful H2 close.
Tonic hides its detached driver results; its socket-drop events do not certify
close correctness, and events after the final snapshot are not captured.

Typed `h2::Error` sources provide numeric reason, `goaway`/`reset`/`io`/`other`
and `remote`/`local_library`/`local_user`/`unknown` where the API preserves them.
A bare reason never implies a frame type or initiator. Client storage is capped
at 512 events per sample; source chains at eight entries and 2048 escaped bytes.
Counters (`total_errors`, `transport_errors_total`, `transport_events_total`,
`transport_events_suppressed`) remain independent of retained event count. Backend
H2 listeners each cap at 512 lifetime events and emit a limit marker. Their
`H2_TRANSPORT` records reuse the same event representation; sample attribution
uses client wall-clock boundaries and is explicitly marked as cross-process
correlation with unmeasured clock skew. Raw cumulative backend/gateway logs are
retained: do not sum repeated payload snapshots as new events.

Existing gateway driver logs hide typed causes behind generic Hyper Display
text. A narrow diagnostic at those existing termination sites is enabled with
`FERRUM_LOG_LEVEL=warn,ferrum_h2_observe=debug`, identically in both arms. Its
fixed-cardinality hop/reason/kind/initiator fields include process-local driver
identity, monotonic time and lifetime. It emits at most 512 terminal records per
gateway lifetime, with a limit marker on the last. It never renders error text,
GOAWAY debug bytes, peer addresses, pool keys, headers, bodies or credentials.
Ordinary warn/error production logging is unchanged. Frontend auto-driver
records can include H1/readiness traffic and forced handler retirement; `ok`
does not assert graceful transport closure. No whole-protocol debug/trace filter
is enabled. Connection IDs are local to each process, not cross-hop correlation
tokens; gateway events have wall-clock timing but no invented client phase.

At 500 ms, the existing passive sampler also reads allowlisted gauges from
loopback-authenticated `/metrics`. The raw measured samples distinguish resident
H2/gRPC pool entries and frontend active connections/requests from configured
shards. Missing, malformed or inaccessible gauges are reported, never zero-filled.
Resident pool entries include idle transports; neither they nor client-local
active-stream gauges prove per-backend stream occupancy or 200/16 multiplexing.
Scrape overhead is equal between the two Ferrum arms, but direct ratios still
include shared-host client/backend and observer cost.

Failures stay in raw samples, stderr and cumulative logs. The existing paired
validator rejects a comparison if any declared repetition is missing or invalid;
the campaign also rejects missing gauge observations, incomplete diagnostic
capture, client/backend event-log truncation, captured client/backend transport
errors or an incomplete H2 driver observation. Inspect every repetition, including
warmup/drain failures and clean controls; bounded logs or zero observed events
are not proof of zero transport faults. Do not average surviving workers into a
performance win. The [recorded hosted campaign](../../../docs/benchmark_h2_grpc_2026_09_18.md)
reproduces adaptive H2 and gRPC failures and rejects a throughput-win claim.
The manifest is disabled after that campaign. Further diagnosis must compare
failure reasons and observed occupancy between the two effective settings.
The H2 backend log identifies `too_many_data_frames`; the gRPC debug subtype,
DATA-length/END_STREAM distributions, per-backend active streams, tonic backend
driver results and exact cross-hop identity remain gaps. Add narrower observation
only if the captured reasons require it; no production fix is justified here.

Hosted `Benchmark Harness Tests` reaches regression cases for typed remote
GOAWAY/RST distinction, cyclic/large error chains, log suppression independent
of counts, monotonic phase attribution, gRPC connector cancellation/failure,
out-of-order cloned connect futures, older socket retirement, cancellation
during Tonic TLS negotiation and a real Tonic RPC after transport loss and
refused reconnect (Linux), effective route
materialization, gauge failure handling and rejection of a failed paired
repetition. Connector tests use leased loopback sockets and explicit lifecycle
signals under a five-second async deadline. Local execution
was prohibited for this change; hosted compilation/tests and root's independent
artifact audit remain required before drawing conclusions.

### HTTP/3 transport experiment (#5588, section 2)

`h3_experiment.json` enables the hosted experiment without changing the frozen
matrix job. `H3_EXPERIMENT_MANIFEST` can select another data manifest; setting
`enabled: false` disables it. With Envoy selected, the runner adds
`envoy-limit-4` to the same counterbalanced pairs as `envoy` (limit 100), Ferrum,
and direct. Both Envoy arms retain pinned 1.33.5, SNI `localhost`, CA validation,
windows, timeouts, and strict HTTP 200/exact-body validation. Generated configs,
image IDs/digests, the experiment manifest, and host socket settings are artifacts.

| Offered workers | Client QUIC connections | Limit 4 admission ceiling | Limit 100 ceiling |
|---:|---:|---:|---:|
| 200 | 21 | 84 | 200 |
| 100 | 11 | 44 | 100 |
| 50 | 6 | 24 | 50 |

These are downstream ceilings from the fixed round-robin worker assignment;
`observed.active_streams` reports client admission during load. The experiment
changes the upstream and downstream limits together. The backend's timestamped
`H3_PROFILE` records show upstream connection
IDs, peer ports, accepted/completed echoes and bytes. Per-connection measurement
deltas and per-thread CPU brackets accompany each sample. They include sampling
slack; neither identifies which Envoy thread owns an individual UDP socket.

The downstream limit is applied to
`udp_listener_config.quic_options.quic_protocol_options`, which constructs the
QUIC transport. Changing only the similarly named HCM options did **not** cap
downstream admission in the first hosted experiment: all 200/100/50 streams
remained admitted. Compare the observed queues and locally active exchanges
with the transport ceiling: local validation can outlive transport stream
closure, so the local gauge is not an exact server stream count. Previous
claims that the historical HCM setting necessarily admitted
only 84/44/24 streams were incorrect.

H3 waits 750 ms at the ready barrier and after worker drain, identically for all
arms, to bracket fast client and upstream sockets with the passive sampler.
The former is `barrier_secs`, the latter `observation_hold_secs`; neither time
enters measured throughput. Envoy histogram records are retained separately
from its named scalar counters. The aggregate accepts the single-artifact flat
layout as well as multiple artifact directories; missing runs fail explicitly.

The enabled experiment requires a disposable Linux runner with passwordless
`sudo sysctl`. It sets `rmem_default`, `wmem_default`, `rmem_max`, and `wmem_max`
before any arm to 4,194,304 bytes. Ferrum/Quinn inherit the defaults; Envoy uses
explicit downstream and upstream `SO_RCVBUF`/`SO_SNDBUF` requests of 2,097,152
bytes because Linux doubles explicit requests. Equal **effective per-socket**
budgets must be observed before a sample is accepted. This does not equalize the
number of sockets or total gateway memory. No production config knob is added.

The existing passive 500 ms sampler now also reads `/proc/net/snmp`,
`/proc/net/udp{,6}`, thread stat files, and `NETLINK_SOCK_DIAG` for this experiment.
`INET_DIAG_SKMEMINFO` gives the same kernel receive/send limits as `getsockopt`,
verified against a live UDP socket in hosted tests. Socket cookies prevent inode
reuse from producing false deltas. The sampler neither executes commands nor
injects descriptors into another process. Kernel UDP deltas cover the shared
host namespace; socket deltas are narrower. The backend peer port identifies
upstream sockets, including unconnected Quinn endpoints. Missing observations,
counter resets, incomplete brackets, and unverified buffer parity stay explicit.

Envoy stats are sampled via its loopback admin endpoint and retained in full.
Pinned 1.33.5 repeatedly adds cumulative `SO_RXQ_OVFL` values; its reported drops
are **not loss totals** ([upstream correction #38652](https://github.com/envoyproxy/envoy/pull/38652)).
Use independent kernel/socket deltas. `TOO_MANY_RTOS`, idle-close, and watchdog
counters remain raw, timestamped observations. Both gateways use info logging;
startup and per-payload logs have Docker timestamps, exposing BPF/GRO/GSO
warnings. No warning is not positive proof of an optimized path: record
unsupported/unverified unless logs or other observations positively establish it.

H3 endpoints close explicitly after worker drain under one shared five-second
deadline, and all drivers are joined or aborted/reaped. `phases.transport_events`
retains connection IDs, UNIX timestamps, raw closure reasons and final Quinn
stats, labelled setup/warmup, measurement, drain, or transport close. Timestamped
server counters between payloads distinguish retired connections from measured
failures; do not infer request loss merely from a post-measurement closure.

For the scoped hosted run use duration 10, concurrency 200, iterations 1, skip
protocols `http1-tls http2 grpcs wss tcp-tls udp udp-dtls`, skip gateways
`kong tyk krakend`, and skip sizes `71680 512000`. The runner defaults to two
pairs: 24 samples across four arms and three sizes. Adaptive extension is off;
two-pair intervals are diagnostic, not a confirmatory performance claim.

Raw JSON lives under `pairs/pair_NNN/`. Root `<gateway>_<protocol>_<size>.json`
keeps the legacy totals/rate fields and adds `samples` plus `expected_pairs`.
Rates use total measured requests / total measured seconds; summary latency
quantiles are the maximum per-sample quantiles, explicitly labelled, because
quantiles cannot be pooled without histograms. All constituent observations are
validated. The rolling regression evaluator restarts its window when
`protocol_perf_budgets.json.workload_revision` changes, excluding missing/older
markers; this revision is `2026-09-18.h1-h3-observation.v3`, accounting for H1
frame/header/TLS observation overhead and H3 observation holds and explicit
retirement instrumentation. The historical
H1 paired-ratio reference remains unchanged. The
combined artifact also contains flattened `observed-samples.json` and
`paired-comparisons.json`; use those or the raw samples for analysis. The frozen
matrix summary remains diagnostic; the aggregate job reports paired intervals.

Hosted `Benchmark Harness Tests` runs the phase/worker/admission tests in
`tests/metrics_tests.rs` and the Python ordering, pairing, aggregation, resource
parser and validity tests. No matrix-job workflow changes are needed.

For the September 2026 multi-gateway investigation, see the
[benchmark audit](../../../docs/benchmark_audit_2026_09_17.md). The gateway
workflow's **combined** summary now reports validity across every iteration:
errors, zero successful work, missing iterations, or inconsistent echo byte
totals exclude a scenario from the scoreboard. Raw rates remain diagnostic.
Each run records its expected matrix before startup (`manifest.json`) and saves
backend/gateway logs plus Envoy counters under `diagnostics/` after the timed
samples. If that manifest is missing or malformed, ranking is suppressed for
the affected protocol while observed rows remain available for diagnosis. A
green workflow alone does not certify an error-free benchmark; inspect the
validity tables.

The per-protocol summary rendered inside the matrix job still shows raw
throughput only. `Trusted Cross Build Policy` freezes that job's bytes against
the trusted base, so a pull request cannot add the validity table (or a test
step) there; read the combined summary, or the rules below, for validity.

Validity rules live in `benchmark_validity.py` so the workflow and these checks
share one definition. This package is not a workspace member, so the workspace
`Tests` aggregate never builds it; the **Benchmark Harness Tests** workflow
(`.github/workflows/benchmark-harness-tests.yml`) is the hosted lane that runs
these tests, on every pull request and `main` push touching
`tests/performance/**`. It is not a branch-protection-required
check. It also runs a static contract
(`tests/test_benchmark_runner_cleanup.py`) that fails if any benchmark runner
or its invoking workflow still contains a port-wide `SIGKILL` idiom. The same
two commands run locally:

```bash
python3 -m unittest discover -s tests/performance/multi_protocol/tests -p 'test_*.py'
cargo test --manifest-path tests/performance/multi_protocol/Cargo.toml --test metrics_tests
```

**Date**: 2026-04-12
**Environment**: macOS Darwin 25.4.0, Apple Silicon
**Duration**: 10s per test, 200 concurrent connections
**Payload**: 10 KB echo (POST with body, backend echoes full payload) for HTTP, H2, H3, WebSocket, gRPC, TCP, TCP+TLS; 2 KB for UDP, UDP+DTLS
**Build**: Release build with native H3 backend dispatch (h3+quinn replacing reqwest for HTTP/3 backend, unified H3 frontend with main proxy dispatch)

### Through Gateway (client → gateway → backend)

| Protocol | Payload | Requests/sec | Avg Latency | P50 | P99 | Max | Errors |
|----------|---------|-------------|-------------|------|------|------|--------|
| HTTP/1.1 | 10 KB | 87,702 | 2.28ms | 2.18ms | 4.65ms | 36.51ms | 0 |
| HTTP/1.1+TLS | 10 KB | 76,041 | 2.62ms | 2.51ms | 5.34ms | 58.56ms | 0 |
| HTTP/2 (TLS) | 10 KB | 28,671 | 6.97ms | 6.80ms | 11.89ms | 33.28ms | 0 |
| HTTP/3 (QUIC) | 10 KB | 6,216 | 32.17ms | 34.24ms | 79.10ms | 3.04s | 0 |
| WebSocket | 10 KB | 98,709 | 2.02ms | 1.98ms | 3.31ms | 34.27ms | 0 |
| gRPC | 10 KB | 26,358 | 7.58ms | 7.50ms | 12.89ms | 38.37ms | 0 |
| TCP | 10 KB | 91,550 | 2.18ms | 2.16ms | 2.67ms | 13.49ms | 0 |
| TCP+TLS | 10 KB | 86,294 | 2.31ms | 2.29ms | 3.18ms | 26.59ms | 0 |
| UDP | 2 KB | 81,353 | 2.46ms | 2.48ms | 2.95ms | 13.56ms | 0 |
| UDP+DTLS | 2 KB | 76,067 | 2.61ms | 2.34ms | 7.03ms | 201.73ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Payload | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|---------|-------------|-------------|------|------|------|
| HTTP/1.1 | 10 KB | 200,268 | 996μs | 972μs | 2.00ms | 47.30ms |
| HTTP/1.1+TLS | 10 KB | 200,126* | 997μs | 973μs | 1.99ms | 28.67ms |
| HTTP/2 (TLS) | 10 KB | 145,204 | 1.38ms | 1.17ms | 4.75ms | 131.33ms |
| HTTP/3 (QUIC) | 10 KB | 5,008 | 39.97ms | 37.34ms | 88.58ms | 144.38ms |
| WebSocket | 10 KB | 187,129 | 1.07ms | 1.04ms | 2.15ms | 34.27ms |
| gRPC | 10 KB | 111,337 | 1.79ms | 1.53ms | 6.13ms | 125.31ms |
| TCP | 10 KB | 180,514 | 1.11ms | 1.08ms | 1.47ms | 8.58ms |
| TCP+TLS | 10 KB | 146,955 | 1.36ms | 1.29ms | 3.03ms | 40.64ms |
| UDP | 2 KB | 254,386 | 785μs | 730μs | 1.46ms | 13.87ms |
| UDP+DTLS | 2 KB | 109,130 | 1.82ms | 1.84ms | 2.41ms | 22.11ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 87,702 | 200,268 | ~56% | reqwest connection pool with keep-alive, 10 KB echo |
| HTTP/1.1+TLS | 76,041 | 200,126 | ~62% | TLS termination + 10 KB body crypto overhead |
| HTTP/2 (TLS) | 28,671 | 145,204 | ~80% | H2 multiplexing with 10 KB framed bodies |
| HTTP/3 (QUIC) | 6,216 | 5,008 | +24%‡ | Native h3+quinn; gateway faster than direct backend |
| WebSocket | 98,709 | 187,129 | ~47% | Tunnel mode (raw TCP copy, no frame parsing) |
| gRPC | 26,358 | 111,337 | ~76% | H2 multiplexing + protobuf passthrough, 10 KB payload |
| TCP | 91,550 | 180,514 | ~49% | Bidirectional copy with adaptive buffer sizing |
| TCP+TLS | 86,294 | 146,955 | ~41% | TLS termination + bidirectional copy |
| UDP | 81,353 | 254,386 | ~68% | Per-datagram session lookup + forwarding, 2 KB |
| UDP+DTLS | 76,067 | 109,130 | ~30% | DTLS termination + plain UDP forwarding, 2 KB |

‡*HTTP/3 gateway outperforming the direct backend is an artifact of the h3-quinn echo server being CPU-bound at 10 KB × 200 concurrency — the direct backend bottlenecks on QUIC crypto overhead.*

### Impact of 10 KB Payloads vs Prior 64-Byte Results

Prior results used GET requests to a fixed JSON endpoint (no request body, ~60-byte response). Current results use POST with 10 KB request body echoed back (10 KB response). UDP uses 2 KB payloads in both runs.

| Protocol | 64B RPS (prior) | 10KB RPS (current) | Delta | Notes |
|----------|----------------|-------------------|-------|-------|
| HTTP/1.1 | 97,179 | 87,702 | -9.8% | Body copy + larger transfer overhead |
| HTTP/1.1+TLS | 97,765 | 76,041 | -22.2% | TLS encryption of 10 KB body is significant |
| HTTP/2 (TLS) | 57,257 | 28,671 | -49.9% | H2 framing + flow control scales with body size |
| HTTP/3 (QUIC) | 7,534 | 6,216 | -17.5% | Already slow; QUIC crypto adds proportional overhead |
| WebSocket | 103,404 | 98,709 | -4.5% | Tunnel mode — minimal frame overhead with larger payload |
| gRPC | 34,564 | 26,358 | -23.7% | Protobuf serialization + H2 framing for larger payloads |
| TCP | 104,609 | 91,550 | -12.5% | Larger buffer copies |
| TCP+TLS | 105,519 | 86,294 | -18.2% | TLS encryption of 10 KB chunks |
| UDP | 81,166 | 81,353 | +0.2% | 2 KB payload in both; within run-to-run variance |

> **Key insight — payload size reveals true protocol cost**: With 64-byte payloads, per-request framing overhead dominates and all protocols look similar. With 10 KB payloads, the cost of body encryption (TLS/QUIC), H2/H3 framing, and serialization becomes visible. WebSocket tunnel mode and raw TCP show the smallest payload-size penalty because they bypass frame parsing. HTTP/2 shows the largest penalty (-50%) because H2 flow control and framing scale poorly with body size at high concurrency.

> **HTTP/3 remains regressed**: The native h3+quinn backend dispatch (#349) continues to show poor throughput (6,216 RPS via gateway). The prior reqwest-backed path auto-negotiated HTTP/2 via ALPN which outperformed native QUIC. This confirms the CLAUDE.md warning: "Don't replace reqwest with H3 pool for HTTP/3 frontend→backend."

> **Note:** Benchmark numbers vary between runs due to system load, thermal
> throttling, and background processes. Focus on the overhead ratios and relative
> comparisons rather than absolute RPS numbers.

## Envoy Comparison Mode

The `--envoy` flag runs each protocol benchmark through both Ferrum Edge and Envoy (native binary), using the **same backend, same load generator, same ports** — a true apples-to-apples comparison.

```bash
# Compare all supported protocols
./run_protocol_test.sh all --envoy --duration 30 --concurrency 200

# Compare a single protocol
./run_protocol_test.sh grpc --envoy
```

### How It Works

For each protocol, the runner:

1. Starts Ferrum Edge with its config, runs `proto_bench`, captures JSON results, stops Ferrum
2. Starts Envoy with an equivalent config, runs `proto_bench`, captures JSON results, stops Envoy
3. Runs the direct-backend baseline (same for both)
4. After all protocols, prints a comparison table

Both gateways run natively (no Docker), bind the same ports (sequentially), and connect to the same `proto_backend` echo server.

### Envoy-Compared Protocols

| Protocol | Envoy Config | Notes |
|----------|-------------|-------|
| HTTP/1.1 | `configs/envoy/http1.yaml` | `http_connection_manager` with `codec_type: HTTP1` |
| HTTP/1.1+TLS | `configs/envoy/http1_tls.yaml` | Downstream TLS termination, plain HTTP to backend |
| WebSocket | `configs/envoy/ws.yaml` | `upgrade_configs: websocket` on HCM |
| gRPC | `configs/envoy/grpc.yaml` | h2c (cleartext HTTP/2) on both sides |
| TCP | `configs/envoy/tcp.yaml` | `tcp_proxy` network filter |
| TCP+TLS | `configs/envoy/tcp_tls.yaml` | Downstream TLS + `tcp_proxy` |
| UDP | `configs/envoy/udp.yaml` | `udp_proxy` listener filter with matcher-based routing |

**Skipped protocols:**
- **HTTP/2** — hyper's raw h2c client gets `ConnectionReset` from Envoy on macOS (known h2c compatibility issue); gRPC already covers HTTP/2 semantics via tonic which works fine
- **HTTP/3 (QUIC)** — Envoy's QUIC support requires a special build with BoringSSL
- **UDP+DTLS** — No native Envoy DTLS termination

### Envoy Tuning

Envoy configs are tuned to match Ferrum Edge where applicable:

- HTTP/2 flow control: 8 MiB stream window, 32 MiB connection window, 1000 max concurrent streams
- Access logging disabled (`access_log: []`)
- Log level: `error` (`-l error`)
- Worker threads: auto (`--concurrency auto`, matches CPU cores)
- Admin interface on port 15000 (not benchmarked)

### Sample Comparison Output

Results from a prior local run on macOS (Apple Silicon M4 Max), 10s duration, 200 concurrent connections, 64-byte payload (pre-echo refactor), Envoy 1.37.1.

```
=========================================================================================================
  Ferrum Edge vs Envoy — Through-Gateway Comparison
  Duration: 10s | Concurrency: 200 | Payload: 64 bytes
=========================================================================================================

| Protocol       |   Ferrum RPS |    Envoy RPS |    Δ RPS |  Winner |  Ferrum P50 |   Envoy P50 |  Ferrum P99 |   Envoy P99 |  Ferrum Avg |   Envoy Avg |
|----------------|--------------|--------------|----------|---------|-------------|-------------|-------------|-------------|-------------|-------------|
| http1          |       96,623 |       92,766 |    +4.2% |  Ferrum |      1.97ms |      1.64ms |      4.36ms |     14.40ms |      2.07ms |      2.25ms |
| http1-tls      |      101,445 |       95,403 |    +6.3% |  Ferrum |      1.90ms |      1.68ms |      3.83ms |     13.56ms |      1.97ms |      2.20ms |
| ws             |      106,788 |      106,781 |    +0.0% |   ~tie  |      1.85ms |      1.48ms |      2.60ms |      6.72ms |      1.87ms |      1.89ms |
| grpc           |       37,920 |       81,798 |   -53.6% |  Envoy  |      5.24ms |      1.19ms |      8.07ms |     25.20ms |      5.27ms |      2.96ms |
| tcp            |      107,097 |      106,779 |    +0.3% |   ~tie  |      1.85ms |      1.44ms |      2.53ms |      4.72ms |      1.86ms |      1.89ms |
| tcp-tls        |      106,404 |      105,858 |    +0.5% |   ~tie  |      1.85ms |      1.43ms |      2.64ms |      7.00ms |      1.88ms |      1.91ms |
| udp            |       82,734 |      135,843 |   -39.1% |  Envoy  |      2.43ms |      1.45ms |      2.88ms |      2.17ms |      2.42ms |      1.55ms |

======================================================================
  Gateway Overhead vs Direct Backend
======================================================================

| Protocol       |   Direct RPS |   Ferrum RPS |  Ferrum OH |    Envoy RPS |   Envoy OH |
|----------------|--------------|--------------|------------|--------------|------------|
| http1          |      207,867 |       96,623 |       ~53% |       92,766 |       ~55% |
| http1-tls      |      207,308 |      101,445 |       ~51% |       95,403 |       ~54% |
| ws             |      205,168 |      106,788 |       ~48% |      106,781 |       ~48% |
| grpc           |      211,749 |       37,920 |       ~82% |       81,798 |       ~61% |
| tcp            |      208,072 |      107,097 |       ~48% |      106,779 |       ~49% |
| tcp-tls        |      204,016 |      106,404 |       ~48% |      105,858 |       ~48% |
| udp            |      281,766 |       82,734 |       ~71% |      135,843 |       ~52% |
```

### Ferrum Edge vs Envoy 1.37.1

| Protocol | Ferrum RPS | Envoy RPS | Δ RPS | Winner | Ferrum P99 | Envoy P99 |
|----------|-----------|-----------|-------|--------|-----------|-----------|
| HTTP/1.1 | 96,623 | 92,766 | +4.2% | Ferrum | 4.36ms | 14.40ms |
| HTTP/1.1+TLS | 101,445 | 95,403 | +6.3% | Ferrum | 3.83ms | 13.56ms |
| WebSocket | 106,788 | 106,781 | +0.0% | ~tie | 2.60ms | 6.72ms |
| gRPC | 37,920 | 81,798 | -53.6% | Envoy | 8.07ms | 25.20ms |
| TCP | 107,097 | 106,779 | +0.3% | ~tie | 2.53ms | 4.72ms |
| TCP+TLS | 106,404 | 105,858 | +0.5% | ~tie | 2.64ms | 7.00ms |
| UDP | 82,734 | 135,843 | -39.1% | Envoy | 2.88ms | 2.17ms |

> **Note:** HTTP/2, HTTP/3, and UDP+DTLS are omitted from the Envoy comparison:
> HTTP/2 (hyper h2c client incompatible with Envoy on macOS — gRPC covers H2 semantics),
> HTTP/3/UDP+DTLS (no standard Envoy equivalent).

### Analysis

**Where Ferrum Edge wins:**

1. **HTTP/1.1 (+4.2%)** — Ferrum beats Envoy on raw throughput with significantly better P99 tail latency (4.36ms vs 14.40ms — 3.3× better). The reqwest connection pool with keep-alive, response body coalescing, and frequency-aware router cache provide consistent performance.

2. **HTTP/1.1+TLS (+6.3%)** — Ferrum's largest advantage. TLS termination via rustls outperforms Envoy's BoringSSL at this concurrency level, with P99 of 3.83ms vs 13.56ms (3.5× better). This confirms rustls is highly competitive for TLS proxy workloads.

3. **TCP (~tie, +0.3%)** — Near-identical throughput with bidirectional `copy_bidirectional` and adaptive buffer sizing. On Linux, `splice(2)` zero-copy relay further reduces CPU overhead for plaintext TCP paths. Ferrum's P99 is 1.9× better (2.53ms vs 4.72ms).

4. **TCP+TLS (~tie, +0.5%)** — TLS termination + raw TCP proxying is effectively tied on throughput, with Ferrum again showing 2.7× better P99 (2.64ms vs 7.00ms).

5. **WebSocket (~tie, +0.0%)** — Tunnel mode (raw TCP copy with no frame parsing) matches Envoy's WebSocket proxying. Ferrum's P99 is 2.6× better (2.60ms vs 6.72ms).

**Where Envoy wins:**

1. **gRPC (-53.6%)** — Envoy's largest advantage. Envoy's native HTTP/2 codec (C++ with writev scatter-gather I/O) achieves 82K RPS vs Ferrum's 38K RPS for small (64-byte) gRPC payloads. However, Ferrum's P99 is 3.1× better (8.07ms vs 25.20ms), meaning Ferrum delivers more predictable latency despite lower peak throughput. As payload size increases (see `tests/performance/payload_size/`), Ferrum's H2 response coalescing closes the gap and wins at 10KB+ payloads.

2. **UDP (-39.1%)** — Envoy uses GRO (Generic Receive Offload) to batch UDP datagrams at the kernel level. Ferrum's `recvmmsg(2)` batching is Linux-only; on macOS it falls back to per-datagram `try_recv_from`. Re-benchmark on Linux where `FERRUM_UDP_RECVMMSG_BATCH_SIZE=64` enables batched recv to close this gap.

**P99 tail latency — Ferrum's consistent advantage:**

Across every protocol where both proxies are compared, Ferrum delivers **1.9-3.5× better P99 tail latency**:

| Protocol | Ferrum P99 | Envoy P99 | Ratio |
|----------|-----------|-----------|-------|
| HTTP/1.1 | 4.36ms | 14.40ms | 3.3× better |
| HTTP/1.1+TLS | 3.83ms | 13.56ms | 3.5× better |
| WebSocket | 2.60ms | 6.72ms | 2.6× better |
| gRPC | 8.07ms | 25.20ms | 3.1× better |
| TCP | 2.53ms | 4.72ms | 1.9× better |
| TCP+TLS | 2.64ms | 7.00ms | 2.7× better |
| UDP | 2.88ms | 2.17ms | 0.8× (Envoy better) |

This means Ferrum provides more predictable latency under load — critical for SLA-sensitive traffic where P99 matters more than peak throughput.

## Prerequisites

- **Rust toolchain** (cargo, rustc)
- **protoc** (protobuf compiler) for gRPC support
- **Envoy** (optional, for `--envoy` comparison mode)
- The following ports must be free: 3001-3006, 3010, 3443-3445, 5001, 5003-5004, 5010, 8000, 8443, 50052
- Port 15000 must also be free when using `--envoy` (Envoy admin)

Install dependencies:
```bash
# macOS
brew install protobuf
brew install envoy   # optional, for --envoy mode

# Ubuntu/Debian
sudo apt-get install protobuf-compiler
# See https://www.envoyproxy.io/docs/envoy/latest/start/install for Envoy
```

## Adding a New Protocol Test

1. Add a backend server in `proto_backend.rs`
2. Add a load generator subcommand in `proto_bench.rs`
3. Create a gateway config in `configs/<protocol>_perf.yaml`
4. Add `test_<protocol>()` and `stop_gateway` call in `run_protocol_test.sh`
5. (Optional) Add an Envoy config in `configs/envoy/<protocol>.yaml` and register in `envoy_compare_protocol()`

## Connection Saturation Benchmark

A separate benchmark mode that finds the **breaking point** — the smallest N at which a gateway can no longer sustain N concurrent long-lived connections — for ferrum-edge, envoy, kong, tyk, and krakend. Distinct from the throughput benchmark above: that one fixes concurrency at 100 and measures RPS; this one ramps concurrency until the gateway falls over.

```bash
cd tests/performance/multi_protocol

# Run all five gateways at default ramp (1K → 5K → 10K → 25K → 50K)
./run_connection_saturation_bench.sh

# Subset
./run_connection_saturation_bench.sh \
    --gateways "ferrum envoy" \
    --connection-levels "1000 5000 10000"

# Stop ramping a gateway as soon as it breaks (faster overall run)
./run_connection_saturation_bench.sh --stop-at-first-break
```

In CI, this runs as the on-demand `Connection Saturation Benchmark` workflow (`.github/workflows/connection-saturation-benchmark.yml`) — that path applies the host-level sysctl/ulimit tuning required for the headline numbers.

### What "breaking point" means here

`proto_bench saturate --connections N` opens N HTTP/1.1+TLS keep-alive connections to the gateway, ramps them up over `--ramp-seconds`, and holds them open for `--hold-seconds` while each connection sends one tiny POST `/echo` per `--heartbeat-interval-ms`. A run is **`ok`** only if all four of:

- `connect_success_rate ≥ 99%`,
- `heartbeat_success_rate ≥ 99%`,
- `peak_alive_connections ≥ 99% × N`, and
- `survivorship_rate ≥ 99%` — i.e., ≥99% of connections that established also lasted the entire hold window without being dropped.

are true. Otherwise it's **`broken`**. The runner script ramps N upward and records the largest `ok` and the smallest `broken`. The survivorship gate is what catches the "gateway accepts N conns, processes one heartbeat each, RSTs them all" case — without it, peak-alive + heartbeat-success can both be transiently satisfied while the gateway sheds every connection.

### Failure-mode classification

The JSON output breaks connect failures into `refused / timeout / reset / tls_error / other` because **how** a gateway breaks tells you why:

| Failure mode | Typical cause |
|--------------|---------------|
| `reset` | nginx-style `worker_connections` exhaustion (Kong default = 16K) |
| `refused` | FD ceiling hit, accept queue full |
| `timeout` | gateway is up but accept loop is starved (CPU pegged) |
| `tls_error` | TLS handshake memory pressure or session cache exhaustion |
| `disconnects_during_hold` | gateway accepted but later RST'd under load (e.g. shutdown_drain triggered by overload manager) |

### Methodology + caveats

- **Default-config gateways**. Each gateway is started with the minimum env vars required to make it function (TLS certs, basic routing). `worker_connections`, `max_concurrent_conns`, etc. are left at their out-of-the-box defaults. This measures what an operator gets from `docker run`. A separate "tuned" run could be wired up later.
- **Universal protocol = HTTP/1.1+TLS**. All five gateways speak this end-to-end with matched configs, so it's the apples-to-apples comparison. Other protocols would force per-gateway exclusions (KrakenD CE has no gRPC; Kong has no H2 upstream; etc. — see `run_gateway_protocol_bench.sh` for the full matrix).
- **All gateways run in Docker with `--ulimit nofile=1048576:1048576`** so no gateway gets a per-container FD-cap advantage. The host-side ulimit/sysctl tuning is applied by the CI workflow before launching anything.
- **macOS hosts hit ~12K FD ceiling and aren't suitable for headline numbers**. The benchmark runs locally for development and at small N (≤4K), but the comparison numbers should always come from the Linux CI workflow.
- **Heartbeat is intentionally low-rate** (default 1 req/sec/conn). The point is to test connection capacity, not RPS — a high heartbeat rate would conflate the two and give a different (RPS-bound) breaking point.
- **Connect attempts are spread over `--ramp-seconds`** so the *client* doesn't SYN-flood itself. With N=50K and ramp=30s that's ~1666 connects/sec, well within typical client capacity given proper ulimit.

### Separate H2/native-gRPC acquisition profile lane (#5588)

The default-off `bench-pool-profile` feature and new manual
`pool-internal-profile.yml` workflow observe sampled pool acquisition polls,
allocator requests, RR groups, probes/readiness, cloning and coalesced creation.
See [the coverage and campaign contract](../../../docs/pool_internal_profile.md).
Use the separate `--pool-profile calibration|profile` selector; ordinary
`experiment.json` stays disabled. Four same-host pairs and direct controls cover
both protocols at 10/70/500 KiB and 1/5 MiB with fixed adaptive=false. The report
retains failed/missing observations and distinguishes useful traffic from profile
completeness. CPU stacks, hardware cache evidence and downstream stream-credit
wait remain unavailable; correctness disposition and dispatch belong to root.

## UDP internal profile campaign

The separate [UDP Internal Profile lane](../../../.github/workflows/udp-internal-profile.yml)
uses default-off `bench-udp-profile`, four UDP1024 echo200 pairs, repeated direct
controls, and same-revision observer calibration. See
[coverage and limitations](../../../docs/udp_internal_profile.md) and the fixed
`udp_profile_manifest.json` / `udp_profile_schema.json` contracts. Profiles and
traffic validity are separate; unpublished tails and scrape failures cannot
become zero-filled success. Controlled locality/burst/churn remain explicit
hooks, and `experiment.json` remains disabled.
