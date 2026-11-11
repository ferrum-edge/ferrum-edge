# H2 guard campaign findings and bounded transition follow-up

Issue [#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588) remains open.
This follows merged [#5613](https://github.com/ferrum-edge/ferrum-edge/pull/5613)
and its [hosted run 35414728772](https://github.com/ferrum-edge/ferrum-edge/actions/runs/35414728772),
revision `f9b9d053f9401335f9ad1d72283d0cb122fa0bd2`. It is a diagnostic extension,
not a production repair, replacement PR, or throughput claim. The new extension
has only static inspection at authoring time; hosted validation remains required.

## What that campaign establishes

The campaign retained all 36 canonical samples: four counterbalanced pairs of
direct/adaptive/fixed arms, 15 seconds, 200 offered workers, HTTP/2 at 71,680
bytes and gRPC TLS at 10,240/71,680 bytes. No failed sample becomes a clean
performance comparison. Aggregate top-level annotations inherit the last pair;
the canonical per-pair records are the evidence.

There is one guard-failure emission in the unique captured gateway prefixes.
HTTP/2 adaptive pair 2, sequence **154**, connection **24**, stream **7857**, is
client-role nonempty nonfinal DATA credit exhaustion: one payload/flow byte,
END_STREAM=false, disposition=queued, required debit 255, available 127,
maximum 32,767. The grown byte target is 2,576,928, with wire window 286,728,
available byte capacity 645,127 and 1,931,801 bytes in flight. Empty-DATA count,
reset counters and ignored/reset/released dispositions are all zero. This is
not the empty lifetime guard or a byte-window rejection.

The failure's 7,173 queued DATA frames include 3,878 finals; 3,165 budgeted
events have been polled and none cleared. Therefore 130 budgeted events remain
queued, **including the frame whose checked debit failed**. Sequence 187 is
terminal state, not another failure: polled=3,295, returned_credit rises from
666,045 to 698,685 and available credit returns to 32,767 about 11.621 ms later.
This establishes real eventual refunds, not a contiguous 129-one-byte receive
schedule. Saturating receive replenishment and refunds prevent deriving that
schedule from the net deficit alone.

The client reports 148 measurement errors: 95 send-request resets, 52 body
resets and one HTTP 502. Ninety-six workers retire, leaving 104. Guard emission
precedes the first recorded client error by about 2.982 ms, but there is no
per-request cross-hop join. The backend records broken pipe, not proven receipt
of the emitted GOAWAY. The 148 open send streams matching 148 client errors is
supporting evidence, not a missing stream association. All other 35 canonical
samples have zero client errors; all 24 current gRPC samples succeed. Historical
gRPC failures remain unexplained by this campaign.

Every adaptive backend starts with framing maximum 32,767; every fixed backend
starts with 16,777,216. BDP window setters do not resize that guard. However,
**no successful/fixed client-role connection has a nonzero-DATA terminal record**
in this capture. Initial records cannot establish fixed's minimum credit,
fragmentation, queue pressure or refund scheduling. Three adaptive HTTP/2
pairs also succeed, so the smaller budget alone does not make failure inevitable.

There are backend warmup errors, frontend teardown errors in some fixed samples,
and 56 measured gRPC event-loop-delay warnings despite successful client work.
The gRPC backend producer does not observe tonic's detached server driver
results. Zero observed backend errors there is not proved absence. HTTP/2 pool
entry count 1 and gRPC entry counts 10–16 are resident-cache gauges, not socket
counts, uniform stream distribution or connection ownership identifiers.

All captured guard prefixes reconcile without missing sequences, suppression,
malformed records or positive values in the six sampled log-drop counters.
That does not establish tail closure: live connections survive forced-removal
capture, final issued sequence was unavailable, and queued/I/O/shutdown health
was not collected. Instrumentation itself invalidates calibrated performance
claims even for zero-error samples. A production correction is not established.

For observation sizing only, ordering lifecycle records by emitted sequence
and counting initialized IDs without a terminal record gives a largest observed
concurrent prefix count of 56 (fixed HTTP/2 pair 1: 21 server-role, 35 client-role).
The other HTTP/2 processes peak at 32–51; gRPC processes peak at 32–38. These are
observer-lifetime counts, not a socket census or a guaranteed next-run bound.

## Exact retained sources

Within artifact `5613-h2-guard-campaign-http2`, under
`ferrum-edge/ferrum-edge/results/http2/run_1/`:

* `pairs/pair_002/diagnostics/ferrum_71680.log`, lines 157 and 191: actual numeric
  failure and terminal records. Use the JSON emission clock, not Docker arrival.
* `pairs/pair_002/ferrum_http2_71680.json`, client events beginning around line
  346, and corresponding `.err`: canonical failed sample and exact raw failures.
* `pairs/pair_002/diagnostics/ferrum_71680_backend.log`, line 189: backend driver
  outcome. Its backend ID is not joined to h2 connection 24.
* `_temp/h2-guard/evidence/` at artifact root: immutable archive, producer source,
  graph/selection identities, source patch and preparation evidence. The h2
  0.4.19 archive SHA-256 is
  `ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16`.

The independent source/artifact audit supplied for this follow-up is
`5613-guard-campaign-analysis.md` (42,181 bytes, SHA-256
`a1a7c2962cb8a00a0865c1f6e9bfd1390c17ada631abd3911be21ce7326dea78`)
and its compact raw-reference JSON (536,671 bytes, SHA-256
`32235b47593594c403bb2f0c826fcec72e5afe9cecb37c2c19d063a31acc3ac7`).
The JSON indexes all 36 canonical hashes, exact guard/client/backend records,
source identities, reconciliation checks and uncertainty. It is retained with
the investigation rather than duplicated into this repository. This follow-up
also directly inspected the decisive raw gateway records and pinned source.

## What the extension can and cannot answer

The temporary lane contract (`tests/performance/multi_protocol/h2_guard/README.md`,
retired with the lane under #7279)
describes numeric transition tails, exact pending/high-water/minimum-credit
state, byte-window and receive-poll epochs, memory/emission caps, reserved
failure emission, explicit live snapshots and independent HTTP/log-fence
acknowledgments. Existing guards, admission/rejection, receive order, production
dependency graph and the original campaign's workload remain unchanged.

Snapshots occur before/after the entire sample, not at the measurement barrier.
They include warmup/drain and earlier payload history. They provide live backend
state even when Inner never drops. A wrapped ring intentionally loses earlier
history; a 512-entry tail may still be too short to explain an eventual failure.
Lock contention, memory/emission/sink loss, malformed ordering or missing
acknowledgments explicitly make collection partial. Even an acknowledged
boundary remains a process prefix with `closed=0`, not a shutdown certificate.

No trustworthy narrow ownership hook exists in this h2 state for reqwest versus
native Hyper pool families, probe identity, peer sockets, frontend streams or
backend connection IDs. No opaque token or socket mapping is invented. Those
joins, cross-process clock skew and sender-side fragmentation remain missing.

If a future hosted capture retains a sufficient real failure tail, replay that
observed DATA/END_STREAM/poll/clear schedule through the pinned real receive path
while holding maximum 32,767 and all abuse guards constant. Vary only eligible
consumer progress to discriminate scheduling from fragmentation/accounting.
Current synthetic fixtures prove boundaries and the producer/consumer contract;
they cannot serve as a campaign replay. A future repair also needs stalled
consumer, cancellation, multiplexing/control-frame progress and resource bounds,
then uninstrumented validation. Raising budgets/timeouts, retrying failures,
reducing offered work or changing to fixed windows is not this RCA's repair.

Owner: Ferrum Edge maintainers via #5588. Reassess after each capture and retire
the temporary patch, generated metrics hook, collector and workflow once the
mechanism has a recorded disposition and any correction has independent normal
review and regression coverage. No production dependency adoption is authorized.
