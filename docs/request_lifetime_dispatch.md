# Authorization lifetime during backend dispatch

An admitted HTTP-family request keeps the absolute authorization deadline accepted at receipt.
Activity, connection establishment, a retry, or a rewritten `grpc-timeout` header cannot extend it.
The earliest authorization, client RPC, or applicable operator phase bound wins; its source is
captured when the phase starts, so late observation cannot change the terminal's attribution.

| Dispatch | Acquisition and readiness | Handoff and response headers | Buffered response |
| --- | --- | --- | --- |
| Native gRPC over H2, mesh mTLS, or HBONE | Client RPC deadline plus authorization, before sender acquisition | Synchronous gate before actual enqueue; actual adapter handoff determines pre-wire/post-wire attribution | Collection inherits authorization and the existing client/read regime; an in-place pre-commitment check runs before the committed observers and again before the single transaction summary |
| Sidecar mesh mTLS, including the Unix h2c carrier | Same composed lifetime for checkout and readiness; readiness also keeps its connect budget | Last synchronous check before `send_request`; composed authorization/client/read header wait | Shared response collection and pre-commitment gate |
| Native H3 backend | All plain H3 frontend routes, including streamed uploads, carry the same plan through TLS checkout and fresh or cached acquisition | A check before every send-future poll bounds QUIC stream-credit readiness and HEADERS; upload and response-header waits inherit the plan | Retained collection inherits the same absolute authorization and client deadline |
| H3 to gRPC bridge | Buffered frontend drain, sender acquisition, and every retry use the same admitted plan | The upload pump owns expiry independently of backend polling; the channel guard rejects already-queued frames; shared gRPC send/header bounds apply | Shared gRPC collection, then an authorization gate before client HEADERS |

Already-elapsed bounds refuse before polling acquisition or send work. A native H3 response-header
wait for a request with no authorization plan and no client deadline keeps only the read timeout
the receive already applies, with no second timer. A cold H3 connection that was established is
never reclassified as a connect timeout because its task woke after the connect instant; the
per-poll send gate still enforces the lifetime. Checkout polls precede timer creation, so an
immediately available sender takes no timer-wheel lock. A completed acquisition error has no later
handoff gate: it checks the captured bound before exposing the connection error. H3 send work
checks the deadline on every poll because opening a QUIC stream and writing its HEADERS can suspend
separately. There is no await between the final check and the poll that can commit the request.

Authorization expiry is one gateway decision, recorded through the request's shared latch. It is
never retried and does not train circuit breakers, passive health, or backend admission. A buffered
native gRPC response that was collected within the lifetime is a real backend outcome: it is
recorded before response hooks run, so neither a client disconnect during those hooks nor a later
pre-commitment terminal releases it as neutral. The actual request handoff marker is retained
separately from the neutral backend-health class, including in retry attempts and dispatch
diagnostics. A sidecar readiness timeout uses its captured connect, client, or authorization winner
even when the task wakes after all deadlines have elapsed. Before client commitment, native gRPC
receives HTTP 200 with `grpc-status: 16`; gRPC-Web receives the corresponding body-framed terminal,
and plain HTTP receives the fixed 401 response. On the buffered native gRPC path the terminal
replaces the response in place, so the request writes exactly one transaction summary, carrying
`grpc-status: 16` and the bounded termination class. For an authenticated request that summary is
handed to bounded detached delivery rather than awaited, as on the H1/H2 path, so no await
separates the final check from the client-visible response. Terminal writes use the existing
bounded post-expiry grace. Once a response has committed, the existing streaming body/relay
authorization owner governs termination and accounting.

A fully-streamed native gRPC dispatch runs its handoff gate before it moves the client's
unreplayable upload into the backend request. A refusal there is pre-wire, so the unread upload
returns to the caller exactly as after a failed sender acquisition, and the caller ends it only
after the Trailers-Only response (HTTP/2) or after HEADERS+FIN (HTTP/3).

Native H3 retains the pool's HEADERS-completion wire boundary: `send_request` returns only after
its HEADERS write completes. Earlier polls can have offered a partial HEADERS frame while the
future remains pending. The per-poll lifetime gate cancels that future before any later poll,
and gateway lifetime errors suppress replay regardless of the pool's wire flag. A finer marker
for partial HEADERS submission would require a transport adapter or vendored API change.

Every native H3 upload owns a reset guard from completed request HEADERS until successful upload
`finish`. Expiry, write failure, malformed trailers, oversize bodies, and cancellation reset the
backend send half with `H3_REQUEST_CANCELLED`; dropping Quinn's send stream alone would turn a
partial upload into clean EOF. This covers buffered bodies, borrowed H3 frontend streams, and
Hyper `Incoming` uploads, including cancellation while waiting for more frontend DATA.

Regression coverage checks zero backend requests on expiry during TLS checkout and before a cached
send, and observes backend QUIC resets after complete DATA followed by a stalled frontend (without
Content-Length), plus buffered flow-control expiry. Paused-clock coverage retains a connect-before-
client winner on late sidecar readiness wakeups and distinguishes pre-handoff authorization refusal
from expiry after transmission; a live pooled upload also asserts its post-handoff marker.

The `BackendResponse` handoff field does not change public gateway error/header tokens. It records
whether the request was handed to the backend independently of the backend-health class.
