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

An HTTP/2 frontend upload has the matching rule. hyper reports a client's `RST_STREAM(NO_ERROR)`
as a clean end of the request body, so every streaming upload adapter relaying an HTTP/2 client's
`Incoming` requires the client's own `END_STREAM` before it ends the backend upload. This covers
native gRPC, the direct HTTP/2 pool, the reqwest path, the direct HTTP/1.1 pool, sidecar mesh
mTLS, HBONE, Unix sockets, and the native HTTP/3 backend. When the gateway-owned upload pump owns
the client body, the pump applies the same check. A reset client instead yields a CANCEL error. An
HTTP/2 backend sees `RST_STREAM(CANCEL)`. An HTTP/1.1 backend sees an aborted body and a closed
connection, never the terminal chunk. A native HTTP/3 backend sees its request stream reset with
`H3_REQUEST_CANCELLED`, never a FIN, and the request ends as a `499` client disconnect. HTTP/1.1
frontends skip the check: a valid chunked EOF need not update `is_end_stream()`.

The same rule covers the buffered collect on the native HTTP/3 backend path, used when retries or
body plugins need the whole upload before dispatch. The collect borrows the client body, and when
it ends the gateway checks the body's receive state. An HTTP/2 upload that ended without the
client's `END_STREAM` is answered as a `499` client disconnect and never sent to the H3 backend.

The streaming body classifier, `classify_reqwest_error`, and the direct HTTP/1.1 pool's hyper error
classifier never count this gateway-initiated reset as a backend failure (see
[error classification](error_classification.md)). The sidecar mesh-mTLS, HBONE, and Unix-socket
dispatchers do not inspect the cause of a `send_request` failure before response headers: apart
from a canceled dispatch of a replayable body, it is `protocol_error`. If the gateway's reset
surfaces there while the dispatch is still running, it is charged to that target's circuit breaker
and passive health, as an explicit client `CANCEL` already is.
