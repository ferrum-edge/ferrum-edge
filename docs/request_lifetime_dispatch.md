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

Buffered request intake applies the same check. A body the gateway collects before dispatch (the
early `before_proxy` prebuffer, which also prepares HBONE and sidecar mesh-mTLS bodies, the H1/H2
retry and body-plugin collect, the native HTTP/3 backend collect, and the native gRPC buffered
collect) is read through the same END_STREAM gate. hyper drops the service future on a client
reset only while that future is pending, so a collect that read the last DATA and a masked reset in
the same poll used to finish with the truncated body. It now fails as a client disconnect, and
nothing is dispatched: a `499` on the HTTP paths, and gRPC `CANCELLED` on the native gRPC collect.

When the dispatcher cancels a pump whose client has already reset, the pump looks past the DATA
still buffered ahead of that reset, so the backend gets the client's `CANCEL` rather than the
`INTERNAL_ERROR` of the gateway's own cancellation. Flow control limits that DATA to one frontend
stream window (`FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE`), so the probe reads up to one
window, in at most one poll per 4 KiB of window (capped at 8,192) plus 16. It stops at the first
frame past one window, because such a client is still streaming. A client that filled its window
with smaller frames than that can still be missed: its backend sees `INTERNAL_ERROR`, which is
still a reset and never a complete body.

The native gRPC buffered collect reports every failed read of the client's upload (a `CANCEL` or
masked `NO_ERROR` reset, or a dropped connection) as the client's own cancellation. The gateway
answers Trailers-Only `grpc-status: 1` (`CANCELLED`), runs the reject-path hooks, and logs the
request under `rejection_phase` `client_disconnect_buffered_grpc_upload` with the
`client_disconnect` error class. It releases a circuit-breaker probe and any backend admission
taken for the body neutrally, and dials no backend. It used to answer `INTERNAL`, and on the
retry path it handed the read failure to the dispatch pipeline as a gateway error.

An HTTP/3 frontend upload has its own form of the rule. A trailer section ends the request body
but not the request stream, so a streamed HTTP/3 upload ends the backend upload only after the
client's FIN, read with `recv_trailers`. A client that resets the stream after its trailers, with
any code including `H3_NO_ERROR`, or loses its connection there, has cancelled the request. No
streaming path completes it at the backend, and none charges it to backend health. Each path keeps
the outcome it already gives a reset in the middle of the body:

- Native HTTP/3 backend: the backend request stream is reset with `H3_REQUEST_CANCELLED`, never
  finished. The client sees a `502` and request metrics count a `502`; the transaction log's error
  class comes from the HTTP/3 error classifier (`ProtocolError` for a stream reset,
  `ConnectionTimeout` for an idle timeout). Backend health, the circuit breaker, and the HTTP/3
  capability are not charged.
- Native HTTP/3 gRPC and the HTTP/3 to gRPC bridge: the backend stream is reset
  (`H3_REQUEST_CANCELLED`, or an HTTP/2 reset instead of `END_STREAM`). The RPC is answered
  `UNAVAILABLE` with error class `ClientDisconnect`.
- Plain HTTP/3 to HTTP bridge: the request body ends with an error. An HTTP/1.1 backend sees an
  aborted body and a closed connection, never the terminal chunk. An HTTP/2 backend sees its stream
  reset. The request is recorded as a client disconnect with no response status.

Before this change the native paths and the gRPC bridge answered this reset as malformed trailers
(`400` / `INVALID_ARGUMENT`), so alerts keyed on `5xx` or gRPC `UNAVAILABLE` can see more of these
requests. An undecodable trailer section, or a known frame after it, is still malformed.

On the plain bridge the dispatch loop also aborts the backend body itself whenever it gives up on
the request before a backend response: the client's STOP_SENDING on the response, a lost
connection, the response-header wait or route deadline (`504`), and the upload deadline. A backend
still receiving the upload when the gateway answers `504` therefore sees it aborted, never a
truncated body accepted as complete. The one halt that still ends the body cleanly follows an early
backend response head: the backend has committed its response, and an erroring HTTP/1.1 request
body would cut it. The plain bridge never forwards the client's `Content-Length`, so the backend
body is chunked (HTTP/1.1) or ended by `END_STREAM` (HTTP/2) and a declared length cannot complete
it before the reset arrives. A client that sends trailers but delays its FIN holds that body open
until the response-header wait answers `504`, as on the native paths. The buffered HTTP/3 drains
apply the same end-of-stream read before dispatch (see [HTTP/3](http3.md)).

The streaming body classifier, `classify_reqwest_error`, and the direct HTTP/1.1 pool's hyper error
classifier never count this gateway-initiated reset as a backend failure (see
[error classification](error_classification.md)). The sidecar mesh-mTLS, HBONE, and Unix-socket
dispatchers do not inspect the cause of a `send_request` failure before response headers: apart
from a canceled dispatch of a replayable body, it is `protocol_error`. If the gateway's reset
surfaces there while the dispatch is still running, it is charged to that target's circuit breaker
and passive health, as an explicit client `CANCEL` already is.

## Request-future stack boundaries

The frontend admission wrapper, ordinary backend dispatch, direct H1/H2
dispatch, and H3 request exchanges construct their bounded futures out of
line without a per-request box. The large routing handler and the remaining
large transport and connection-setup children keep their boxed boundaries.
These factories are synchronous and do not spawn tasks: request guards,
task-local affinity, deadlines, and cancellation remain with the same task.

The frontend and backend state-budget test measures the concrete futures as
well as the frontend boundary. H3 has separate request and connection-setup
state budgets and cold-dispatch tests on ordinary Tokio worker stacks.
Coroutine-state size is not a measurement of the compiled poll-frame size;
real listener, cancellation, and protocol tests remain required alongside
the state ceilings when changing these boundaries.
