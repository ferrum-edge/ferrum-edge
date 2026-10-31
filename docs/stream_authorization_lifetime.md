# Authorization Lifetime of an Admitted Stream

This document is the authorization-lifetime contract for authenticated streams: the deadline, termination semantics, the gateway-owned response and upload pumps, the final pre-commitment gate, observability, and coverage. It was split out of [response_body_streaming.md](response_body_streaming.md); request-lifetime dispatch rules live in [request_lifetime_dispatch.md](request_lifetime_dispatch.md).

Idle timeouts, per-frame read timeouts, and RPC deadlines answer "is this stream
still making progress". They are **independent** of the question this section
answers: "is the credential that admitted this stream still valid".

Ferrum streams SSE, chunked HTTP, native gRPC, and gRPC-Web bodies without
buffering, and authentication runs once, at request admission. Without an
explicit bound, a client could present a token with seconds of validity left,
open a long-lived stream, and keep receiving protected data long after a *new*
request with the same credential would be rejected. Issue #3815 tracks that gap;
issue #3816 tracks the same gap for client certificates.

## The contract

Every authenticated stream carries one **absolute, monotonic authorization
deadline**, anchored when the request was admitted. It is the **earliest** of:

| Bound | Source |
|-------|--------|
| The accepted credential's authoritative expiry | JWT / JWKS `exp` plus that provider's configured leeway; OIDC session expiry; OAuth2 introspection `exp` / `active_until` / `expires_in`, converted once at validation so a cache hit cannot slide it; the `mtls_auth` leaf certificate's `notAfter`, converted once at first successful evaluation so a connection-cache hit cannot slide it |
| The finite fallback maximum | `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` (default `3600`, valid `1`–`86400`) |

That deadline then composes with every other bound the protocol already
enforces — the client `grpc-timeout`, listener replacement / route drain,
process shutdown, and idle/read timeouts — on the same earliest-wins basis.

Three properties are load-bearing:

- **Activity never extends it.** DATA frames, SSE events, gRPC messages, and
  keep-alives do not reset the timer. It is armed once and checked on every
  poll, so a backend that streams continuously (and therefore never yields a
  `Pending` poll to drive an idle check) is still bounded.
- **There is no unbounded configuration.** A credential admitted without an
  authoritative expiry — `key_auth`, `basic_auth`, `hmac_auth`, LDAP — is
  bounded by the fallback maximum alone. A validated `exp` further out than the
  host's monotonic clock can represent lands in the same place: whether that
  conversion overflows is a property of the platform clock, never of the
  credential, so the credential stays admitted and simply publishes no bound of
  its own instead of being treated as already expired. `0` is rejected in every
  mode.
- **Unauthenticated streams are untouched.** No principal was admitted, so
  there is no authorization lifetime to enforce. A public SSE endpoint behaves
  exactly as before.

## Termination semantics

| Point | Behavior |
|-------|----------|
| Before the credential is accepted | Authentication rejection or challenge, with the status chosen by the provider. For example, expired OIDC claims enter its configured browser or API challenge path (the browser path may redirect); ordinary token and mTLS validation failures use their provider's rejection behavior. An `mtls_auth` leaf outside its validity interval fails the per-request temporal check, including on a reused H1 keep-alive connection and on new H2/H3 streams over an existing transport connection |
| After acceptance, before the downstream response head is committed | A fixed terminal chosen once, at the single point where every H1/H2 dispatch path converges: plain HTTP, SSE, and chunked responses get a fixed `401` with the compiled-in `{"error":"Unauthorized"}` body; native gRPC gets HTTP 200 with trailers-only `grpc-status: 16` (`UNAUTHENTICATED`); gRPC-Web gets the equivalent bounded terminal through the shared translation. This is the terminal a **request-upload** expiry produces, because the upload seam fires while the backend is still withholding response headers |
| After the response head is committed, before any response DATA | Native gRPC receives `grpc-status: 16` (`UNAUTHENTICATED`) trailers; gRPC-Web receives the equivalent bounded trailer frame in DATA. Ordinary HTTP and SSE have **no** terminal status metadata, so the body ends with a transport error instead — a `grpc-status` trailer is never synthesized for a client that did not speak gRPC, and the body never ends cleanly, which would be indistinguishable from a complete response |
| After response DATA is committed | The body ends with a transport error, which resets the HTTP/2 or HTTP/3 stream and terminates an HTTP/1.1 or SSE body deterministically. A complete gRPC message boundary cannot be proven at that point, so a terminal status is **never fabricated** |

When the deadline fires, the wrapper drops the inner backend body immediately —
before the downstream is polled again — so upstream work is cancelled, the
opposite relay direction is torn down, and no detached producer remains. The
request guard, per-IP guard, circuit-breaker and load-balancer accounting,
backend-admission permits, and body-buffer budget are released exactly once
through the same deferred machinery every other terminal path uses.

## The gateway-owned response pump

The response-body adapter only acts when the transport **polls** it, and hyper
does not always poll a response body:

- **HTTP/2.** `PipeToSendStream` polls the body for a frame first, then reserves
  stream send capacity for DATA. If capacity is unavailable, it retains that
  ready chunk while awaiting `SendStream::poll_capacity`; a client that
  advertises `SETTINGS_INITIAL_WINDOW_SIZE: 0` — or that simply stops issuing
  `WINDOW_UPDATE` — can therefore leave a chunk waiting indefinitely.
- **HTTP/1.1.** the dispatcher flushes a connection that can no longer buffer
  before it polls the body, so a client that stops reading parks the write.

Both are client-controlled, so a body-only bound is not an enforceable
authorization lifetime. Authenticated streaming responses therefore move the
backend body into a gateway-owned **response pump**
(`src/proxy/response_watchdog.rs`), which mirrors what
[the upload pump](#the-gateway-owned-upload-pump) does for the request
direction.

**Ownership.** The pump is the upstream body's sole owner and sole poller. The
client-visible body holds only the receiving end of a bounded channel. Nothing
is shared between them except that channel, a handful of write-once flags, and
the terminal-owner CAS below, so there is **no lock on the response path** — the
hot-path invariant forbids one, and a
lock would also let a task enforcing the deadline block behind somebody else's
inner `poll_frame`.

**One winner, decided by a CAS — not by who is scheduled first.** The pump and
the protocol adapter wrapped around it (`TotalDeadlineBody`, which owns the
client-visible terminal *shapes*: native `grpc-status: 16` trailers, the bounded
gRPC-Web frame, the deterministic HTTP/SSE transport error, plus the
deferred-accounting classification) are two independently scheduled observers of
one response. Exactly one of them settles it, and which one may not depend on
the runtime's scheduling order. Three shapes are all unsound:

- A **boolean** "did it expire?" flag. The adapter reads it, the pump then
  publishes an expiry and closes the channel, and the adapter — in the same poll
  — delivers the protected frame the pump had already queued, or the pump's
  internal released-upstream error instead of the protocol-correct terminal.
- A **timer in the adapter**, in the other direction. The pump can reach a clean
  upstream EOF (or an upstream error) well before the deadline and queue that
  terminal, while a downstream parked on flow control does not poll it until
  long after; an independent sleep would then overwrite that completed response
  with an authorization terminal, set the classification flag, and record the
  shared latch for a stream this contract never terminated.
- Reading **neither**, and deferring to the pump. A poll that arrives at or
  after the deadline then depends on the pump's timer task having been scheduled
  first — which the client, not the gateway, decides.

`AuthorizationTerminalOwner` resolves all three. It is one shared
compare-and-swap over `{Open, InnerCompletion, AuthorizationExpiry}` carrying
the single absolute deadline instant, so either observer may claim the bound the
moment the clock reaches it (one atomic load, one monotonic clock read, no
timer and no allocation); the upstream's own terminal is claimable **only** while
the clock is still before the deadline, so a completion can never overtake an
elapsed bound because a tokio timer had not fired yet; and the first claim is
final, so `fired`, the shared latch, and the fixed-cardinality counter describe
exactly one outcome. A claimed expiry is visible before the channel closure that
wakes a parked receiver, and every observer reads the owner **before** it reads
the channel, so a frame queued before the bound is never delivered after it. At
the exact deadline instant the security bound wins, deterministically. The
client `grpc-timeout` wrapper installed *inside* this one keeps its own timer and
is unchanged.

**Backpressure.** The channel bound is one frame, and the pump reserves capacity
*before* it reads the next frame, so at most one frame is ever in flight and the
backend feels the downstream's backpressure almost exactly as it did when hyper
polled it directly. A full channel parks the pump on `reserve()`, which is
precisely why the deadline arm is biased ahead of it: backpressure delays
delivery, it never delays enforcement.

**Ordering.** Frames, trailers, and the terminal travel in order through one
FIFO channel. An upstream error is delivered as an error, never collapsed into a
clean end of stream, and an expiry closes the channel *without* a terminal so
the downstream cannot mistake it for a complete response either.

The two guarantees the pump provides:

1. **Upstream cancellation.** At the deadline the pump drops the backend body it
   owns. From that instant the gateway reads no further protected byte, and the
   backend stream, its pooled connection, and every guard rooted in that body
   are released — whatever the transport is parked on. A cancelled or dropped
   pump reaches the same state through the ordinary task drop, so no detached
   producer can survive the response body.
2. **Transport close.** Dropping the upstream does not release what the response
   body itself owns: the request guard, the per-IP guard, circuit-breaker and
   load-balancer accounting, backend-admission permits, and the deferred
   transaction logger all live in `ProxyBody`, which hyper owns. If the
   downstream still has not drained the terminal a bounded grace after the
   deadline, the pump asks the connection task to close the client connection.
   hyper then drops the response body, releasing all of the above exactly once
   through the ordinary `Drop` path, and the client observes a protocol-visible
   termination — a `GOAWAY` then a close on HTTP/2, and a chunked or SSE body
   that ends **without** its terminating chunk on HTTP/1.1.

A client that *is* draining never reaches step 2: the adapter's own terminal is
delivered on the next poll, the body is dropped, and the pump is aborted with
it. The steady-state cost is one `Sleep`, one task, and one one-slot channel on
authenticated streaming responses only; an unauthenticated or buffered response
never constructs any of it.

**Deliberate trade-off.** HTTP/2 gives a server no way to reset one stream from
outside hyper — the `SendStream` is owned by the parked pipe — so the transport
close is connection-scoped and sibling streams end with it. It is preceded by
`graceful_shutdown` (a `GOAWAY`, then a bounded settle window in which siblings
can still complete), and it is only ever reached for a connection that is
demonstrably refusing to drain an already-expired authenticated stream. Leaving
that stream parked instead would let a hostile client retain a request slot, a
per-IP slot, an admission permit, and a load-balancer connection indefinitely.

## The final pre-commitment gate

Buffered response collection, every awaited pre-commitment response phase
(`after_proxy`, the buffered normalize / inspect / transform hooks, the final
client-visible body and header policies, and the response-committed hook), and
one last authoritative check immediately before the response head is committed
are all bounded by the same absolute plan. The client RPC deadline alone is not
enough (it is absent for an ordinary HTTP request): a slow hook could otherwise
carry an admitted credential past its expiry and then commit a **protected**
response head, or commit a streaming head only to terminal-error it immediately
afterwards while the fixed pre-commitment terminal was still available.

Composing the two owners into one instant is not enough on its own, because the
two owners want different outcomes. Each awaited phase therefore carries the
authorization **plan** beside the composed instant
(`RequestContext::precommit_response_phase_bound`), and an elapsed bound is
resolved by `PrecommitPhaseResult`:

- **Client RPC deadline.** Unchanged, byte for byte: gateway deadline
  provenance is marked and the canonical `grpc-status: 4` terminal is selected.
- **Authorization lifetime.** The phase is cancelled, the request's shared
  termination latch records the bounded class **exactly once**, no RPC-deadline
  provenance is marked — the plugin that was running and the backend that
  answered are blameless, and that marker would otherwise drive `grpc-status: 4`
  terminal write bias in the protocol writers — and the only selectable terminal
  is the fixed, redacted pre-commitment one. A tie is attributed to
  authorization, matching every relay's biased select ordering.

Attribution comes from the **captured composition**, never from re-reading the
clock once the bound has fired. Asking "is the authorization deadline in the
past?" after the fact is a scheduling race: a phase that is not polled again
until after the *later* of the two instants sees both as elapsed, and a strictly
earlier client `grpc-timeout` would be reattributed to the gateway's security
decision — silently changing client `grpc-timeout` behavior. The winning owner
is decided in `ComposedAuthBound::compose`, where both instants are known, and
survives arbitrary observation delay; the clock is still consulted for the
authorization case, so a bound that fired for some other reason can never
fabricate an expiry.

Every composed HTTP/3 seam carries that same typed bound, because a write parked
in QUIC flow control — and a dispatch phase parked on a backend that withholds
its response head — is exactly the case that is not observed again until after
both instants have passed: the native-H3 gRPC dispatch (backend open plus
response-head wait), the native-H3 response-head write, the native-H3 buffered
and streaming downstream write seams, and the cross-protocol plain, terminal,
and streaming write seams.

A response HEADERS write that such a bound cancels after h3 took its frame
cannot be followed by another write on that stream: h3-quinn still holds the
cancelled frame, fails the next `send_data` with a connection-level error, and
h3 closes the whole QUIC connection with `H3_INTERNAL_ERROR`, every sibling
stream included. The cross-protocol plain head writes therefore report whether
the cancelled head was offered to the send half
(`stream_util::await_offered_response_write_before_deadline`). An offered head
is answered with a stream reset; only a head whose bound had already elapsed
before the write began still gets the fixed `401` or the gRPC-Web
`DEADLINE_EXCEEDED` HEADERS (#5745). The native aggregate MCP SSE writer
applies the same rule to its protected event-stream head
(`stream_util::await_offered_authorized_headers_write`). The gRPC-Web
`DEADLINE_EXCEEDED` trailer frame the bridge appends after a committed head is
subject to it too: the buffered body write reports whether it was offered, and
both streaming relays mark each write in flight
(`stream_util::track_response_write_in_flight`) because the client deadline
cancels the whole relay from outside. A cut write is answered with a reset,
never an appended frame.

The committed-response observer is the one phase where an elapsed bound can
mean "continue in the background", and only for the client-owned RPC deadline. When the authorization bound wins, the pending hook —
which owns a **clone of the request context and the protected response body** —
is dropped rather than spawned, and every remaining observer is skipped: a
detached continuation is precisely a protected-data side effect running after
the credential stopped being authorized. An already-elapsed bound is decided
before the observer is constructed at all, so no clone is ever handed out.

When the **client's** RPC deadline is the earlier bound the hook is still
detached — but the credential's own lifetime does not stop mattering, because
the detached invocation keeps holding that context clone and that protected body.
The detached cleanup therefore runs under the **earliest** of the fixed
five-second post-response timeout and the admitted credential's absolute
authorization deadline, so the pending hook and every remaining observer are
cancelled and dropped no later than that instant.

That bound is deliberately **not** `tokio::time::timeout_at`, which polls its
inner future before it observes the timer: a chain whose pending observer and
remaining hooks are all ready on their first poll would run to completion even
when the bound elapsed before the task was ever scheduled, and spawning is not
running — an unbounded amount of time can pass between `tokio::spawn` and the
first poll on a loaded runtime. The cleanup therefore starts with an explicit
past-deadline **refusal** that polls nothing at all, and then races a
deadline-biased `select!` whose per-poll clock gate re-checks the same instant
before every resumption. The chain is never first-polled, and never resumed,
at or after the authorization bound. The client's RPC terminal is
untouched — this is post-terminal observer work — and nothing here records an
authorization termination: the stream's terminal was decided by another bound,
so counting one would be a false, and on a bidirectional stream a double,
termination. An unauthenticated request carries no bound and keeps exactly the
fixed timeout it always had.

Native HTTP/3 gRPC has its own equivalents, because that relay writes its own
response head instead of returning a `ProxyBody`. A gate runs immediately before
the first client-visible terminal the relay can produce (the declared-size
refusal), and again after every response-header hook and policy, immediately
before the response HEADERS are written. Either gate turns an expired credential
into the fixed trailers-only `grpc-status: 16` through the bounded write-grace
path, retires (cancels and joins) the gateway-owned upload pump, releases the
admission permits exactly once, and leaves the circuit breaker, passive health,
and the adaptive limiter to record the backend's own status with no error class.
The response-header write itself is bounded by the earliest of the client RPC
deadline and the authorization deadline; a downstream that cannot accept the
HEADERS by expiry is reset rather than waited on again or misreported as
`DEADLINE_EXCEEDED`.

### The buffered terminal summary is the gate's own decision

On the buffered H1/H2 path the gate is also the **audit** boundary, because the
transaction summary and the client-visible response must describe the same
outcome. The gate runs before the summary is built, so the summary it feeds
carries the terminal status, the buffered (non-streamed) classification, and the
bounded `authorization.termination_reason` the gate latched — there is no earlier
protected summary to retract.

Terminal transaction logging is therefore **not awaited** for a request that
carries an authorization plan. Awaiting the logging chain would reopen exactly
the window the gate closed: the credential could expire while one logging plugin
blocked, after earlier plugins in the chain had already recorded the still
protected outcome. A later gate can repair the *response*, but nothing can
retract an audit record that has already been emitted, so the client would see a
fixed `401` / `grpc-status: 16` while the audit trail claimed the protected
status. The single summary is instead handed to the same bounded
observability-delivery cleanup the client-RPC-deadline path already used: every
applicable logging plugin receives it, in configured order, **exactly once**,
inside one finite-budget task that counts against
`FERRUM_LOG_DELIVERY_MAX_TASKS` and is drained at shutdown. Nothing detached
here is unbounded, and the request task itself awaits nothing between the gate
and the response it hands to hyper.

A request with **no** authorization plan has no decision to protect and keeps the
historical sequential, awaited logging contract byte for byte. The predicate is
the gate's own `effective_request_auth_deadline`, so the two can never disagree
about which requests those are.

## Observability

Expiry is classified as a **policy** termination, not a backend fault, so error
rate alerts stay meaningful:

- Deferred backend accounting records it health-neutral (the backend did nothing
  wrong), exactly like a client-chosen `grpc-timeout` expiry.
- The transaction summary carries a bounded
  `authorization.termination_reason` metadata value — `credential_expired` or
  `authenticated_stream_max_lifetime` — stamped exactly once: inside the
  single-fire deferred logger for a streaming response, and by the
  pre-commitment gate before the summary is built for a buffered one. Either
  way one summary is delivered for the exchange, and it is the one that
  describes the response the client actually received.
- `GET /metrics/runtime` exposes `authorization_lifetime`, a fixed-cardinality
  counter pair whose only label dimension is a closed protocol family (`http`,
  `grpc`, `grpc_web`, `stream_tcp`, `stream_udp`). WebSocket is deliberately
  **not** a family here: WebSocket sessions are bounded by their own
  `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS` policy (issue #3738) and reported
  through `websocket.termination_reason`, so publishing a `websocket` series
  under `authenticated_stream_max_lifetime` would name a different operator
  knob and could only ever read zero.

No token, claim, subject identifier, certificate field, provider response, or
absolute expiry value reaches a log, a metric, a trailer, or a response body.
The `grpc-message` and the internal termination text are compiled-in literals.

## Coverage

| Surface | Enforced |
|---------|----------|
| Generic HTTP/1.1 and HTTP/2 streaming responses, including SSE | Yes — two mechanisms, armed from the same absolute plan. The body adapter emits the protocol-correct terminal when the transport polls it, and a **gateway-owned response pump** owns and polls the backend body, releases it at the deadline — and, after a bounded grace, closes the client connection — when the transport does not. See [The gateway-owned response pump](#the-gateway-owned-response-pump) |
| HTTP/1.1 and HTTP/2 streaming and bidirectional request **uploads** | Yes — two mechanisms, armed from the same absolute plan. The client body adapter every streaming dispatch path installs (reqwest, direct-H2, mesh mTLS, HBONE, Unix socket, and the fully-streamed native-gRPC body) refuses to hand the transport another client byte after expiry, and a **gateway-owned upload pump** owns the inbound body in a task the gateway schedules, so the bound fires — and the client body is released — even while the backend transport is parked on flow control and is polling nothing. See [The gateway-owned upload pump](#the-gateway-owned-upload-pump) |
| HTTP/1.1 and HTTP/2 request uploads the gateway **buffers** before dispatch | Yes — a body a request-body plugin, a gRPC-Web translation, or retry replay forces into memory never reaches those adapters, so the collect itself carries the plan (`collect_request_body_under_authorization`). Covers the reqwest buffered arms, the H3-backend bridge's buffered arms, and both buffered native-gRPC arms |
| The response-**header** wait on every H1/H2 dispatch path | Yes — reqwest (initial attempt and retry), the direct HTTP/1.1 pool, direct-H2, mesh mTLS, HBONE, and Unix socket compose the plan over the client RPC deadline and `backend_read_timeout_ms`, so a backend that withholds its response head cannot hold an authenticated request open past expiry even when both of those bounds are disabled |
| Backend **connection checkout** and request **handoff** on the direct HTTP/1.1 pool, Unix-socket and HBONE inner HTTP/1.1 pools, direct-H2, sidecar mesh mTLS, and the Unix-socket h2c carrier | Yes — the plan is composed **before** acquisition and bounds pool wait, dial, TLS, CONNECT, and protocol handshakes; any idle-race replay is held to the same absolute instant. Each path checks the captured bound immediately before its transport handoff, so a request that expires during acquisition is refused before it reaches the backend. Native H3 checks the bound on every send-future poll through TLS checkout, fresh or cached sender acquisition, QUIC stream-credit readiness, and HEADERS writing. Its pool's observable wire marker is HEADERS completion: earlier pending polls may have offered part of HEADERS, so this marker does not identify the exact first wire submission. Gateway lifetime errors suppress replay regardless of that pool marker. The H3 cross-protocol gRPC bridge bounds its buffered drain, sender acquisition, upload pump, and retries with the admitted plan. All these expiries keep their captured authorization, client, or operator winner and use the existing health-neutral authorization handling; the exact transport commitment marker remains protocol-specific (GHSA-xcg4-wj3x-gjj2; #5990) |
| Native gRPC **sender acquisition**, request **handoff**, and response-**header** wait (`proxy_grpc_request_core` and the fully-streamed dispatch, on the first attempt and on every retry) | Yes — the client RPC deadline and the plan are composed once, **before** the sender is acquired, and bound the acquisition itself (pool wait, dial, TLS and HTTP/2 handshakes, the h2c peer preface). A retry is held to the same absolute instants. The composed bound is re-checked immediately before the send future is built, with nothing awaited between the check and its first poll. The response-header wait is bounded by the plan whenever authorization expires before the wait's own client deadline or `backend_read_timeout_ms`. Expiry is the gateway's own health-neutral decision (classified `ClientDisconnect`, never retried), latched and counted once, and answered with the fixed pre-commitment `grpc-status: 16` terminal, never `DEADLINE_EXCEEDED`; an earlier client deadline or read bound keeps its own terminal (GHSA-xcg4-wj3x-gjj2) |
| The direct-H2 **early-response** upload join | Yes — the upload-completion gate is installed whenever a request-size limit is configured **or** the request carries an authorization lifetime, the join waits under the composed plan, and the handler then `cancel_and_join()`s the gateway-owned pump before returning, so no gateway-owned upload survives the handler and no early backend response is committed while an authenticated upload is still running past expiry |
| Native gRPC server-, client-, and bidirectional streaming | Yes |
| gRPC-Web streaming, binary and text | Yes |
| HTTP/3 backend responses relayed to an H1/H2 downstream (`StreamingH3`) | Yes |
| Native HTTP/3 frontend streaming responses, including backend SSE relays and inspected streams | Yes — the relay resets the H3 stream at the deadline rather than fabricating a clean finish |
| Native HTTP/3 aggregate MCP SSE listener (`send_h3_aggregate_sse_response`) | Yes — the broker listener lifetime is composed with the captured authorization plan (earliest wins; an exact tie is attributed to authorization). HEADERS and every flow-control-blocked DATA/FIN write are bounded by that composition. Authorization before the 200/event-stream head commits writes the fixed redacted `401` under the post-deadline grace, otherwise the stream is reset; after commitment the stream is reset rather than finished cleanly. Listener-lifetime expiry keeps its existing non-authorization outcome and does not increment authorization counters; a clean FIN attempt after the listener deadline is still bounded by the same post-deadline grace, with a reset fallback if flow control blocks past that grace. Unauthenticated listeners are unchanged |
| Native HTTP/3 gRPC server-, client-, and bidirectional streaming | Yes — clean `grpc-status: 16` trailers while no response byte is client-visible, otherwise a stream reset; the request-upload pump is retired by its guard in the same step |
| H3 cross-protocol relays to HTTP/1.1, HTTP/2, and gRPC backends, gRPC-Web translation included | Yes, in both directions: the request-upload bridge terminates with a fixed `401` before response headers are committed, and the response relay resets or emits the bounded terminal after commitment |
| Inspected / latency-tracked streaming bodies | Yes |
| WebSocket over H1, H2 Extended CONNECT, and H3 Extended CONNECT | Yes, through the pre-existing WebSocket deadline arbiter (issue #3738), which uses the same `credential_deadline_at`. Its absolute maximum is `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS`, a different knob from `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS`, and it reports through `websocket.termination_reason` — so it is deliberately **not** a family of the `authorization_lifetime` counters |
| TCP+TLS stream sessions on the userspace relay | Yes — armed at `on_stream_connect` admission and enforced across every post-admission setup stage (DNS resolution, retry backoff, backend connect and TLS handshake, the outbound PROXY v2 header, and the inspected first-bytes forward) as well as the relay itself, so no backend or application byte is written on an expired credential |
| DTLS-terminating stream sessions | Yes — armed at accept-time admission and composed over every post-admission setup stage (DNS resolution, backend connect, backend DTLS handshake), then raced against relay completion, the idle watchdog, and drain; both directions are closed and the backend connection is torn down |
| Plain-UDP stream sessions | Yes — a plain-UDP listener runs the same `on_stream_connect` admission chain, so it can admit a Consumer, an external identity, and a credential deadline exactly like DTLS. The maximum is anchored at **first-datagram session admission**, before the epoch resolve, the mesh egress decision, and the admission chain, so a slow stream-connect plugin cannot buy extra authorized lifetime. Every post-admission setup stage that awaits is bounded (the first-datagram `on_udp_datagram` policy hooks, DNS resolution, the backend bind/connect and backend DTLS handshake), and the plan is re-read before the session is committed — before any backend success is recorded, before the session map insert, before the reply task exists, and before the first backend send. Both directions are then enforced: the client→backend forward (inline path, `last_client` fast path, and the bounded hook-ingress worker) and the backend reply task's deadline arm. See the note below |
| CP/DP configuration streams | Yes, through the separate control-plane lifetime enforcement |

The native HTTP/3 frontend and the H3 cross-protocol bridge own the QUIC
request and response halves directly rather than going through `ProxyBody`, so
each relay loop races its own copy of the same absolute deadline. The deadline
is captured once from the accepted request context before the relay takes
ownership and is never recomputed from relay activity; the arm is placed ahead
of the client `grpc-timeout` arm so the security bound is the one attributed
when both are ready, and each arm breaks its relay loop, so exactly one
completion and one counter increment occur per terminated stream. The bounded
termination class is latched on the request and reaches the H3
`BodyOutcome` / response-stream termination hooks and the transaction summary
through the ordinary path.

Deliberate scope notes:

- The Linux **kTLS splice** frontend leg cannot be wrapped by the relay-side
  deadline. Eligibility is therefore decided before the frontend handshake: a
  TLS-terminating TCP listener that can admit an authenticated stream principal
  declines the kTLS handoff and is relayed on the buffered userspace path, where
  the deadline is enforced. See
  [Kernel TLS and the stream authorization deadline](frontend_tls.md#kernel-tls-and-the-stream-authorization-deadline).
- **Plaintext TCP** stream sessions carry no gateway-verified credential from a
  built-in mechanism, so no deadline is derived for them.
- A **plain-UDP** session is bounded whenever its `on_stream_connect` chain
  admitted a principal, and is otherwise untouched: an unauthenticated session
  has no plan at all, so its datagram path reads no clock, takes no lock,
  registers no timer, and behaves byte for byte as it did before. The
  authenticated path costs one additional monotonic instant comparison per
  datagram — deliberately not a per-datagram timer, mutex, map walk,
  allocation, or formatted string. An elapsed deadline **refuses the datagram
  inline** rather than waiting for the reply task's timer to be scheduled, and
  the first observer wakes the reply task, which owns the single teardown:
  the generation is marked expired before any cache or map reuse, only that
  exact generation is removed, the backend socket / DTLS connection and the
  hook-ingress channel are closed (which cancels an in-flight datagram hook),
  and the overload connection guard and the listener's active-session slot are
  released exactly once. A setup-phase expiry releases a claimed HALF_OPEN
  circuit-breaker probe slot **neutrally** and records no backend outcome. The
  disconnect summary reports a client-side, backend-health-neutral decision
  (`RecvError` / `ClientToBackend` / `RequestError`) carrying only the bounded
  `authorization.termination_reason` class — no identity, credential,
  certificate field, expiry instant, or source address.
- **Ordinary expiry is logged at `debug!`, never `warn!`.** It is expected
  lifecycle and client-triggerable, and the counters plus the transaction
  summary already carry it, so warning-level logging would only give a client a
  log-amplification lever. Warning and error levels stay for genuinely
  anomalous cleanup, write, and invariant failures.
- A TCP setup-phase expiry is a **client-side, health-neutral** refusal
  (`StreamSetupKind::AuthorizationExpired`): the half-open circuit-breaker probe
  slot and the per-target backend-inflight slot are released without recording a
  backend outcome, so the breaker, passive health, and the adaptive buffer
  tracker are untouched. Retries and backoff sleeps cannot refresh the absolute
  deadline — it is re-checked at the top of every connect attempt.
- A **buffered H1/H2 upload** is bounded by the collect, not by a body adapter:
  the plan composes over the client RPC deadline and the operator whole-upload
  stall timeout, and the authorization arm is biased first, so a plan that has
  already elapsed fails closed without polling the collect at all. When the
  authorization bound is the one that elapsed, the dispatch returns a
  health-neutral outcome and the single pre-commitment terminal decides the
  client-visible shape; a buffered **native-gRPC** upload takes the equivalent
  trailers-only `grpc-status: 16` terminal through the shared reject pipeline,
  which releases the half-open circuit-breaker probe slot and any body-phase
  admission preacquisition first.
- **Direct-H2 early responses and hyper's detached upload pipe.** When
  `send_request` yields a response head, hyper moves the client body into a
  detached HTTP/2 pipe task, and h2 resets a stream only once *every* reference
  to it is dropped — the pipe holds one, and hyper closes its own cancellation
  channel as soon as the response head resolves. The gateway therefore cannot
  force an immediate `RST_STREAM` from outside without tearing down the whole
  pooled multiplexed connection and its sibling requests. The upload pump is
  what makes the lifecycle enforceable anyway: the gateway, not hyper, owns the
  inbound body, so expiry releases it and terminates the transport body with an
  error regardless of the pipe's state, and `cancel_and_join()` gives the
  handler an actual join before it returns.
- An H3 request body that is **buffered before dispatch** composes the
  authorization deadline with the optional client RPC deadline into one
  `auth_lifetime::ComposedAuthBound` (`http3::server::h3_upload_authorization_bound`)
  and drains under it through
  `http3::server::collect_h3_request_body_under_authorization`, so a
  continuously active trickle upload cannot outlive the credential either. The
  operator whole-upload guard (`backend_read_timeout_ms`) composes on top and
  keeps its own precedence: when it is strictly earlier the drain is a plain
  read timeout with no authorization attribution at all. Only when the composed
  ABSOLUTE bound fires is the owner consulted, and it is the one captured at
  composition rather than a fresh read of the clock — so a drain observed after
  BOTH instants passed still reports the client's own strictly earlier
  `grpc-timeout` as the client's. When the authorization bound is the captured
  winner, the terminal is the fixed redacted `401` (gRPC keeps
  `grpc-status: 16`) rather than the deadline contract.

## The gateway-owned upload pump

Every H1/H2 backend transport hands the client request body to a hyper client
and lets that client's own connection task drive it. For HTTP/2 the task is
`PipeToSendStream`, which polls for a body frame before reserving capacity for
DATA, then retains a ready chunk while it waits for stream send capacity. Two
consequences follow, and together they defeat any bound that lives only inside
a body adapter:

* After polling a ready DATA frame, a pipe parked in `poll_capacity` does not
  poll the body again, so a cancellation channel or a `Sleep` armed *inside*
  the body cannot be observed until flow-control credit, a reset, or a
  connection close arrives.
* Once the response head resolves, hyper's own cancellation sender is gone, so
  the detached pipe can keep owning the inbound body — and the request
  accounting rooted in it — indefinitely.

The same detachment exists on the HTTP/1.1 pooled clients (mesh mTLS, HBONE's
inner client, the Unix-socket pool) and inside reqwest, whose connection task
owns the body the same way and parks on socket writability, or on HTTP/2
capacity when it negotiates HTTP/2.

`proxy::upload_pump` closes that gap for **authenticated** streaming uploads.
The inbound `hyper::body::Incoming` moves into a gateway-owned future, and the
transport is handed a bounded bridge instead. The future selects, biased, over
an explicit dispatcher cancellation, the admitted stream's absolute
authorization deadline, and the next unit of work (bridge capacity, then one
source frame). Arms one and two are polled by the gateway — never by the
backend transport — so they fire while that transport is parked and polling
nothing.

Who polls the pump depends on what it enforces. A pump that carries an
authorization deadline is given **its own task** at install: that deadline is
absolute and armed immediately, and the dispatcher may still be inside a
pre-dispatch wait (pool acquisition, admission) that polls nothing else. A pump
whose only bound is `backend_write_timeout_ms` is driven **inline by the
dispatcher's own task**, from the response-header race every dispatcher already
runs against the write watermark: that watermark cannot arm before the
transport's first body poll, and no transport takes that poll before its
dispatcher enters the race, so nothing the pump enforces can fall due while no
one is polling it. An ordinary request/response upload therefore spawns no
task and pays no cross-task hop per frame. If that race ends while the upload
is still live — the backend answered before consuming it, a replay is about to
replace it, or the join is dropped — the pump is handed to a task at that
moment and continues exactly as the always-spawned pump did.

What this enforces, exactly:

- After the deadline the gateway polls no further client body, hands the
  transport no further client byte, and **discards** anything still queued in
  the bridge.
- The transport body ends in an **error**, never a clean end of stream, so the
  backend resets rather than accepting a truncated upload as a complete request.
- The inbound body is dropped **before** the pump publishes its outcome, so a
  dispatcher that awaits `cancel_and_join()` has an actual join: once it
  returns, no gateway-owned upload task or client-body ownership survives.
- Direct-H2 — the one H1/H2 dispatcher whose upload is scoped to the handler,
  because its completion gate already withholds an early backend response until
  the upload terminates — joins at every bounded exit and arms cancel-on-drop so
  residual early returns still release the upload promptly. The
  streaming-response transports (reqwest, mesh mTLS, HBONE, Unix socket, native
  gRPC) return while the response is still streaming, so their upload's lifetime
  is the transport body's: dropping that body closes the bridge, which the pump
  observes on its very next poll whatever else it is waiting on, and the pump
  self-terminates at the deadline regardless.

What this deliberately does **not** claim: bytes the pump handed to the
transport *before* expiry may already sit in that transport's buffers and may
still reach the wire afterwards. Those bytes are no longer the gateway's to
recall, and the pump makes no statement about them.

Cost and invariants:

- The bridge holds **one** in-flight frame, and capacity is reserved before the
  source is read, so the backpressure the transport used to apply directly to
  `Incoming` is preserved rather than replaced by buffering. Native gRPC keeps
  full-duplex semantics — this is not a buffer-first collect.
- Frames move by `Bytes` handle; no per-chunk copy or allocation is introduced.
- Byte counting, the request-size ceiling, and gRPC length-prefixed message
  counting stay in the adapter above the bridge, so they remain authoritative
  and unchanged. The client body's `size_hint` is snapshotted before the move
  and decremented as frames cross, so `Content-Length` framing survives.
- Unauthenticated requests with `backend_write_timeout_ms` disabled construct
  no pump at all: no future, no channel, no timer. That path is unchanged. With
  the write watermark live, the pump is one boxed future and one bounded
  channel, driven inline as described above.
- A **fully buffered** upload under the write watermark has nothing to relay
  and uses no bridge: the transport takes refcounted 64 KiB slices of the
  collected buffer synchronously — so the request head and the first body
  slice leave in one write — and records each take; a watcher future enforces
  the same terminals from that record (write idle since the latest take,
  cancellation, release, completion) and owns the same post-EOS drain
  judgment. The last slice is the body's end of stream, so an HTTP/2 backend
  sees `END_STREAM` on the final DATA frame.
- Termination messages are compiled-in literals from a closed set, and the
  fixed-cardinality counter is recorded through the request's shared once-only
  latch, so an upload and a response body racing the same plan still count
  exactly one termination.

## A downstream that stops reading

`send_data` / `finish` park until QUIC flow-control credit arrives, so a client
that stops consuming keeps a relay loop out of its own `select!` and its timer
is never polled. The H3 native-gRPC and gRPC-Web relay therefore races the
**earliest** of the client `grpc-timeout` and the authorization deadline around
every downstream write, and resets the stream when the authorization bound is
the one that elapsed — a client `grpc-timeout` is optional, so the client
deadline alone would leave the common case unbounded. A stalled downstream
receives no post-expiry bytes in any case, because it is not reading.

**Every** H3 downstream write shares that seam, not only the gRPC ones. A single
helper, `http3::stream_util::await_authorized_response_write`, races one
`send_data` / `send_trailers` / `finish` against the earlier of the admitted
stream's absolute authorization plan and the matched route rule's body deadline
(`request_timeout_ms` / `attempt_timeout_ms`, PR #5741), and reports one of four
outcomes (written, client write failed, authorization expired, route deadline
exceeded); authorization wins an exact tie. A route expiry is cut like the
relay's own route deadline arm — an `H3_REQUEST_CANCELLED` reset, the
`read_write_timeout` body class, and health-neutral accounting — so a client
that stops reading is cut at the deadline itself. The helper is the sole
recorder of the fixed-cardinality counter for a parked write. It is used by:

- `http3::server`'s inline native-H3 → native-H3 streaming relay, including the
  plugin-inspected and SSE variants and the terminal
  `finish_h3_response_with_backend_trailers`;
- `http3::server::stream_h3_open_response_to_client` and
  `proxy_to_backend_h3_streaming` (the refined native-H3 relays);
- `http3::cross_protocol::stream_reqwest_response` and
  `stream_inspected_reqwest_response` (the H3 → H1/H2 plain, inspected, and SSE
  relays).

The remaining writers reach the same plan through
`auth_lifetime::ComposedAuthBound`, which folds the authorization deadline into
whatever absolute bound the protocol already had: the native-H3 gRPC relay
(`dispatch_grpc_native_h3`), the buffered native-H3 writer, the seven native-H3
buffered request-upload drains, and the cross-protocol plain bridge's header,
buffered-body, and post-relay trailer/FIN writes.

Attribution is uniform, and it is taken at COMPOSITION, where both instants are
still known — never by re-reading the clock once the bound has fired. A parked
write, a backend that withholds its response head, and a continuously active
buffered upload are all routinely observed only after BOTH instants have passed;
asking "is the authorization deadline in the past?" there would report the
gateway's security decision for a phase the client's own strictly earlier
deadline actually bounded, changing the client-visible terminal, the recorded
class, and the fixed-cardinality counter. A genuine tie still resolves to
authorization, matching the biased `select!` ordering. There is deliberately no
projection helper that composes the two and returns only the instant: a seam
that composes always keeps the value that can name its owner
(`ComposedAuthBound::deadline` is taken from it, not instead of it).

The terminal follows commitment state: a fixed redacted `401` (gRPC
`grpc-status: 16`) before response headers commit, a deterministic reset
afterwards. A gateway policy expiry is health-neutral everywhere: it never moves
the circuit breaker, passive health, or the H3 capability registry.

## Live acceptance coverage

`tests/functional/functional_h3_auth_lifetime_test.rs` exercises this contract
end to end against a real QUIC listener with a real short-lived HS256 JWT: the
native-H3 streaming response relay, the H3 streaming request-upload bridge
(fixed `401` before commitment), native gRPC before and after response DATA
(`grpc-status: 16` versus deterministic reset), gRPC-Web's bounded trailer
frame, and four non-reading / continuously-active regressions: a stalled gRPC
downstream, a stalled **plain/SSE** native-H3 response, a stalled **plain/SSE**
cross-protocol response (both with a 4 KiB per-stream receive window so the
gateway's first `send_data` provably parks in flow control), and a
continuously active request upload. Each case proves the stream is usable
before the deadline, terminates inside a bounded grace despite continued
backend activity or a client that never reads, and increments the
fixed-cardinality `credential_expired` counter for its protocol family exactly
once.
