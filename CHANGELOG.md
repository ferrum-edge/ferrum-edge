# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Port-aware Gateway API HTTP-family route representation and real listener
  binding (issue #3612). Materialized proxies carry the admitting listener's
  `listen_port` plus a namespace-qualified TLS class, and a new
  `GatewayListenerManager` binds a socket for every declared Gateway listener
  port in `file`, `database`, and `dp` mode alongside the global proxy ports —
  so two same-protocol listeners such as `:80` and `:8080`, and HTTP/HTTPS
  listeners on distinct ports, all serve through the real binary. The listener
  set is reconciled on every config publication (reload / update / delete /
  withdrawal); a withdrawn listener stops routing at the config swap and its
  socket then drains, and an unbindable port is reported on
  `GatewayListenerManager::bind_failures` and retried rather than being fatal.
  Cross-kind arbitration is keyed by the resolved Gateway listener identity, not
  by port number, so it retains healthy sibling claims and sibling listeners
  sharing a port cannot suppress or TLS-taint one another. A numeric port
  claimed by physically incompatible listener shapes — plaintext vs an
  effective TLS-serving claim, or complete TLS certificate sets from more than
  one Gateway namespace that disagree on the physical socket — is
  refused at admission on every conflicting side,
  reported on the Gateway's `status.listeners[]` as `Conflicted=True` /
  `Accepted=False` (`PortUnavailable`) / `Programmed=False`. Differing raw
  `certificateRefs` alone are not a conflict: Gateway API v1.5.1 excludes the
  `tls` field from listener distinctness, so same-port HTTPS siblings with
  disjoint hostnames stay Accepted and each retains its listener-owned SNI
  certificate set. Same-kind route merging keys on the
  exact admitting listener, so two Gateways sharing a port never have their
  dispatch rules combined, and a host+path claimed by two different listeners on
  one port is refused on both sides — in Route status as well as in the data
  plane: the affected `status.parents[]` entries report `Conflicted=True`, and
  `Accepted=False` / `Programmed=False` with `reason: Conflicted` once no claim
  under that parentRef survives, while surviving parents and listeners keep
  reporting programmed. When HTTP/3 is enabled, every TLS-class
  listener port also gets its own QUIC socket and `Alt-Svc` advertises HTTP/3
  only where one exists. Listener supervision reaps and rebinds a listener whose
  accept loop dies, and an HTTP↔HTTPS class flip retires the old accept loops
  before rebinding so the two classes never coexist on one port.

- Gateway API `UDPRoute` support (issue #3275). The K8s controller watches
  `gateway.networking.k8s.io/v1alpha2` `UDPRoute`, translates it onto the shared
  L4 materialization path as a Ferrum UDP stream proxy bound to the attached
  `protocol: UDP` Gateway listener port, and writes `Accepted` / `ResolvedRefs` /
  `Programmed` parent status. Per pinned Gateway API v1.5.1, `backendRefs` is a
  weighted **set**: one serviceable leg dispatches directly, two or more
  non-zero-weight legs materialize a namespaced Ferrum upstream that preserves
  the declared relative weights (omitted weight defaults to `1`, `weight: 0` is
  withdrawn, and the set is bounded at 16 legs). A leg naming a missing Service
  or a Service without the referenced port keeps its declared weight and is
  pointed at an unresolvable blackhole target, so its share of sessions fails
  closed and is never renormalized onto the resolvable legs. Selection is
  per UDP session (client 5-tuple), not per datagram. Admission is strict and
  fail closed: a numeric `backendRefs[].port` is required on every entry
  including zero-weight ones, only core `Service` backends are accepted,
  cross-namespace backendRefs need an exact `UDPRoute` ReferenceGrant,
  cross-namespace `parentRefs` are refused, a `UDPRoute` never attaches to a
  non-UDP listener, and `spec.hostnames` (not a Gateway API `UDPRoute` field,
  and unmatchable on a datagram) is rejected rather than silently ignored.
  `spec.rules` is supported at exactly one rule: the pinned CRD accepts
  `1..=16`, but a `UDPRouteRule` carries only `name` and `backendRefs` and so
  has no match predicate, leaving N rules as N indistinguishable matches on one
  port with no standards-defined precedence and no cross-rule weight
  comparison. Rather than invent an aggregate or let listener bind order pick a
  winner, a multi-rule `UDPRoute` is refused with a `spec.rules` diagnostic that
  names the upstream bound, and — because the object is upstream-valid — status
  reports `Accepted=False` with the upstream `UnsupportedValue` reason instead
  of the generic `Invalid`, while `ResolvedRefs` is still evaluated on its own
  terms. A `UDPRoute` whose `parentRefs` name only non-Gateway parents (a GAMMA
  `Service` parent, a mistyped `kind`, an unrecognized `group`) opens nothing
  either: Ferrum implements no non-Gateway `UDPRoute` parent and such a route is
  not a status candidate, so the backend-port fallback would be an unannounced
  north-south UDP listener. Present but malformed or explicitly empty
  `parentRefs` fail closed too. Only a `UDPRoute` with no `parentRefs` field at
  all keeps that fallback; `TCPRoute`/`TLSRoute` keep their historical
  Gateway-parent-only gate. Update and delete regenerate live stream listeners
  and upstreams.
  Attachment, weighted backend sets, ReferenceGrant fail-closed behavior,
  status, update, and deletion are gated by CI Unit Tests
  (`tests/unit/gateway_core/k8s_udproute_translation_tests.rs`), and the **live
  UDP data path** by CI Integration Tests
  (`tests/integration/gateway_api_udproute_datapath_tests.rs`), which bind the
  translator's own listener port with the production `start_udp_listener` and
  assert a datagram round-trips to the backend the route named, that two
  `UDPRoute`s on two UDP listeners do not cross-talk, that a weighted set is
  served from its generated upstream one leg per session, and that a leg naming
  an absent `Service` is dropped rather than answered. The Gateway API
  conformance lab does not add a UDPRoute black-box step. The upstream profiles
  stay `GATEWAY-HTTP,GATEWAY-GRPC` and no `GATEWAY-UDP` profile is claimed.
- `ai_federation` incremental provider response streaming behind a new root
  `streaming` block (issue #3298). With `streaming.enabled`, an OpenAI Chat
  Completions request carrying `"stream": true` is claimed in `before_proxy`,
  bound to exactly ONE provider, and routed through `RequestContext.route_override_*`
  so the ordinary proxy dispatch path relays provider SSE incrementally — time
  to first token, client-disconnect cancellation, byte budgets, and shutdown
  accounting all come from the shared streaming response machinery, and the
  plugin adds no queues, channels, or detached tasks of its own. The provider
  commit boundary is fail-closed: fallback across providers happens only during
  pre-commit selection (open circuit, streaming-ineligible provider, unusable
  endpoint), and after the claim no second provider is ever spliced into the
  same logical stream — a post-commit failure truncates with one
  gateway-authored terminal SSE `error` event. Streaming eligibility is limited
  to providers whose native streaming wire format already is the OpenAI SSE
  contract (`openai`, `mistral`, `xai`, `deepseek`, `meta_llama`,
  `hugging_face`, `azure_openai`) with a static header credential; `anthropic`,
  `google_gemini`, `google_vertex`, `aws_bedrock`, `cohere`, and any AWS
  SigV4 / Google OAuth2 provider fail closed with a field-specific `501` and
  belong to `ai_stream_router`. A claimed stream retains at most one SSE event —
  the partial event being assembled, or the terminal event once the provider has
  framed its completion (`streaming.max_event_bytes`, 4 KiB–1 MiB, default
  256 KiB) — and the
  ceiling is enforced on every complete AND partial event before any of its
  bytes are retained or released, so retained state grows with neither stream
  length nor transport chunk size. Ordinary events are released as soon as they
  are complete, but the terminal `data: [DONE]` event is HELD back until the
  provider's body ends: a client following the OpenAI contract may stop reading
  at `[DONE]`, so releasing one before upstream EOF would let it accept a
  successful completion the gateway went on to refuse. At a clean EOF with
  nothing else outstanding the provider's own terminal event is released
  verbatim; ANY provider byte after the retained marker — a second terminal, a
  data event, a comment / `id` / `retry` line, an oversized or non-UTF-8 block,
  or a trailing partial line — fails the stream closed and DROPS the marker, so
  the client receives the gateway-authored `error` event and no completion
  marker at all. Terminal detection follows the SSE field
  grammar — an event is terminal only when the CONCATENATION of its `data` lines
  is exactly `[DONE]`, and `CR`/`LF`/`CRLF` plus their legal mixed blank-line
  forms are all recognized — so `data: [DONE]\ndata: …` is ordinary data and
  cannot pass as completion. Oversized events, data after the terminal marker, a
  duplicated terminal marker, a non-UTF-8 or otherwise undecidable event, a
  truncated stream, a content-coded stream, and a non-`text/event-stream` 2xx
  all fail closed with fixed-cardinality reasons that never echo a provider
  byte, header, model, or URL. A claimed stream is accounted like a buffered
  call: it holds one non-queuing `max_concurrent_requests` permit and one real
  `ProviderCircuit` admission (so a half-open circuit still grants exactly one
  concurrent probe) in a clone-safe reservation that is released exactly once on
  completion, non-2xx body termination, client disconnect, downstream policy cut,
  backend error, pre-header cancellation, or a fail-closed final-body rejection
  — including while a slow non-2xx error body is still streaming after headers;
  a non-2xx circuit verdict is staged at headers and applied at body end/drop so
  a disconnect after those headers keeps the provider score; a 2xx is scored a
  circuit success only after a valid terminal marker. `model_mapping` /
  `default_model` apply to streams through an owner-scoped request transform
  that rewrites the provider-visible top-level `model` and re-asserts
  `stream: true` (a body with duplicate JSON members is deliberately left
  unrewritten and still fails closed). The committed provider's
  `connect_timeout_seconds` / `read_timeout_seconds` become the streaming
  route's dispatch budgets instead of the matched proxy's; on this path
  `read_timeout_seconds` is a WHOLE-EXCHANGE bound (connect through last body
  byte), and the new `streaming.read_timeout_seconds` (0–86400, `0` =
  unbounded) overrides it for streams only. Provider response headers are
  reduced to the bounded safe allowlist the buffered path already publishes,
  plus a gateway-authored `Content-Type: text/event-stream` and
  `Cache-Control: no-cache`; provider cookies, redirects, auth
  challenges, validators/digests, and unknown metadata never reach the client.
  The claim mints the same private provider claim
  `ai_stream_router` uses, so `request_mirror`, `serverless_function`,
  `mcp_gateway`, and `mesh_route_dispatch` stand down identically, and
  `enforce_final_backend_header_policy` plus `on_final_request_body_with_context`
  re-assert the credential, destination, committed model, and committed dispatch
  budgets over the finalized backend-visible request (GHSA-xhp5-hqj8-3mwg).
- New non-rejecting `origin response-header boundary` plugin phase, run once per
  response at the top of `run_after_proxy_hooks` (the shared funnel for H1/H2,
  native gRPC, gRPC-Web, and both H3 paths) before any `after_proxy` hook.
  A plugin that routed a request to a third-party destination opts in with
  `enforces_origin_response_header_policy` and bounds what that destination
  contributed in `enforce_origin_response_header_policy`, without discarding the
  gateway decorations later hooks add. `ai_federation`'s streaming path is the
  only owner today.
- New `RequestContext.route_override_backend_connect_timeout_ms`, the connect
  counterpart to the existing read-timeout route override, so a plugin that
  repoints a request at a direct third-party destination can apply that
  destination's own connect budget instead of silently inheriting the matched
  proxy's.
- Gateway API live `GATEWAY-GRPC` conformance: CI advertises
  `Gateway,ReferenceGrant,HTTPRoute,GRPCRoute`, runs the upstream
  `GATEWAY-HTTP,GATEWAY-GRPC` profiles against a live Ferrum listener, with
  exact-method, header, listener-hostname, weighted-backend, and core status
  coverage owned by the pinned upstream suite (issue #3272).
- NodeWaypoint captured TCP observability now exports the bounded-cardinality
  `ferrum_mesh_bpf_accept_to_first_byte_microseconds` histogram for IPv4 and
  IPv6. SOCK_OPS timestamps passive establishment and enrolls the exact accepted
  socket in a bounded SOCKHASH; an SK_SKB stream parser consumes the first
  non-empty inbound application-data callback only after the existing orig-dst
  bridge confirms capture. Socket-cookie identity, delete-wins/BPF_EXIST phase
  transitions, bounded deferred userspace SOCKHASH removal after a parser/verdict
  grace period, kernel close cleanup, LRU eviction, one-hour monotonic age
  validation, and reload generation isolation prevent tuple/listener reuse,
  callback-lock recursion, raced handoff, stale state, and `ktime` wrap from
  fabricating samples. The metric has fixed microsecond buckets with saturating
  count/bucket counters, drops sum overflow, and adds no per-flow labels (#3309).
- **SECURITY (`a2a_gateway`)**: `endpoint.grpc_services` now recognizes both the
  canonical A2A 0.3 service `a2a.v1.A2AService` and A2A 1.0's
  `lf.a2a.v1.A2AService` by default. Dropping the 1.0 identity from the defaults
  meant a deployment that had relied on the former default silently stopped
  applying method policy to 1.0 traffic after upgrading — an authorization
  bypass. Both identities are now detected and policed; the two remain
  distinct card layouts, so a 1.0 Agent Card is still never decoded as 0.3 and
  card rewriting on the 1.0 service continues to fail closed with
  `agent_card_grpc_schema_unsupported` (#3297).
- Gateway API `BackendTLSPolicy` is watched and translated for Service-backed
  `HTTPRoute`/`GRPCRoute` backends (issue #3276). `validation.hostname` projects
  to upstream `backend_tls_sni`, optional `subjectAltNames` to
  `backend_tls_san_allow_list`, and ConfigMap/Secret `caCertificateRefs` to the
  upstream CA trust posture with `backend_scheme: https`. Policy
  `status.ancestors` names the targeted Service as Ferrum's single ancestor,
  with `Accepted` / `ResolvedRefs` conditions using the portable
  `PolicyConditionReason` vocabulary, preserving third-party controllers'
  ancestors and stable condition transition times. The ancestor is the Service
  and not the routing Gateways because nothing on Ferrum's overlay or verdict
  path takes a Gateway as input, so the verdict cannot vary per Gateway; that
  also bounds Ferrum's own contribution at one entry, so no number of Gateways
  can approach the CRD's hard `MaxItems=16` ancestor limit. Ferrum writes policy
  status only where a managed Gateway *effectively* routes to the targeted
  Service — a route that materialized on an accepted parentRef, not merely one
  naming a Gateway. When third-party controllers have filled all 16 ancestor
  slots, Gateway API forbids adding another entry, so Ferrum publishes none and
  the same shared predicate makes translation reject the policy: covered
  backends fail closed with the HTTP 500 fault instead of silently originating
  backend TLS that no status can report.
- `wellKnownCACertificates: System` now projects the new first-class
  `system://` backend TLS trust source rather than an unset CA path. `system://`
  pins the built-in system/webpki trust anchors for every HTTP/H2/H3/gRPC
  backend client, health probe, and DTLS/stream backend: unlike an unset CA it
  deliberately does NOT fall back to the cluster-global
  `FERRUM_TLS_CA_BUNDLE_PATH`, and it never inherits `FERRUM_TLS_NO_VERIFY`, so
  a cluster-wide private CA can no longer silently replace the public roots a
  policy explicitly requested. It partitions backend connection pools, is
  reported in the TLS material inventory, is rejected on client cert/key fields,
  is rejected with any path or query options, and is rejected alongside
  `backend_tls_verify_server_cert: false` on every config surface that builds a
  backend TLS identity — Proxy, Upstream, the `mesh_route_dispatch`
  route-local destination override, and Istio `DestinationRule` TLS overlays.
- A Gateway API route rule whose `backendRefs` mix `BackendTLSPolicy`-covered
  and uncovered backends now fails closed with a field-specific sanitized
  warning and an HTTP 500 fault abort. Ferrum folds a rule's backends into one
  upstream carrying one backend scheme and one TLS identity, so the previous
  behavior originated TLS — with the covered Service's SNI and trust anchors —
  to Services no policy covered.
- `BackendTLSPolicy` `targetRefs[].sectionName` is now resolved against the
  target Service's real `spec.ports[].name`. A `sectionName` that names no port
  reports `Accepted=False, reason=TargetNotFound` with a field-specific message
  and fails to attach, instead of being reported `Accepted=True` on Service
  existence alone while applying nowhere; it deliberately does not spill onto,
  or fail closed, the Service's other valid ports.
- `BackendTLSPolicy` now enforces the Gateway API GEP-1897 transport contract on
  an explicitly modeled port transport. Translation retains a bounded,
  deterministic per-Service port index recording each port's classified
  transport, and a port is eligible only when its `spec.ports[].protocol` is
  proven `TCP` (omitted counts as TCP, matching the Kubernetes default;
  comparison is case-insensitive). `UDP`, `SCTP`, and any unrecognized protocol
  value are all ineligible — the previous `udp: bool` predicate treated SCTP and
  unrecognized values as "not UDP" and therefore silently admitted them to
  backend TLS. A policy that explicitly attaches to an ineligible port reports
  `Accepted=False, reason=Invalid` scoped to that port, leaving sibling TCP ports
  alone; a Service-wide policy on a Service with no TCP port is rejected the same
  way because it would govern nothing. Route traffic selecting a rejected policy
  fails closed with the HTTP 500 fault rather than originating TLS over a non-TCP
  transport or dropping to plaintext. A Service mixing TCP and non-TCP ports is
  accepted with a warning in the `Accepted` condition message and takes effect
  only on its TCP ports. A Service declaring more than 64 ports cannot have its
  port transport proven and is rejected fail closed. Condition messages name the
  transport from a fixed set and never echo the raw cluster-supplied `protocol`
  string. A Service-wide policy
  that is fully shadowed by section-specific winners now reports
  `Accepted=False, reason=Conflicted` instead of claiming success while governing
  no port; it remains accepted when it still wins at least one eligible port.
- Health probes now fail closed on **any** explicitly configured backend TLS
  material that cannot be used, in both verified and no-verify modes and on both
  the HTTP and gRPC probe paths. Previously a configured CA was only enforced
  when verification was enabled, and a configured mTLS client identity was never
  enforced at all.
  - A configured backend CA is the sole trust anchor, so an unloadable or
    unparseable CA fails the probe instead of silently verifying against the
    public webpki roots — reachable through a `BackendTLSPolicy`
    `caCertificateRefs` Secret whose `k8s://…#ca.crt` source becomes unreadable
    after translation accepted it. Multi-certificate CA bundles are parsed as
    bundles, the ordinary shape of a Kubernetes `ca.crt`.
  - A configured backend mTLS client certificate/key pair that cannot be loaded
    or parsed now fails the probe rather than downgrading it to an anonymous
    handshake, which measures something real requests never perform: a backend
    that merely *prefers* client certificates answers the anonymous probe while
    refusing proxy traffic, marking a target healthy that no request can use. A
    half-configured pair (certificate without key, or key without certificate)
    fails for the same reason instead of being ignored.
  - Disabling verification is a statement about whether the peer certificate is
    checked, not a licence to ignore material the operator named, so neither rule
    is relaxed by `backend_tls_verify_server_cert: false` or
    `FERRUM_TLS_NO_VERIFY=true`. Probe diagnostics carry the material's source
    identifier and a failure class only, never certificate or key bytes.
- Backend TLS SNI overrides (`backend_tls_sni` — the projection target of both
  DestinationRule `trafficPolicy.tls.sni` and `BackendTLSPolicy`
  `validation.hostname`) are now honored on the reqwest **HTTP/1.1** transport,
  not only on the direct-H2, gRPC, and native-H3 pools. An HTTP/1.1-only TLS
  backend — the ordinary `BackendTLSPolicy` case — previously returned a terminal
  `502` with `gateway-error-reason: backend_tls_sni_requires_direct_h2`, and the
  reqwest retry path and the H3→HTTP cross-protocol bridge rejected the override
  outright. reqwest exposes no per-request server-name hook (its connector
  derives the rustls server name from the request URL host), so the dial carries
  the override in the URL **authority** while pinning the pooled client's
  resolver to the selected target's already-resolved, already-egress-screened
  address; because that resolver answers every name with the pinned address, the
  override hostname is never itself resolved and the selected backend target
  stays authoritative for where the socket connects. ALPN is restricted to
  `http/1.1` on that client so HTTP/2 cannot derive `:authority` from the server
  name — the backend reads the authority from the explicit `Host` header instead
  — and both the pinned address and the force-H1 discriminator join the existing
  SNI/CA/SAN/mTLS/verification components of the reqwest pool key, so an SNI dial
  shares a client with neither a default h2-capable client nor another target's
  pin. Retries, timeouts, and streaming bodies are unchanged because the dial
  reuses the ordinary reqwest path, and the retry path rebuilds the dial against
  the newly selected target so an LB rotation between attempts still dials the
  rotated target. The `502` remains the fail-closed answer only where the dial
  genuinely cannot be constructed (no resolved target address to pin, or a
  backend URL whose authority does not carry the selected target host). On the
  H3→HTTP cross-protocol bridge that decision is taken as a **local
  dispatch-policy** check — before backend admission, before the
  least-connections connection-start record, and before any client is fetched —
  so an override that cannot be expressed terminates with the same sanitized
  `502` and `gateway-error-reason`, halting the H3 request body and dialing no
  backend, on the buffered and streaming legs alike. A stray override on a
  plaintext backend has no server name to override and is ignored uniformly —
  on the H3 bridge, on the HTTP/1.1 and HTTP/2 first attempt, and on the reqwest
  retry path, which previously answered it with the terminal, non-retryable
  `502` even though the first attempt dispatched it normally. The `dns_override`
  literal-target guard on that retry path is likewise waived only for a dial
  that actually carries the server name in its URL authority, never for a bare
  `sni` field that will not be applied.
- Config admission no longer rejects a backend TLS SNI override combined with
  effective retry, a request-body-buffering plugin, or `pool_enable_http2:
  false`, for proxy-level overrides and for DestinationRule / `BackendTLSPolicy`
  per-port TLS overlays alike. Those rejections existed because only the
  direct-H2 pool could carry a server name; the reqwest/HTTP-1.1 SNI dial above
  serves all three, so `ferrum-edge validate` and the Admin API were refusing
  Gateway API `BackendTLSPolicy` shapes that work. The request-body-buffering
  admission screener that derived the third leg is retired with them. Nothing
  that is genuinely unrepresentable becomes admissible: the runtime `502` /
  `gateway-error-reason: backend_tls_sni_requires_direct_h2` still fires when a
  dial cannot be constructed, and a `wss://` upgrade whose effective backend TLS
  carries an `sni` value is still refused before dialing, because the WebSocket
  transport derives both `Host` and the TLS server name from the request URI and
  cannot apply a distinct server name at all.
- Active HTTP health probes that carry a backend TLS SNI override are now
  restricted to **HTTP/1.1**. The probe puts the server name in the URL
  authority and the real target authority in an explicit `Host` header; HTTP/2
  rebuilds `:authority` from the URI, so an h2-negotiated probe presented the
  override to the backend instead of the target it was probing. The client's
  ALPN advertises `http/1.1` alone, so an h2-capable backend cannot select h2 on
  it. The same client keeps its resolver pinned to the real target, and a probe
  whose dial cannot be pinned now fails closed in every case rather than
  degrading to the unpinned minimal fallback client.
- Active **HTTP and gRPC** health probes now verify against the same effective
  backend TLS server name as request traffic. A backend covered by
  `backend_tls_sni` (`BackendTLSPolicy` `validation.hostname` or a
  DestinationRule `trafficPolicy.tls.sni`) presents a certificate for the
  override, not for the target host, so probes previously failed name
  verification and ejected a target that served requests normally. The probe
  still dials only the already-resolved, egress-screened target candidate and
  the backend still sees its own authority: the HTTP probe carries the override
  in the probe URL while pinning that client's resolver to the real target host
  and sending an explicit `Host` (so the override hostname is never resolved),
  and the gRPC probe sets it as the TLS `domain_name` / rustls `ServerName`
  while tonic's `origin` keeps the target authority. An HTTPS probe with an
  override is built per target rather than per upstream, and fails closed when
  the dial cannot be pinned. TCP and UDP probes are unaffected.
- The authority-host rewrite used by cross-cluster HBONE dispatch and by the
  backend TLS SNI dial now requires a **host boundary**: a source host of
  `foo.example` no longer matches the authority `foo.example.evil`. Callers
  construct exact authorities, so this is defence in depth; bracketed IPv6
  behaviour is unchanged.
- Istio `DestinationRule.spec.exportTo` is now honored, and DestinationRules
  are resolved by Istio's lookup hierarchy — client namespace, then target
  service namespace, then the configured `istio_root_namespace` (issues #2465
  and #2469). Previously `exportTo` was discarded at translation, so a rule
  declared namespace-local with `exportTo: ["."]` could be carried to and
  applied by a client in another namespace, silently changing that client's
  TLS/SNI/trust, subset, timeout, pool, load-balancing, locality, and outlier
  behaviour; and the root namespace was dropped from slice construction while
  every remaining match was layered in lexical `(namespace, name)` order, so
  the alphabetically last rule won and renaming a namespace could reverse the
  result. Visibility is now evaluated during slice construction — before
  lookup selection and before a per-node slice is serialized — and the winning
  tier is resolved per destination there and re-applied per upstream at
  materialization, where visibility is defensively rechecked before lookup, so
  `(namespace, name, normalized host spelling)` order is only ever an
  intra-tier tiebreak. The two compose in that order: `exportTo` is absolute, so
  root-namespace fallback cannot resurrect a rule a subscriber was never
  allowed to see. Supported values are `*`, `.`, and explicit namespace names;
  `~`, empty entries, non-RFC-1123 namespace names, lists over 64 entries, and
  `*` combined with an explicit namespace are rejected fail-closed
  (Kubernetes: `FerrumAccepted=False`/`Invalid`; native/file/xDS: the config is
  refused and the previously accepted slice stays live), with diagnostics that
  name the field and index and never echo the operator-supplied value. Focused
  Rust integration and Istio conformance tests verify visibility, lookup tiers,
  hostile-input rejection/redaction, and native/xDS carrier parity, and a
  functional suite runs the shipped `ferrum-edge` binary against a real
  multi-namespace destination to prove the decision ON THE WIRE: a rule
  exported only to the destination's own namespace does not change a
  subscriber in another namespace, the same rule exported mesh-wide from the
  root namespace does, and a client-namespace rule wins outright over visible
  service- and root-namespace rules. The `mesh-e2e-sidecar` kind/SPIRE
  assertions for these two rows stay `live_deferred` because Trusted Cross
  policy forbids changing that suite's executable and configuration surfaces
  from this change.

  The target-service tier is granted only on evidence of ownership: an
  in-cluster Service confirmed by the service inventory or pinned by a
  `.svc`-qualified host, a short host resolved in the rule's own namespace per
  Istio, or an external host declared by exactly one visible `ServiceEntry` —
  in which case that ServiceEntry's namespace is the owner. When ownership
  cannot be established — an external host with no visible ServiceEntry, a
  wildcard host, an unconfirmed two-label host, or a host claimed by visible
  ServiceEntries in two different namespaces — the service tier is disabled
  for that host and only the client and root namespaces may write policy for
  it. Ferrum never falls back to treating a rule's own declaring namespace as
  the owner, which would let a public DestinationRule from an unrelated
  namespace nominate itself as the service tier for an external host it does
  not own and reach the subscriber's materialized upstreams.

  Per-destination lookups do not imply per-destination application: an
  `Upstream` has one set of slots, and every field a rule projects (load
  balancer and hash keys, backend TLS, outlier thresholds, connection-pool
  caps, locality, subsets) is upstream-wide. An upstream whose targets span two
  destinations that resolve to **different** winning rules is therefore refused
  before any upstream is mutated — merging them would let `(namespace, name,
  host)` sort order decide which service's policy governs the other. On a live
  data plane the slice is rejected and the last good config is retained in
  full; at startup the config fails to load with an error naming the upstream.
  Single-destination upstreams, multi-port upstreams, and an upstream whose
  second destination has no visible rule of its own are unaffected.

  The process-global dedup map that keeps the "multiple DestinationRules target
  one destination" warning from becoming per-reload × per-DP spam is now
  bounded on both axes — at most 128 client-namespace keys, each holding at
  most 32 distinct counts. The key is the subscriber's namespace, so without a
  key budget a churning or hostile fleet of subscriber namespaces could grow it
  without limit. Saturation degrades toward visibility (warn every time), never
  toward silence, and namespaces admitted before saturation keep steady-state
  dedup.

- `virtual_service_cors_policies[].export_to` is now validated with the same
  fail-closed boundary check `DestinationRule.exportTo` and, like ServiceEntry
  and DestinationRule visibility, is evaluated through the one shared
  `export_visibility_admits` helper. Malformed lists (`~`, empty entries,
  non-RFC-1123 namespace names, over-long lists, `*` mixed with an explicit
  namespace) on a native/file/xDS source are now a config rejection instead of
  being interpreted at evaluation time. Visibility is enforced at the SAME
  three points a DestinationRule's is — CP slice narrowing, the xDS ECDS
  carrier fold on the data plane, and outbound `cors` plugin synthesis on the
  data plane — so a producer that bypasses slice admission cannot inject
  another namespace's CORS behaviour onto a workload's outbound routes.

- The mesh root namespace (`meshConfig.rootNamespace`) now rides `MeshSlice`
  (native field plus a dedicated `IstioRootNamespaceCarrier` ECDS carrier), so
  the data plane can distinguish an admitted root-tier DestinationRule from one
  declared in an arbitrary namespace and **refuse** the latter at
  materialization. This closes the reverse-translated xDS path, where
  carrier-recovered rules never pass slice admission. Missing, empty, or
  whitespace-only root provenance fails closed: Unscoped rules are refused,
  independently provable client/service tiers still apply, and a legitimate
  root-tier default is unavailable rather than guessed. Blank root carriers are
  ignored so they cannot clear trustworthy provenance. Non-blank values are
  now validated as lowercase RFC 1123 namespace labels at both the native/file
  config boundary and the xDS ACK boundary; a malformed xDS value is NACKed
  while the last accepted slice remains live, and diagnostics never echo it.

- That materialization-time refusal now resolves the matched destination host's
  owning namespace with the SAME shared helper, in the same precedence order,
  that slice admission uses — `.svc`-qualified syntax, then an
  inventory-confirmed two-label `name.namespace`, then the declaring
  `ServiceEntry`. When that owner is resolved it is authoritative for the
  service tier; an upstream container namespace cannot widen it. Upstream
  namespace is retained only as a narrow fallback when host ownership cannot be
  resolved (for example a ServiceEntry-derived EgressGateway upstream whose
  external host is owned by the visible ServiceEntry). This prevents an
  operator-authored or multi-target upstream in an unrelated namespace from
  manufacturing service-tier policy for a host owned elsewhere.

- DestinationRule lookup-tier arbitration on the data plane is now per
  destination HOST rather than per upstream, matching Istio's per-host
  resolution. An upstream whose targets span two services previously collapsed
  the two independent lookups into one upstream-wide minimum, silently skipping
  the only rule the second host had.

- xDS ACK-time carrier validation now covers every `exportTo`-bearing carrier
  family, not just the reserved DestinationRule shape. A LEGACY (non-reserved
  name) DestinationRule carrier — recognized by its inner `type_url`, so
  genuinely unrelated ECDS extension configs are untouched — gets the same
  fail-closed structural and `export_to` validation the reserved shape gets, and
  the `VirtualServiceCorsPoliciesCarrier` entries' `export_to` lists are
  validated at the ACK boundary too. Previously both were ACKed and normalized,
  and a malformed value only surfaced later as a policy that was silently
  dropped or matched nothing; now the response NACKs, the ECDS accumulator rolls
  back, and the last accepted slice keeps serving. Rejection diagnostics name
  the carrier field and the offending index, are capped at eight per rejected
  carrier, and never echo the carrier-supplied value.

- `exportTo` entries on the DestinationRule, ServiceEntry, and
  VirtualService-CORS xDS carriers are canonicalized (trimmed) at decode. The
  shared visibility evaluator deliberately never reinterprets padded input and
  ACK-time validation checks a trimmed copy, so an un-normalized `[" beta "]`
  was previously ACKed and then matched nothing.
- **BREAKING (`a2a_gateway`)**: `endpoint.grpc_services` now defaults to the
  canonical A2A 0.3 service `a2a.v1.A2AService` (package `a2a.v1`, from
  `a2aproject/A2A` at tag `v0.3.0`) and A2A 1.0's
  `lf.a2a.v1.A2AService` by default, and every configured entry carries a declared
  Agent Card wire layout (issue #3297). The default is the identity whose card
  layout the default `endpoint.protocol_versions` (`0.3.0`) actually describes;
  retaining the 1.0 identity preserves method-policy enforcement for deployments
  that relied on the former default, while its schema prevents the 0.3 decoder
  from interpreting its renumbered card. Entries may still be plain service-name
  strings — a published A2A name resolves to the layout the specification gives
  it (`a2a.v1.A2AService` -> `a2a-0.3`, `lf.a2a.v1.A2AService` -> `a2a-1.0`) and
  any custom name resolves to `none` — or the explicit
  `{service, card_schema}` object form a custom deployment uses to declare
  which published layout its own service serves. Declaring a `card_schema` that
  contradicts a published A2A service name is rejected at admission; the layout
  is a property of the protocol, not of the deployment. Detection, method
  policy, and `a2a.*` metadata are unchanged for every schema, but Agent Card
  protobuf rewriting is implemented only for `a2a-0.3` and fails closed with
  `agent_card_grpc_schema_unsupported` (`a2a-1.0`) or
  `agent_card_grpc_schema_undeclared` (`none`) before a byte of the reply is
  decoded — a 1.0 card is never interpreted with 0.3 field numbers. Deployments
  fronting a 1.0 or custom service should set
  `discovery.rewrite_agent_card_urls: false` or declare
  `card_schema: a2a-0.3`.
- `a2a_gateway` rewrites unary gRPC Agent Card protobuf payloads (A2A 0.3.x
  wire layout) with the same JSON-RPC endpoint URL policy as HTTP cards,
  clears invalidated signatures, and fails closed on unsupported versions or
  malformed/compressed frames (issue #3297). The rewritten frame is emitted
  from its first byte through `BoundedResponseBodySink`: a bounded counting
  pass supplies the gRPC frame prefix and every `AgentInterface` length
  prefix, so no complete would-be replacement — and no interface submessage —
  is ever materialised outside the reserved construction sink
  (GHSA-pwcm-6rh8-f2gh). Only a proven-successful reply is inspected (HTTP
  `200` plus a terminal `grpc-status` of exactly `0`, read from the merged
  header+trailer view), so a non-OK upstream response is forwarded as written
  instead of being mistaken for a card; refusals are trailers-only gRPC
  `INTERNAL` under HTTP `200` with an empty body, never a synthetic 5xx or an
  HTTP body on a native gRPC stream. The 0.3.x layout gate is positive AND
  exact: the card must carry an explicit `protocol_version` (field 16) whose
  value equals a configured `endpoint.protocol_versions` entry — that list has
  no family or wildcard syntax, so `["0.3.0"]` refuses `0.3.99` — and the
  matched version must belong to the implemented 0.3 family, so an exactly
  configured `1.0.0` is refused too. An absent or empty `protocol_version`
  fails closed with `unsupported_agent_card_protobuf_version` regardless of
  configuration, because A2A renumbered `AgentCard` for 1.0 (field 3 became
  `supported_interfaces`, `signatures` moved 17 -> 13, field 14 became
  `icon_url`, `protocol_version` was removed) and proto3 cannot distinguish an
  unset field from `""` — guessing would flatten each interface submessage
  into a bare URL and re-serve the card under its now-invalid original
  signature. All seventeen known 0.3 top-level fields are schema-validated
  before any rewrite — the declared wire type (including a canonical `0`/`1`
  varint for `supports_authenticated_extended_card`), at-most-once
  multiplicity for every singular field, and UTF-8 for every known string that
  gets re-emitted — so a malformed known field can no longer be preserved
  verbatim beside rewritten siblings once the signature block is dropped. The
  submessages the rewriter preserves rather than parses (`provider`,
  `capabilities`, `security_schemes`, `security`, `skills`, `signatures`) are
  checked for shape only and are not claimed to be deeply validated; the one
  nested exception is every `AgentInterface`, whose `url` is required and
  proven, because an interface without a usable URL would otherwise be the only
  evidence a "rewritten" card advertised an endpoint at all. The protobuf
  decoder rejects over-long / out-of-range / non-canonical varints, field
  numbers outside `1..=2^29-1`, and unrepresentable length prefixes. Every
  rewritable URL field must parse as a bounded absolute `http`/`https` URL with
  a real host and no embedded credentials — a scheme prefix is not proof — and
  anything else fails closed with
  `agent_card_protobuf_url_layout_mismatch`. A card the plugin admitted whose
  rewrite never reaches the client fails closed with
  `agent_card_grpc_rewrite_not_applied`. Operators fronting a non-0.3 A2A
  backend should set `discovery.rewrite_agent_card_urls: false`; leaving it
  enabled refuses such cards rather than serving un-rewritten internal URLs.
  The absolute-URL proof requires an explicit canonical authority spelling
  before any path, query, or fragment; ambiguous recovery forms such as
  `http:///a2a` fail closed because hostile wire input can be parsed differently
  by downstream consumers.
- `a2a_gateway` now enrolls in `request_deduplication` replay presentation
  provenance, because its Agent Card rewrite is a client-facing transform that
  a finalized replay deliberately skips (issue #3297). Every retained response
  is stamped with a content digest of the plugin's whole accepted
  configuration, so a change to `discovery.public_base_url`, `endpoint.path`,
  `endpoint.agent_card_path`, `endpoint.protocol_versions`,
  `discovery.rewrite_agent_card_urls`, or `enabled` retires representations
  captured under the old settings instead of replaying a card that advertises
  a superseded endpoint. The request-derived mode is the exception:
  with `discovery.public_base_url` unset and
  `discovery.trust_forwarded_headers` enabled, the rewritten origin comes from
  per-request forwarded headers and from the connection's TLS SNI, neither of
  which the deduplication fingerprint binds, so configuration admission now
  rejects that pairing with HTTP 400 and the runtime retains and replays
  nothing. The refusal is per instance — a configured-public-base
  `a2a_gateway` composes with `request_deduplication` exactly as before.
- The `a2a_gateway` gRPC Agent Card functional harness no longer converts
  deterministic startup failures into retries or blocks without a bound
  (issue #3297). The gateway child's stdout/stderr are captured to per-attempt
  files, and a spawn attempt is retried ONLY when those diagnostics demonstrate
  an address-in-use bind race — the one failure a fresh port pair can fix. A
  config parse error, a child panic, a failed readiness/authentication check, or
  any other deterministic fault now fails immediately with a bounded tail of the
  child's output (the per-attempt bearer token redacted) instead of being
  re-rolled into "did not start after 3 attempts". Every live gRPC call carries
  a per-call timeout, and the reload poll loop hands each call the smaller of
  that ceiling and its own remaining deadline while checking the child for death
  on every iteration, so a wedged or dead gateway fails diagnostically rather
  than hanging. Simultaneously-held proxy/admin port reservations and
  owned-process readiness are unchanged, and no fixed sleep became a success
  criterion.
- `ai_transcript_audit` native gRPC payload capture via an explicit descriptor-based
  `grpc` enrollment block (issue #3304). Enrolled methods are framed, bounded,
  schema-decoded, and redacted under the same capture `mode` contract as HTTP;
  unenrolled methods stay undecoded. Enrollment is decided against the
  BACKEND-EFFECTIVE method, which `grpc_method_router` only republishes in
  `on_backend_path_resolved` — after the request-body buffering decision and
  `before_proxy` have already run — so a proxy with a `grpc` block buffers every
  native gRPC request and the final request-body hook makes the authoritative
  call. A client path that only becomes enrolled after listen-path stripping is
  therefore captured instead of escaping onto the streaming fast path, and a
  provisional enrollment the backend-effective method refutes has its staging
  entry discarded with no record emitted and no protobuf reinterpreted through
  the HTTP/JSON capture path. A request that short-circuits before routing never
  resolves a backend path, so its client-path method stays authoritative for it.
  `grpc.max_message_bytes` and `grpc.max_messages` carry immutable deployment
  maxima (8 MiB and 1024 frames) enforced at admission: the decoded-byte scan
  budget bounds decoded payload, not frame count, so legal zero-length frames
  would otherwise let an operator-configured frame count drive an unbounded
  frame vector. Descriptor-tree depth/node ceilings are aggregate across the
  complete buffered body rather than resetting for each frame. Malformed,
  oversized, undecodable, or scan-exhausting bodies omit excerpts with
  compiled-in reasons rather than exporting partial or unredacted bytes.
  Name-based redaction matches the HTTP JSON contract exactly: a value is
  replaced when any enclosing name is
  sensitive — the field, an ancestor message field, or a protobuf map key
  (never exported as a label; map values use collision-free ordinal paths such
  as `metadata.0`, and the key is consulted only for the redaction decision) —
  repeated elements inherit their field's decision instead of being judged on
  the numeric index; configured `text_fields` retain every repeated value under
  a collision-free indexed path rather than silently selecting the first; and
  JSON embedded in a protobuf string is decoded and redacted before export.
  Map ordinals are assigned over a deterministic
  canonical key order rather than protobuf map iteration order, so identical
  input always produces identical labels and identical bounded truncation.
  Enrolled requests stage binary-safe from a bounded retained snapshot of the
  buffered body — native protobuf is routinely non-UTF-8 — so a later
  `before_proxy` reject or synthetic response cannot leave the transaction
  unaudited; that short-circuit capture reads the request `grpc-encoding` from
  a minimal framing witness taken while the authoritative `before_proxy` header
  map was live, and no other request header is retained or logged. Framed gRPC
  bodies never enter the HTTP/JSON capture path, including
  `application/grpc+json`, which satisfies the JSON media-type test while
  carrying length-prefixed frames.
- `ai_semantic_firewall` streamed `inspect` mode now accepts
  `streaming.window: tokens` with an explicitly selected bounded tokenizer
  (`streaming.tokenizer`: `chars4`, `whitespace`, or `unicode_words`), soft
  `max_window_tokens` / `overlap_tokens` budgets, and deterministic
  complete-token cuts under the existing `max_window_bytes` memory/CPU cap
  (issue #3302). Invalid or non-token-window uses of the new fields fail closed
  with field-specific diagnostics; OpenAPI and `docs/plugins.md` stay in parity.
- VirtualService `tcp[]` / `tls[]` L4 match predicates `sourceLabels`,
  `sourceSubnets`, `destinationSubnets`, `gateways`, and `sourceNamespace`
  compile onto a shared precomputed `Proxy.stream_match` carrier and are
  evaluated from trustworthy connection/workload metadata before stream route
  selection (issues #3246–#3250). Shared-SPIFFE label evidence is bound to an
  exact pod/IP or identical-label replica set. AND semantics apply within one
  match arm; OR across match candidates on a shared listen port. Missing
  identity, label, subnet, or gateway evidence denies the requiring predicate;
  candidates retain VirtualService declaration order, including an explicitly
  earlier catch-all that shadows later rules;
  `exportTo` projects routes into eligible sidecar/named-gateway namespaces,
  where workload selectors remain mesh-only and gateway selection stays
  independent;
  malformed label keys/values, namespaces, gateway names, and CIDRs fail closed
  at translation with field-specific `FerrumAccepted=False`/`Invalid`
  diagnostics. Istio
  gateway scope defaults to the reserved `mesh` token; named-gateway data
  planes set `FERRUM_STREAM_GATEWAY_REF`. Existing SNI/port routing and
  weighted-split fail-closed behavior are preserved.
- `ai_stream_router` now implements the `google_gemini` provider adapter
  (issue #3299): OpenAI Chat Completions streaming requests are translated to
  Gemini/`streamGenerateContent` (Vertex-compatible) bodies, native SSE and
  JSON array/object response streams are normalized to OpenAI
  `chat.completion.chunk` SSE (content/role deltas, multi-candidate indexes,
  finish/safety/usage, function calls, bounded provider errors), and
  malformed/oversized/unrepresentable frames fail closed under the existing
  stream bounds without logging credentials or oversized payloads.
- Istio DestinationRule `trafficPolicy.loadBalancer.localityLbSetting.failoverPriority`
  is implemented end to end (#3238). The K8s translator and native/file/xDS mesh
  validators accept ordered label keys (`key`) and key/value overrides with
  exactly one equals sign (`key=value`), reject empty or malformed entries and
  mutually exclusive combinations with `distribute` / `failover` (fail closed —
  never silently degrades to another locality mode), and project the list onto
  mesh upstreams.
  Outbound/service-discovery targets stamp workload labels plus derived topology
  metadata so endpoint matching does not silently broaden. Source labels on
  mesh upstreams keep authoritative `MeshSlice.labels` and fail closed when
  same-SPIFFE local replicas disagree on enrichment or topology (no sibling
  first-match overwrite). The load balancer precomputes deterministic priority
  tiers from source workload labels against endpoint labels/locality (including
  `mesh.network`/`mesh.cluster` fallbacks), uses non-truncating ranks, prefers
  the best healthy rank, and recomputes on endpoint/locality/label reload.
  Istio-compatible activation keeps the ranks inert until applicable upstream,
  per-port, or per-subset active/passive health enables failover. An entirely
  empty source-label map creates no tiers; with a non-empty map, individually
  missing labels compare as empty strings.
  Duplicate list positions are kept; expected values follow Istio's override-map
  semantics (last `key=value` wins for that key at every position, including
  bare-key entries), with a warning on duplicate identical raw strings.
  FerrumAccepted status reports field-specific rejection diagnostics and an
  inactive-policy advisory when the applicable DestinationRule policy lacks
  `outlierDetection`. Docs, OpenAPI, and focused create/update/delete/data-path
  tests cover the behavior.
- **Behavior change (bundled with #3238):** mesh `source_locality` projection no
  longer picks the first same-SPIFFE local sibling. When multiple label-
  compatible local workloads share the mesh SPIFFE but disagree on locality,
  Ferrum now returns `None` and turns locality-first preference off for that
  slice (fail closed). Previously the result was ordering-dependent. Same-SPIFFE
  local siblings that agree, or a single matching workload, are unchanged.

- A required two-control-plane/two-data-plane multicluster poller gate now uses
  verified TLS/mTLS, audience-bound per-remote credentials, and four independent
  Toxiproxy links to live-verify last-good retention, independent trust/endpoint
  expiry, fail-closed traffic, same-generation recovery, bounded/redacted metric
  parity, and in-flight `RemoteCluster` retirement without stale reinstall.

- `/metrics` no longer replays stale mesh observability samples. The
  `prometheus_metrics` render cache (`render_cache_ttl_seconds`, default 5s) is
  invalidated only by producers the registry owns, but the mesh federation,
  remote-discovery, mesh identity/config, and xDS families are process-static
  and could not invalidate it — so any scrape landing inside the TTL of a
  previous scrape replayed frozen counters and stale cached-bundle age gauges.
  A real trust/discovery partition could therefore come and go while
  `ferrum_mesh_federation_poll_failures_total` and
  `ferrum_mesh_remote_discovery_poll_failures_total` reported no increment at
  all. These families are now rendered live on every scrape, matching the
  existing treatment of the NodeWaypoint ADR series.

- Audited admin mutations are durable **before they run** (issue #2421).
  The admin write gate fsyncs a pre-mutation audit intent — a stable event id
  plus the authenticated actor, method, sanitized path / namespace, canonical
  socket source address, and bounded request id — into
  `FERRUM_ADMIN_AUDIT_SPOOL_DIR` before the
  configuration mutation is invoked, and durably finalizes that same id with
  `success` or `failure` once the mutation returns. A crash between commit and
  finalize replays as an explicit `outcome: unknown_outcome` event, never a
  silent deletion and never an inferred outcome. Records live under
  per-process-generation instance directories whose ownership lock is held
  exclusively for the process lifetime, so several gateways may share one spool
  root and no process can classify its own in-flight record; every record is
  bound to a non-secret audit-destination identity (backend type, namespace, and
  a digest of the redacted connection URL) so a reconfigured gateway cannot
  replay another deployment's evidence into the wrong database. Discovery and
  replay start with the mode's database backend rather than waiting for a later
  mutation. Mutation settlement tasks explicitly carry the request audit slot
  across `tokio::spawn`, and cancellation ownership transfers before spawn so a
  disconnected client cannot race the detailed outcome against a generic
  fallback record. The blocking prepare/fsync is itself detached and settles a
  cancellation that arrived mid-write as `unknown_outcome`, so the newly
  durable intent cannot remain dormant in a live process generation. Delivery
  is at-least-once on the stable id and every backend
  insert is insert-only and idempotent (PostgreSQL/SQLite `ON CONFLICT (id) DO
  NOTHING`, MySQL `ON DUPLICATE KEY UPDATE id = id`, MongoDB `insert_one` with
  duplicate-key treated as success), so a duplicate delivery converges to the
  existing immutable row instead of replacing it. Directory fsync failures are
  treated as durability failures; corrupt, unrecoverable, and
  foreign-destination records are quarantined under `<spool>/failed/` and that
  degradation is sticky until the evidence is resolved. Health and metrics reads
  are O(1) from atomics and cached background state. Graceful shutdown closes
  admission, drains every accepted queue entry, interrupts retry waits, and
  explicitly aborts **and joins** the delivery worker rather than detaching it;
  a memory-only deadline loss is counted and latches degraded health. Managed
  TLS/ACME file-store mutations and explicit TLS rotation actions, which also
  emit audit events, now take the same durable pre-action handoff without
  inheriting config-database topology gates. New `FERRUM_ADMIN_AUDIT_{SPOOL_DIR,
  UNAVAILABLE_POLICY,QUEUE_CAPACITY,SPOOL_MAX_RECORDS,RETAINED_MAX_RECORDS,
  MAX_DELIVERY_ATTEMPTS}` settings, `ferrum_admin_audit_*` Prometheus families,
  and an authenticated `/health` `audit_pipeline` object.

- Admin audit events gain optional `source_address`, `request_id`, and
  `outcome` fields (folded into the baseline `audit_events` schema).
  `GET /backup` always admits a durable security record before releasing
  unredacted configuration (independent of `FERRUM_ADMIN_AUDIT_ENABLED`,
  which continues to gate ordinary mutation audit events only): synchronous
  primary insert when available, otherwise the bounded local fallback under
  `FERRUM_ADMIN_AUDIT_FALLBACK_PATH`, failing closed with `503` if neither
  sink admits the event. Authenticated denied/failed backup attempts are
  audited with fixed failure categories only; backup payload bytes and
  secrets never enter audit events or logs. Local fallback publication uses
  same-directory atomic replace (Unix `rename(2)`; Windows
  `MoveFileExW(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`) so
  repeated appends succeed when the destination already exists, without
  unlinking the live file first. Local fallback reads open the data file
  without following symlinks, validate the opened handle (regular file,
  owner-only mode, Unix single-link), and refuse inputs above
  `AUDIT_LOCAL_FALLBACK_MAX_BYTES` (16 MiB) before parse. Hard-linked lock
  targets are rejected before chmod/flock. Local fallback lock acquisition is
  non-blocking (in-process `try_lock`, Unix `flock(LOCK_EX|LOCK_NB)`,
  Windows immediate share denial) so contention fails closed instead of
  hanging a blocking-pool thread. The fallback retains the newest 4096
  events; eviction at capacity emits a content-free
  `audit_local_fallback_evicted` warning so rollover of older security
  records is never silent. Backup `resources=` filters are
  a closed allow-list; unknown tokens are rejected with static client text
  and never persisted raw in audit metadata (#2422).
- Kubernetes controller watch scopes now rebuild their reflector from an
  authoritative list when they go idle past `FERRUM_K8S_WATCH_IDLE_RELIST_SECS`
  (default `300`, `0` disables, clamped to `0`–`86400`). kube-rs raises an
  error only when a watch *fails*, so a watch that stops delivering without
  failing leaves the task alive while its reflector serves a permanently stale
  object set and every later Gateway API / Istio resource stays invisible to
  reconciles; `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` cannot recover it because it
  re-reconciles that same store. A Gateway API conformance run captured that
  signature — the TCPRoute `v1alpha2` scope initialized, four TCPRoutes existed
  in the cluster, the sibling ReferenceGrant watcher kept receiving events, the
  controller stayed alive and kept reconciling, and the TCPRoute store stayed
  frozen with no watcher error, restart, or status write for 120s. That is
  consistent with a silently stalled or black-holed watch; the artifact carries
  no transport-level evidence of where the event stream was lost, so the
  recovery is deliberately cause-agnostic and bounds any no-event stall. The
  replacement generation is swapped in make-before-break — the previous store
  keeps serving until the replacement reports `InitDone` — so a relist never
  looks like a mass deletion, and a replacement that never finishes listing is
  itself abandoned and retried without blanking the scope. Because bookmarks
  are consumed inside kube-rs, a healthy quiet scope is indistinguishable from
  a stalled one and relists on every window, so the window doubles as the
  per-scope full-list rate against the API server; each scope's deadline
  carries a bounded offset seeded per process, so neither the scopes on one
  replica nor the replicas of one scope list in lockstep. Watcher task
  ownership, the stream-end deregistration contract, and the CRD reprobe loop
  are unchanged.

- API-spec YAML ingestion now expands anchors and aliases through a bounded
  libyaml event graph (node, depth, alias-reference, expanded-byte, and work
  budgets) with cycle / undefined-alias / duplicate-anchor /
  duplicate-mapping-key detection before JSON conversion (#3307). The expanded
  byte budget is a fail-closed upper bound on the compact JSON representation,
  including string/key escaping. Merge keys are applied when present. JSON and
  YAML share the same expanded-node admission cap so autodetection cannot
  weaken checks. Expansion also fails closed on non-core/local YAML tags,
  non-finite numbers, and integers outside the exact JSON `i64`/`u64` range.
  Scalar number and boolean mapping keys keep the stringified spelling the
  previous `serde_json::to_value` conversion produced (`200:` → `"200"`), so
  YAML that leaves status codes unquoted still ingests and already-stored specs
  still restore.
- Istio Telemetry `accessLogging.filter.expression` now supports bounded boolean
  expressions with `||`, `&&`, parentheses, and the existing `response.code`,
  `response.status`, and `response.duration` comparison atoms. `duration` is
  accepted as the documented latency shorthand, and duration thresholds accept
  integer milliseconds by default or explicit `ms` / `s` suffixes with checked
  millisecond conversion. Pure conjunctions continue to compile into flat
  `AccessLogFilter` fields; expressions containing `||` compile into a
  pre-evaluated `expression` AST consumed by the injected `stdout_logging`
  plugin.
- Machine-readable vendored-patch lifecycle inventory at
  `docs/vendored-patch-lifecycle.json`, enforced on every PR and weekly
  `dependency-audit` run by `scripts/check_vendored_patch_lifecycle.py`. The
  inventory records owner, upstream filing state (or deliberate-fork staging ref),
  co-retirement groups, compatible-release test status, and the shared retirement
  checklist for all eleven current `[patch.crates-io]` logical patches. Unfiled
  deliberate forks are flagged for upstream filing or dated owner reaffirmation
  rather than tracked only in GitHub issue #3335. Because the `dependency-audit`
  job that runs the gate is required to stay on full CI, the PR planner now keeps
  `docs/dependency-policy.md`, `docs/vendored-patch-lifecycle.json`, and
  `docs/upstream-*-patches/` off the lightweight documentation path.

### Fixed

- Gateway API HTTPRoute / GRPCRoute no longer fall back to a listener-less,
  port-agnostic claim when they declare Gateway `parentRefs` that resolve to no
  concrete, materializable listener (issue #3612). An absent, mismatched, or
  otherwise ineligible declared parent previously could expose the backend on
  unrelated frontends while status correctly reported `NoMatchingParent` /
  `NotAllowedByListeners`; it now emits no proxy, upstream, plugin, or
  materialized-parent record for that parent, and contributes no HTTP/gRPC
  conflict key or cross-kind arbitration claim either — so two routes naming
  the same unmaterializable parent keep the attachment-failure status rather
  than inventing `Conflicted`. The parentless legacy shape (`spec.parentRefs`
  absent) and resolved listener port/TLS stamping are unchanged.
- Gateway API L4 routes (`TCPRoute`, `TLSRoute`, `UDPRoute`) no longer fall back
  to opening a listener on the **backend** port when they declare Gateway
  `parentRefs` that resolve to no materializable listener. An unknown,
  mismatched, protocol-incompatible, or disallowed declared parent previously
  bound an unintended OS listener while status correctly reported
  `NoMatchingParent`; it now materializes nothing and warns. The backend-port
  fallback is retained only for the parentless legacy shape.
- Applied DestinationRule subset-scoped
  `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests}`
  with per-port > selected-subset > top-level precedence, target-rotation-safe
  dispatch resolution, transport/pool isolation, and subset-keyed RAII H1
  admission (issues #3228, #3240, #3241, and #3242). Retry loops retain the
  original route/`Proxy.retry` ceiling and re-resolve each target's effective
  `maxRetries` after load-balancer rotation so a stricter (or zero) mixed-port
  candidate is never dispatched, while a looser candidate may continue up to
  `min(original_route_ceiling, candidate_cap)` rather than being blocked by a
  permanently lowered initial-port projection.
  Startup pool warmup resolves the per-target effective proxy before it builds
  and keys each reqwest warmup client, so a `DO_NOT_UPGRADE` reached through the
  subset or top-level tier pre-warms its force-H1 client instead of
  ALPN-negotiating HTTP/2 to a backend the operator forbade H2 for and parking
  that idle connection on a pool key the data path never uses. The HTTP/3→HTTP
  bridge now derives its `http1MaxPendingRequests` cap lookup and admission-lane
  key from the DestinationRule policy port (`dispatch_policy_port()`) like the
  H1/H2 path, so a `targetPort`-remapped Service no longer splits one
  destination's in-flight budget across two lanes (a cap of N admitting 2N when
  both frontends serve it) and an explicit `portLevelSettings` cap is visible to
  the bridge. Subset-scoped `connectionPool.http.idleTimeout` and
  `http2MaxRequests` — which the subset apply layer does not project — are now
  reported honestly through a translate-time warning and
  `status.ferrum.translation.deferred_fields` instead of being silently ignored
  by a fully-accepted DestinationRule.
- Corrected stale `prometheus_metrics` source documentation that claimed
  `TransactionSummary.client_disconnected` was "hardcoded false in all literal
  constructors" and that `ferrum_client_disconnects_total` could not yet fire
  (#3257). The HTTP-family plumbing has been live since the deferred-log path
  landed: `ProxyBody` classifies the terminal body state and
  `DeferredTransactionLogger` writes it into the summary for HTTP/1.1, HTTP/2,
  and gRPC, while HTTP/3 populates it synchronously from `H3StreamResult`. The
  comments now record which paths set the flag, why a backend-side reset keeps
  it false, why buffered responses always report false, and that WebSocket
  sessions are counted by `ferrum_websocket_sessions_total` instead. Added the
  previously missing regression coverage tying terminal body classification to
  the rendered counter, including its `proxy_id`-only cardinality bound and
  stale-entry eviction.

- DestinationRule-only create/update/removal now atomically republishes the
  affected route table (and LB) before mesh status/revision reports the
  generation programmed (#3243). `#[serde(skip)]` DR-derived proxy projections
  (`dispatch_port_overrides`, `dispatch_port_override_fallback`, `resolved_tls`,
  and mesh stream-relay dispatch maps) are compared even when serialized proxy
  `updated_at` is unchanged — including the empty-`ConfigDelta` publish path —
  so route-held `Arc<Proxy>` values cannot stay stale until an unrelated event.
- Durable `api_chargeback_sink` ClickHouse requests now pin
  `wait_for_async_insert=1` whenever the setting is omitted, even when Ferrum
  also omits `async_insert`. This prevents a ClickHouse user/profile default
  from turning an acknowledged export into fire-and-forget buffering before
  Ferrum advances or deletes durable spool state (#3040). The explicit
  `allow_lossy_async_insert` opt-in remains available for operators that accept
  that loss mode.

- H1/H2 WebSocket backend dials now use the effective proxy of the target they
  are actually dialing (#2416). The WebSocket branch previously received only
  the retry-capped base proxy: retry rotation moved the URL, the admission
  target, and the circuit-breaker key to the next port while the socket kept the
  unresolved route-level `connectTimeout`, trust roots, client identity, and
  verification posture — so any selected port with distinct
  `portLevelSettings` could dial with the wrong timeout, trust an unintended CA,
  or present the wrong client certificate. Every attempt (the initial one and
  each rotation) now resolves
  `resolve_backend_connection_proxy_for_target` for its own `current_target` at
  the top of the dial loop and passes that one proxy to both the direct
  TCP/TLS dial and the mesh egress dial, matching what the H3 WebSocket bridge
  already did. Retry accounting, health/load-balancer feedback, circuit
  breaking, connection and request guards, and the selected target's identity
  are unchanged. `docs/mesh.md` no longer documents an H1/H2 WebSocket
  exception to the effective-proxy pipeline.
- WebSocket policy-port vs transport-dial-port semantics are now stated
  explicitly and shared by both frontends (#2416): target selection chooses the
  **policy port** (`UpstreamTarget::dispatch_policy_port()` — the declared
  Service port when a Kubernetes `targetPort` remap applies), and that port
  keys every DestinationRule lookup the upgrade makes. The transport dial port
  is separate: a `mesh.mtls` target dials `:15006` and a `mesh.hbone` target
  dials `:15008`, reaching the app port through the tunnel, and those transport
  listener ports are never policy sources. See "WebSocket policy port vs
  transport dial port" in `docs/mesh.md`.
- A WebSocket backend dial whose effective backend TLS carries an `sni`
  override now fails closed instead of silently verifying the request URI's
  host (#2416). `client_async_tls_with_config` derives both `Host` and the TLS
  server name from the request URI and cannot apply a separate SNI, so the
  upgrade is refused pre-dial as a gateway-side dispatch rejection (`502`,
  non-retryable, neutral to the circuit breaker and passive health) — the same
  posture the reqwest retry path already takes. Because the policy is resolved
  per target, a `portLevelSettings[].tls.sni` refuses only that port's
  upgrades. Mesh egress is unaffected (its SNI is chosen by the mesh dial
  plans). **Behavior change:** a `wss://` route that previously connected while
  ignoring a configured backend TLS SNI now returns `502`. Direct WebSocket
  transport requires the backend URI hostname to be the intended TLS server
  name (with `dns_override` available when that name must resolve to a specific
  address); a distinct backend TLS SNI override is unsupported.

### Changed

- `ai_federation` config admission: a root `streaming` key is now the supported
  streaming opt-in and must be an object (issue #3298). `stream`,
  `streaming_enabled`, and `enable_streaming` are still rejected at every scope,
  and a per-provider `streaming` key is rejected with a scope-specific
  diagnostic. Enabling `streaming` makes the plugin declare a backend-boundary
  header policy plus request header/destination mutation AND a request-body
  transform (the provider-visible `model` rewrite), so such an instance can
  no longer be composed with `request_deduplication` or `response_caching` on the
  same proxy; instances without the block are unaffected. The `streaming` block
  accepts `enabled`, `max_event_bytes`, and `read_timeout_seconds` and rejects
  every other key. Those refusals (and the `hmac_auth` request-body-transformer
  refusal) are now enforced at candidate/admin-write admission as well as at
  runtime plugin-cache construction: `ai_federation` joined the
  security-composition candidate inventory, so an admin write can no longer
  persist a chain that only the runtime build would reject. A streaming instance
  additionally declares `enforces_finalized_request_policy()`, because its
  final request-body hook can refuse the backend-visible representation.
- Native gRPC trailers-only mapping for Ferrum-authored HTTP 404 rejects
  (route miss, GRPCRoute `reject_unmatched`) now emits `grpc-status`
  `UNIMPLEMENTED` (12) instead of `NOT_FOUND` (5), matching the official gRPC
  HTTP↔status table and Gateway API `GRPCExactMethodMatching` (issue #3272).
- **Breaking (native/file/xDS mesh sources only):** an omitted or explicitly
  empty `destination_rules[].export_to` is now **namespace-local**, matching the
  fail-closed-by-omission convention `ServiceEntry.export_to` and
  `virtual_service_cors_policies[].export_to` already use. Add
  `export_to: ["*"]` to any native, file, or carrier-authored DestinationRule
  that must stay visible outside its own namespace. Kubernetes translation is
  unaffected: an omitted or empty `spec.exportTo` is materialized as an explicit
  `["*"]`, preserving Istio's public default.
- DestinationRules declared outside the client namespace, the target service's
  namespace, and the configured `istio_root_namespace` are no longer admitted
  to a subscriber's slice at all, and DestinationRules in the configured root
  namespace are now admitted (they previously were not).
- Reqwest backend TLS clients built via `use_preconfigured_tls` /
  `BackendTlsConfigBuilder::build_rustls_for_reqwest` now advertise ALPN
  `[h2, http/1.1]` unless the proxy forces HTTP/1.1 (`h2UpgradePolicy:
  DO_NOT_UPGRADE` or `pool_enable_http2: false`). Previously the
  BuiltRustls path left ALPN empty, so production reqwest dials never
  negotiated HTTP/2 on main. **Behavior change for existing deployments:**
  every non-force-H1 HTTPS reqwest dispatch — including retry-configured
  proxies, traffic routed to reqwest by body-buffering plugins or body-size
  limits, and capability-`Unknown` targets — now offers h2 and will switch
  from HTTP/1.1 to multiplexed HTTP/2 against dual-ALPN backends. Direct-H2 /
  H3/QUIC builders are unchanged. Enables DestinationRule
  `h2UpgradePolicy: UPGRADE` on the default reqwest path (issues #3228,
  #3240–#3242).
- Required CI owners now declare `merge_group` triggers and event-aware
  base/head selection so a future `main` merge queue can run the six required
  checks (`Tests`, `Merge Coverage`, `Gateway API Conformance`,
  `Mesh E2E Sidecar Live`, `Trusted Cross Build Policy`,
  `Multicluster Federation Live`) on the synthesized queue SHA without
  deadlocking. Repository ruleset/branch-protection enablement remains a
  separate root-owned step (#2458).
- Gateway API and Istio status planning now build immutable per-reconcile
  indexes and reuse one primary translation/materialization (plus skip errors)
  instead of retranslating a filtered snapshot once per status object, and
  borrow included `K8sObject` values rather than deep-cloning `spec`/`status`
  JSON (#2397). Both paths share that translation/index snapshot; only Gateway
  API status planning applies the fair deterministic 256-candidate rotating
  work budget *before* expensive per-object status work so the cap bounds CPU
  as well as API writes. Istio status planning remains unlimited
  (`StatusPlanBudget::unlimited(0)`). Fail-closed validation and status parity
  for every supported Istio/Gateway resource are preserved.
- Shared `BatchingLogger` flush/retry/fallback now Arc-shares one immutable
  batch payload (`Arc<Vec<T>>`) across every delivery attempt and the optional
  failed-batch hook instead of deep-cloning owned records on each non-final
  attempt (#3029). Sink flush closures borrow or Arc-clone that handle; byte
  leases stay charged for the shared records' lifetime and release when the
  last Arc drops after success, terminal discard, or fallback ownership
  transfer.
- `proxy_alerts` / notification delivery now expose bounded-cardinality
  Prometheus delivery metrics (`attempted` / `succeeded` /
  `failed_transient` / `failed_permanent` / `backpressure_dropped` /
  `abandoned_at_deadline` / `in_flight`, labeled only by fixed
  `channel_type`), classify transport/HTTP outcomes into permanent vs
  transient failures with a bounded jittered retry budget, track dispatch
  tasks per plugin generation (reload stops admission and cooperatively
  cancels; process shutdown drains via the shared observability delivery
  budget), and commit Trigger/Resolve cooldown + incident state only after
  a defined delivery settle (`PendingTrigger` / `PendingResolve`). See
  `docs/proxy_alerts.md` and `docs/notifications.md` (#2448).
- Abandonment is now reported under a fixed, compiled-in reason taxonomy
  instead of one catch-all counter. New
  `ferrum_notification_delivery_rejected_total{channel_type,reason}`
  (`generation_closed`, `registry_rejected`) covers drops where the
  registry-owned delivery body never started — including the pre-`begin_task`
  generation rejection that previously incremented nothing at all — and new
  `ferrum_notification_delivery_abandoned_total{channel_type,reason}`
  (`generation_retired`, `shutdown_deadline`, `task_dropped`) covers bodies
  that started without a committed outcome (channel transport may or may not
  have been polled). `ferrum_notification_delivery_attempted_total` advances at
  that body-start boundary (not the first channel call) so hard-deadline drop
  classification and the accounting identity stay race-free; an admit-then-cancel
  race can therefore increment `attempted` with no bytes on the wire.
  `ferrum_notification_delivery_abandoned_at_deadline_total` increments
  **only** for the true hard abort at the global shutdown drain deadline; a
  rejected or reload-retired send no longer inflates it, and a pre-body
  rejection never inflates `attempted`. Every rejection path still runs the
  producer settle callback exactly once (#2448).
- `proxy_alerts` re-breach during an externally in-flight Resolve no longer
  silently suppresses the follow-up alert. The incident parks in
  `ResolveInFlightRebreached` (no notification that could overtake the Resolve
  on the wire), and the Resolve's settle — success, failure, or abandonment
  alike, because none of those proves the endpoint did not act — converges to
  `CompensatingTrigger`, so the next breaching sample re-alerts through the
  ordinary cooldown gate. A rule that recovered again in the meantime returns
  to `Healthy` with no phantom alert (#2448).
- Documented the best-effort endpoint delivery contract: bounded
  backpressure/failure paths can produce zero copies, while transport timeouts,
  connection errors after the request was written, and cancellation after bytes
  left the process can duplicate a delivery on retry or report an abandoned
  outcome despite endpoint action. Retries preserve `fired_at`, but later
  re-admission does not; Ferrum supplies no cross-admission idempotency key.
  Webhook/email consumers must be idempotent or duplicate-tolerant (#2448).

### Security

- Buffered response bodies the gateway retains are now bounded per response and
  in aggregate, and every retained allocation is charged before it exists
  (GHSA-pwcm-6rh8-f2gh). `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0` ("unlimited")
  remains a streaming policy but folds to a finite fail-closed ceiling whenever
  a body is retained, and a new process-wide budget
  (`FERRUM_RESPONSE_BUFFER_MAX_TOTAL_BYTES`, default 256 MiB, charged in 64 KiB
  blocks) caps what all concurrent buffered responses hold at once. The charge
  is owned by the allocation rather than by the request, so it survives the
  collector's return and is released when the last handle drops — covering
  retries, plugin replacement, the response cache entry copy, deadlines,
  disconnects, and cancellation identically. What is charged is CAPACITY, not
  payload length: collectors pick their own growth target and reserve it before
  asking the allocator, preallocation hints are charged before they are
  allocated, and the eager small-response paths collect through that same
  collector instead of awaiting an opaque whole-body read (a declared
  `Content-Length` is a backend claim, not proof of the capacity handed out).
  Representation decodes charge their output capacity, their stacked
  input+output peak, and a conservative per-codec working-set ceiling. Plugins
  that replace a buffered response body (`response_transformer` body rules,
  `compression`, `sse`, `grpc_web`, `mcp_gateway`, and the AI response
  plugins) now run inside a reserved window: a full covering window is a
  precondition of every producer invocation, refilled only after the previous
  replacement was installed, and each producer materialises its output through
  a ceiling-bounded sink so an oversized replacement is refused while it is
  written rather than after it is resident. A plugin whose replacement contract
  the gateway cannot prove — any out-of-tree plugin that does not declare
  `Plugin::response_body_production()` — is refused rather than invoked, and a
  chain that cannot rewrite reserves no window at all. Refusals are separated
  by cause: a body past the per-response ceiling keeps its backend
  `response_body_too_large` attribution, while an exhausted aggregate budget is
  the gateway-local, health-neutral `gateway_buffer_capacity` terminal
  (HTTP `503` / gRPC `RESOURCE_EXHAUSTED`) with a fixed redacted body, so it
  never poisons circuit breaking, passive health, or adaptive concurrency.
  "Materialises through a ceiling-bounded sink" now holds from the first output
  byte in every declared producer, not just at the point the finished bytes are
  installed: `sse` frames its wrapped event incrementally over the input instead
  of building normalized full-body `String` copies, `ai_response_guard`
  assembles redacted SSE one event at a time, applies its regex pattern passes
  under one shared ceiling, and re-frames redacted protobuf straight into the
  bounded output, `ai_stream_router` serializes its upstream-error envelope
  through the sink and drives the buffered Anthropic normalizer in fixed-size
  slices, and `grpc_web` streams base64 armouring into the sink rather than
  holding a second complete encoded copy. Multi-pattern whole-body text redaction
  keeps the prior pass buffer live while building the next inside one
  ceiling-sized window, so allocator capacity slack can reduce the largest
  redactable body to well below the per-response ceiling (often on the order of
  half or less, depending on pattern count) and fail closed rather than
  forwarding partially redacted bytes. `ai_response_guard`'s SSE
  fail-closed residual check builds its candidate body under a reserved budget
  window as well. That keeps the documented worst-case peak of a rewriting
  response at exactly two ceilings (the old body plus one covering window).
  Three residual holes in that construction-side bound are closed with it.
  `grpc_web` no longer builds a complete trailer payload — every eligible,
  upstream-controlled `(name, value)` cloned into an owned vector — before
  copying or armouring it: the frame's declared length now comes from a bounded
  counting pass that retains no value, and a second pass writes the payload
  straight into the final bounded destination, so neither a complete payload nor
  a complete binary preimage is ever resident beside the output. gRPC-Web
  **text**-mode bodies that concatenate independently padded base64 segments
  (one padded run per upstream flush boundary) are now accepted at reframing time,
  decoded as one framed stream, and re-emitted as a single canonical standard
  base64 body — original flush segment boundaries are not preserved on output.
  The buffered
  Anthropic SSE normalizer writes every normalized byte through an accumulator
  bound to the response's own retained ceiling rather than returning a complete
  expanded emission per call, so a small route-effective ceiling is enforced
  from the first output byte instead of only after a constant-sized transient.
  `ai_response_guard` reserves a real budget window for the two remaining
  full-size candidates it builds during inspection (the JSON/content residual
  scan and the native-gRPC redaction preflight), treating a refused window as a
  rejection; and a detected `redact` that never produced a safe replacement is
  now tracked in typed request state and rejected at the final response-body
  hook, because a refused construction returns "no replacement", which a
  transform loop would otherwise read as "unchanged" and forward the original
  sensitive body. The reserve-then-fill sink seam hands its producer a target
  limited to exactly the room it was admitted for, and no longer skips the fill
  and its length check for a zero-length append.

- `ai_stream_router` now enforces its provider credential and model policy
  against the **final** backend-visible request instead of only at claim time
  (GHSA-xhp5-hqj8-3mwg). The plugin selected a provider, stripped client
  credentials, injected the provider key, and translated the body at priority
  2984, while the generic `request_transformer` runs at 3000 — so a later header
  rule could add, overwrite, or rename the credential (leaking a normal-backend
  static secret to the third-party provider, or restoring a client-controlled
  credential header), and a later body rule could replace the already-selected
  `model` after `model_patterns` matched. Two shared lifecycle boundaries close
  it, neither of which depends on relative priority: a new non-rejecting
  `enforce_final_backend_header_policy` phase re-strips every credential and
  gateway-identity header and re-installs only the selected provider's
  credential over the finalized outbound header map — after every `before_proxy`
  pass, after each deferred routing/remaining pass, and after a finalized-egress
  header overlay, on the H1/H2 and native HTTP/3 ladders alike — and
  `on_final_request_body` now fails closed unless the provider-visible `model` is
  a non-empty string equal to the committed model that still matches the selected
  provider's `model_patterns`, the final body is unambiguous JSON, and the
  committed destination witness is intact. Model failures
  return an OpenAI-shaped `400` (`model_policy_violation`); a broken
  provider/route invariant returns `500` (`provider_policy_violation`). No model,
  header, query, or body value is echoed or logged. Headers outside the plugin's
  owned set are untouched, so intended non-credential transforms still apply —
  Ferrum does not attempt to classify an arbitrary unknown custom header as a
  credential, so a bespoke normal-backend secret header configured on the same
  proxy is still forwarded. Because
  the header re-assertion happens after every `before_proxy` hook, plugin-cache
  admission now **rejects** `ai_stream_router` composed with
  `request_deduplication` on the same proxy and protocol (`response_caching` was
  already refused alongside it by the deferred-request-body-transformer rule).

  The boundary now covers the rest of the provider-visible request as well,
  through one private typed claim on the request context (never metadata, never
  logged, holding the opaque owning-instance identity plus the exact committed
  model, destination, resolved backend TLS, DNS decision, and backend-visible
  query):

  - **Model.** The model that selected the provider is authorization state, not
    observability: it is committed to the private claim, and final body
    enforcement plus the claim-owned response normalizers read it from there.
    `ai_stream_router.model` remains published for logs and other plugins, but
    is never read back — otherwise a later in-process plugin could change the
    final body's `model` *and* republish that key as the same value, satisfying
    an equality check while bypassing the selection that chose the provider, the
    price, and (for `{model}` endpoints) the backend URL. Whether the owning
    instance's own transform produced the Anthropic representation, and whether
    the claim forbids tool use for this generation (the response normalizer's
    fail-closed `tool_use` guard), are claim state for the same reason. The one
    metadata value a claim-owned hook still reads is
    `ai_stream_router.provider_content_encoding`, which comes from the
    provider's own response headers and only selects a bounded decoder.
  - **Query.** `request_transformer` can also add / update / rename / remove
    query pairs after the claim, appending a normal-backend static secret to the
    third-party provider target. The claim now freezes the exact safe
    backend-visible query — after authentication strip markers and current
    pre-router mutations — and the gateway replays it at
    `effective_backend_query_string*`, the single capture funnel for H1/H2,
    native HTTP/3, and retry replay. A folded endpoint query still means an
    empty separately-appended query; otherwise the already-safe client query
    continues unchanged.
  - **Upstream identity and backend TLS.** The destination witness previously
    checked only scheme/host/port/authority/path, so a later plugin could keep
    the visible host while changing upstream / load-balancer identity or
    weakening server verification, SNI, or mTLS. The claim now clears
    `route_override_upstream_id` and requires it to stay clear, and pins
    `route_override_resolved_tls` for exact equality (plaintext HTTP is a
    distinct committed state). Both default public verification and
    `inherit_backend_tls: true` are covered.
  - **DNS.** A base proxy's `dns_override` was cleared only when the override
    changed the backend host *text*, so a proxy already configured with the
    provider's hostname kept its pinned address and could receive the provider
    credential at an operator-chosen destination. A narrow typed route-override
    knob (`RouteOverrideDnsPolicy::ClearInherited`, honored by
    `RequestContext::apply_route_overrides*`) now lets a direct provider claim
    revoke the inherited pin explicitly. Unrelated same-host route rewrites keep
    their existing semantics.
  - **Instance ownership.** Multiple `ai_stream_router` instances are allowed and
    two of them may share a provider *name* while differing in endpoint, key,
    provider type, patterns, and normalization — so the public
    `ai_stream_router.provider` metadata key could not decide who owned a claim,
    and both instances could reapply credentials, transform the body twice, or
    normalize the response twice. Exactly one instance now claims (first match in
    configured order), and request transformation, final header/query
    enforcement, final body revalidation, response-header handling, and response
    stream inspector / normalizer selection all verify the private owner.
    `fail_on_missing_model` / `fail_on_no_matching_provider` still decide an
    unclaimed request in normal plugin order.
  - **Built-in coordination follows the private claim.** `ai_federation`,
    `request_mirror`, `serverless_function`, `mcp_gateway`, and
    `mesh_route_dispatch` decided whether to skip a claimed provider request
    from the public `ai_stream_router_claimed` metadata string. Metadata is a
    mutable map, so a later plugin deleting or rewriting that marker could make
    those built-ins re-route, mirror, federate, or invoke a function over a
    request whose third-party provider credential, model, destination, and query
    were already committed. All five now decide from a crate-private
    `RequestContext::has_ai_stream_router_claim()`, which exposes only the
    claim's existence — never its owner, model, destination, TLS, DNS decision,
    query, or credential. The marker is still published for logs and
    third-party/custom plugins, and intentionally UNCLAIMED pass-through still
    coordinates through `ai_stream_router_pass_through`.
- Stateful plugin protections are no longer owned by an individual plugin
  instance, so a qualifying configuration reload can no longer reset them
  (GHSA-wmqm-6mxj-gm9p). `request_deduplication` in local mode now owns its
  active idempotency leases, retained completed responses, execution barriers,
  and their accounting through a **stable policy identity** (`namespace` +
  plugin-config id) rather than through the instance the plugin cache happened
  to construct. Previously a routine incremental rebuild handed a replacement
  instance an empty map while the original request was still executing, so an
  immediate retry of the same idempotency key re-dispatched a side-effecting
  operation — a duplicate payment or write during ordinary dynamic
  configuration change — and a completed entry retained only by the retired
  instance was likewise forgotten. A compatible reload now inherits the live
  state; changing `header_name`, switching between `local` and `redis`, or
  changing `on_redis_unavailable` is a semantic change that isolates onto fresh
  state, so a retired generation's late completion lands on the state it took
  its lease from and cannot corrupt the replacement policy. Capacity and TTL
  changes are compatible without resetting the protection domain. Each
  admitted operation, completion, and execution barrier retains its original
  protection window, so a reload cannot shorten an in-flight lease; new
  operations use the replacement settings. Every still-live semantic
  generation remains discoverable, so a rapid A → B → A policy sequence
  recovers A's active protection domain instead of admitting against a third
  empty state.
  Retention is bounded to currently configured policies plus whatever in-flight
  work still holds a reference.

- `load_testing` now admits at most **one** effective instance per proxy after
  global/proxy/proxy_group merge, rejected at plugin-cache construction
  (GHSA-wmqm-6mxj-gm9p). Two same-name effective instances each held their own
  run-admission flag and could start overlapping high-cost cohorts against one
  gateway with no reload at all, multiplying thousands of loopback requests per
  instance. Cross-generation admission for one policy identity was already
  shared; this closes the duplicate-instance half.
  Compatible-state lookup also retains every still-live semantic generation,
  so an A → B → A reload cannot lose A's active cohort admission flag.

- `body_validator` no longer fails open on unusual methods, empty bodies, or
  uninspectable data (GHSA-2vmr-ww8r-mww3,
  <https://github.com/ferrum-edge/ferrum-edge/security/advisories/GHSA-2vmr-ww8r-mww3>).
  Request-side applicability now follows the configured representation instead
  of a hard-coded `GET`/`HEAD`/`OPTIONS`/`DELETE` exclusion, so a body-bearing
  request under a governed media type is buffered and validated on any method.
  Once a configured rule applies, an empty JSON/XML document, a body that is not
  valid UTF-8, and a missing buffered representation are rejections (`400`
  request, `502` response) rather than silent pass-throughs; the early request
  hook prefers a downstream-rewritten UTF-8 `request_body` metadata view when
  present (composition with `ai_prompt_shield`), falls back to raw buffered
  bytes when no text view exists, then the transport-proven-empty witness, and
  otherwise fails closed — while the final request-body hook still validates
  the exact backend-visible bytes. Native gRPC always runs frame validation, so
  a zero-length transport body or anything shorter than the five-byte frame
  header is rejected, while a well-formed frame carrying an empty proto3
  message is validated normally. Response-side no-body exemptions are now
  explicit and protocol-correct (`1xx`, `204`, `205`, `304`, `HEAD` responses,
  and empty terminal gRPC *error* replies with a single valid non-zero
  `grpc-status`); an ordinary body-bearing success such as `200` with an empty
  body, or an empty `grpc-status: 0` unary reply, is no longer exempt. The new
  representation-failure diagnostics are fixed strings that never log or echo
  body bytes.

- WAF no longer forwards the unscanned suffix of an oversize body past an
  enforcing body rule (GHSA-7jh9-fjqf-jcvf). `max_scan_bytes` defaults to 1 MiB
  while the gateway admits 10 MiB request and response bodies by default, and
  the previous `on_body_too_large: scan_truncated` default scanned only that
  first 1 MiB, recorded `waf.scan_truncated`, and then forwarded the complete
  body even in global enforce mode. A client could pad an upload with 1 MiB of
  benign bytes and place an enforced SQLi/XSS/traversal/SSRF/custom-rule payload
  after the cap; a compromised backend could do the same with configured
  disclosure/data-leak content in a response. `on_body_too_large` now defaults
  to the new **`fail_closed`** value: a governed request or response body that
  does not fit inside `max_scan_bytes` is rejected whenever that direction
  actually carries an enforcing body policy — global `mode: enforce` plus either
  anomaly `scoring` with an applicable body rule or at least one applicable
  `action: enforce` rule reading `body_text` / `body_json_path` (request) or
  `response_body` (response), including the body-scoped `FE-ENCODING-001` /
  `FE-ENCODING-002` specials. Per-rule path, method, header, and consumer
  conditions and request-wide `global_exemptions.header_present` suppression are
  honored, so a scoped or exempted enforcing rule does not block an unrelated
  request. Both directions share one decision on the finalized backend-visible
  representation, so H1, H2, and H3 behave identically and a request transformer
  that grows a body past the cap is still governed. A body of exactly
  `max_scan_bytes` is scanned in full and is not oversize.

  Monitor-only operation is deliberately unaffected: with `mode: monitor`, or
  with every body rule left at the built-in monitor default, an oversize body is
  still prefix-scanned and recorded rather than blocked. Oversize bodies handled
  by `fail_closed`, `scan_truncated`, or `block` record fixed-cardinality
  `waf.body_too_large=true` and `waf.body_too_large_target` (`request_body` /
  `response_body`); blocks add `waf.action=blocked` with
  `waf.block_reason=body_too_large`, and prefix scans keep
  `waf.scan_truncated=true`. No body bytes are logged. The explicit `skip` mode
  still avoids body inspection and may avoid buffering a known-oversize request,
  so it emits none of this body-size metadata. Operators who deliberately accept
  prefix-only inspection can opt out with the still-supported
  `on_body_too_large: scan_truncated`; `skip` and `block` are otherwise
  unchanged. The unbounded-SSE decision is also unchanged — the prefix-only
  opt-out concedes the suffix of a bounded body and does not reach a stream with
  no scanned prefix.

- `body_validator` and `openapi_validator` validation diagnostics no longer
  disclose the rejected representation (GHSA-5p2h-fq6q-gwh9). Both plugins used
  to format the offending instance value — or a payload-chosen JSON, XML, form,
  or multipart member name — into the string returned in the client-visible
  reject / problem body and stored in `openapi_validator.request_error` /
  `openapi_validator.response_error`, which every configured logging plugin
  exports. On the response side that republished exactly the upstream
  representation validation exists to withhold, letting a client that can
  trigger an invalid backend response read back a token, credential, or PII
  field; on the request side it copied caller credentials into gateway
  telemetry and every downstream sink. Diagnostics are now assembled under a
  centralized construction contract
  (`plugins::utils::validation_diagnostics`): a compiled-in failure category, an
  allowlisted JSON Schema keyword, and — request side only — a bounded instance
  location. Numeric JSON Pointer segments render as a fixed `#` marker (pointer
  text alone does not prove array shape); an object member name survives only
  when the *configured schema declares it as a JSON property*, and every other
  segment renders as `~`, so a hostile member name is replaced rather than
  sanitized after the fact. Segment count, segment length, and total diagnostic
  length are capped by compiled-in constants. Raw schema paths (including
  `$defs` / reference names), configured XML names and namespaces, and hostile
  `Content-Encoding` coding tokens are never formatted into diagnostics. No
  production path formats a rejected value, an expected `enum` / `const`
  constant, a raw `jsonschema` / `roxmltree` / `prost` rendering, a backend
  `Content-Type`, or the request target, so there is nothing left for truncation
  to protect and no raw-detail escape hatch in configuration or tracing.
  Response-side conversion and decode failures collapse further, to a single
  fixed sentence, because even the class of failure describes an upstream
  representation the client was never entitled to observe.
  `error_truncate_chars` is retained as a size bound and now only narrows
  (`min(configured, 256)`). JSON, XML, form, multipart, protobuf, and gRPC
  validation decisions, statuses, and fail-closed behavior are unchanged;
  `openapi_validator`'s unknown-operation detail no longer interpolates the
  request method and target.

- Matched VirtualService route-level request/response header transforms remain
  authoritative under multiple same-type transformer instances
  (GHSA-3xxr-xhhj-9962). Previously each enabled `request_transformer` /
  `response_transformer` applied its static rules and then consumed the shared
  route-override list, so a later instance could re-add, rename into, or
  overwrite a backend- or client-bound field the matched route had removed or
  set. Enabled instances now apply only static header rules; proxy core applies
  each matched route list exactly once after the last eligible instance on the
  request and response chains (ordinary H1/H2/H3, synthetic/rejection,
  header-capability simulation, and deadline provenance paths). Disabled RTDS
  instances stay complete no-ops and do not suppress route overrides. Query and
  body transform ordering is unchanged.

- Updated the transitive `event-listener` dependency from 5.4.1 to 5.4.2,
  removing the `StackSlot` cross-thread unsoundness reported as
  RUSTSEC-2026-0221.

- `ai_rate_limiter` pre-dispatch prompt reservation no longer under-counts billed
  prompt text when a recognized field is present (GHSA-2r5g-438w-85hr). The
  estimator walks the already-parsed request JSON once and sums billable string
  values, visited object member names (including nested tool / function JSON
  Schema property names), and JSON scalar literals (`null` / booleans / numbers
  at serialized width), so sibling instructions, schema keys, and schema scalars
  cannot be omitted from the reservation. Exclusions are path/context aware —
  unsigned numeric output caps only at the exact paths also read for
  completion-budget reservation (negative/fractional values count fail-closed),
  and multimodal URL/base64/file leaves only inside matching provider
  content-part family and part `type` (member names and unrelated textual
  siblings still count; wrong-family / malformed parts count fail-closed).
  Ordinary strings, including well-formed `data:` URLs in `instructions` or
  schemas, always count; collision-shaped reserved spellings outside those
  contexts count fail-closed. The walk remains a conservative `chars/4`
  heuristic, not provider tokenizer parity.

- Irreversible request egress no longer precedes request-body transformation or
  final request policy (GHSA-4vr5-4wm3-x5xv). `request_mirror` and
  `serverless_function` previously ran their external dispatch in
  `before_proxy`, consuming the *pre-transform* metadata body: a mirror, a
  serverless function, or a pre-proxy authorization function could receive a
  field `request_transformer` was configured to remove or redact, and could be
  handed a request that WAF body rules, OpenAPI request-schema validation,
  request-body validation, or the post-transform `request_size_limiting`
  ceiling went on to reject — a disclosure or billable side effect that no
  later local rejection could retract. Both plugins now have no `before_proxy`
  hook at all and instead run in a new **finalized-request-egress** phase that
  the gateway reaches only after request-body collection, canonical
  `transform_request_body` rewrites, and every `on_final_request_body` policy
  hook have accepted the exact backend-visible representation. The phase hands
  plugins an immutable header/body snapshot; a `pre_proxy` `serverless_function`
  publishes its header injections through a backend header overlay that the
  proxy merges only after re-establishing gateway-owned assertions and the
  egress baggage policy. `ai_federation` also dispatches from this boundary
  rather than from inside the ordered final-body hook pass, so
  `priority_override` cannot move provider I/O ahead of a final request policy.
  The phase is wired on H1/H2 (HTTP, WebSocket handshakes, and native gRPC) and
  HTTP/3, runs at most once per request, and is therefore not repeated by
  retries, which replay the already-finalized body.

  Consequences worth reading before upgrading:
  - A body-forwarding `serverless_function` may now share a proxy with
    `request_transformer`; that composition was previously refused outright
    because the function saw different bytes than the backend. The refusal is
    retained — and widened to cover final request-body policy plugins — for
    registered custom plugins that still declare
    `egresses_request_body_before_finalization()`.
  - A buffered request on a proxy with an egress plugin now finalizes its body
    *before* the backend circuit-breaker gate rather than inside backend
    dispatch, so an open breaker is reported after the upload is read.
  - A mirrored body is now the transformed body and is metered against
    `max_mirrored_request_body_bytes` at its post-transform length; a transform
    that inflates the body past that ceiling drops the mirror instead of
    replaying a truncated payload.
  - Rejections produced by these plugins report
    `rejection_phase = "finalized_request_egress"` instead of `"before_proxy"`.
  - Egress plugins no longer run for HBONE `CONNECT` tunnels, which
    short-circuit the dispatch ladder before the phase boundary.
- Retained-response replay now follows one fail-closed partition contract across
  `response_caching`, `request_deduplication`, and `ai_semantic_cache`
  (GHSA-w27g-65rf-h7xm, GHSA-v4g3-2r4f-f6pc, GHSA-37gg-v9m4-8445). A new shared
  module, `plugins::utils::replay_partition`, defines it.
  - **Caller authorization, not a display subject.** Every key binds the
    authentication mechanism, resolved identity and consumer, peer SPIFFE
    identity, and SHA-256 digests of every credential presented, so two
    tokens that resolve to the same `sub` with different scopes, audiences, or
    tenancy claims can no longer share a retained result. `scope_by_consumer`
    and `cache_key_include_consumer` no longer gate caller isolation; they now
    only add the display identity to the digest. `request_deduplication` also
    stops excluding credential headers from the request fingerprint and binds
    their digests instead, so a same-subject/different-scope credential is a
    conflict rather than a replay. Both credential views are bound under separate
    provenance labels — the pristine inbound wire headers and the live
    backend-visible headers — because the post-routing caches run after
    `ai_stream_router`, which strips the client credential and injects the
    provider's; binding only the live view would collapse two distinct client
    tokens onto one partition. The route's precomputed credential registry now
    includes custom header locations configured by `key_auth`, `jwt_auth`,
    `jwks_auth`, and `oauth2_introspection`. Present credential-bearing query
    parameters are privately digested before authentication/transformer
    stripping and remain mandatory caller dimensions independently of the
    response cache's legacy `cache_key_include_query` setting.
  - **Every caller binds canonical caller context.** A new
    `anonymous_caller_scope` option (`caller_address` default, `shared` opt-out)
    binds the gateway-resolved canonical peer address, which the origin observes
    through Ferrum's regenerated `X-Forwarded-For`. Authenticated callers bind it
    too — the backend receives their regenerated forwarding identity as well and
    may vary policy or content by it — so the `shared` attestation applies to
    anonymous callers only. A caller whose canonical address cannot be derived is
    refused rather than keyed incompletely.
  - **Effective destination is part of the key.** `response_caching` and
    `ai_semantic_cache` run after every route-dispatch plugin and now bind the
    post-routing upstream / host / port / scheme / authority and rewritten path,
    so a header-selected tenant backend cannot replay another backend's result.
    `ai_semantic_cache` now uses that shared contract instead of a plugin-local
    encoding that omitted the proxy *namespace*, and additionally binds a
    length-framed backend-visible request-context digest (original client
    authority and `Host`, method, path, the effective outbound query, and every
    non-credential request header, with credential values digested), so
    cross-namespace and header/query-only tenant collisions are closed for both
    exact and semantic lookup scopes.
    `response_caching` now binds the same complete backend-visible request
    *target* unconditionally: the effective outbound query is a key dimension
    even when `cache_key_include_query` is `false`, which is retained only as a
    legacy keyspace toggle. Its base partition also binds every origin-visible
    request header, including tenant, policy, tracing, correlation, unsupported
    precondition, `Range`, and arbitrary request `Cache-Control` dimensions,
    even when the origin omits them from `Vary`. Only operations this cache
    actually implements stay addressable under the original entry partition:
    `If-None-Match` / `If-Modified-Since`, zero-length `Content-Length`, and a
    pure bare, argument-free `no-cache` / `no-store` refresh when
    `respect_no_cache` is enabled. The complete `Vary` tuple remains an
    additional backend-nominated and operator-configured digest.
    `Authorization`, `Proxy-Authorization`, and `Cookie` are now present as
    dimensions on every retained response, including anonymous responses, so
    the emitted `Vary` contract also protects downstream shared caches that
    cannot see Ferrum's private caller partition. Authorization storage
    admission checks both the pristine inbound and live backend-visible views,
    so a request transformer cannot erase the origin opt-in requirement.
    Conditional revalidation, a pure client no-cache/no-store refresh, and
    `Content-Length: 0` are addressed to a stored entry rather than selecting a
    different one; mixed, argument-bearing, disabled, or unimplemented request
    directives stay bound.
  - **`ai_semantic_cache` lookup moved to the final-request-body stage**
    (priority `2996` → `4057`). It previously looked up in `before_proxy`,
    ahead of `request_transformer` (3000) and every `transform_request_body`
    hook, so the headers, query, and prompt bytes it called "backend-visible"
    were pre-transform, and a hit could bypass a fail-closed final-request-body
    validator — notably `ai_prompt_compressor`, which stages a
    marker-sanitization rejection in its transform and enforces it in its final
    hook at 4055. Lookup now runs in `on_final_request_body_with_context`, after
    that rejection boundary and after every request-body transform, and still
    before `ai_federation` (4060) performs provider I/O. Every `before_proxy`
    admission guardrail continues to run ahead of any hit, exact/semantic Redis
    behavior is unchanged, and store remains in `on_final_response_body`.
  - **Tracing and correlation request headers are bound, not excluded.** The
    request-context partition previously excluded `traceparent`, `tracestate`,
    `b3`, `X-B3-*`, `X-Request-Id`, `X-Correlation-Id` and related names by
    reusing the response-cache sanitation classifier and asserting they are
    fresh "by construction". That is not a valid request-side proof:
    `correlation_id` preserves a valid client-supplied identifier, the plugin
    may be absent entirely, and the value reaches the origin either way. They
    are now bound like any other backend-visible header. The separate
    response-header replay sanitation contract still strips trace identifiers
    from retained responses and is unchanged.
  - **A consumed credential no longer reads as an anonymous caller.** The
    authenticated/anonymous classification now treats a candidate credential
    present in *either* the pristine inbound wire headers or the live
    backend-visible headers as authentication. A credential that an earlier
    plugin removed was previously invisible to the classifier, so such a caller
    was labelled anonymous and `anonymous_caller_scope: shared` could drop its
    canonical-address binding — the one relaxation that is meant to apply only
    to callers who presented nothing.
  - **`request_deduplication` now witnesses routing and request shaping.** Its
    lookup moved from priority `2750` to `3010`, after route dispatch and
    request-transformer header/query rules but before terminate-mode serverless
    execution. Its logical key now binds the effective destination and its
    fingerprint binds the outbound query. Admission rejects every
    same-protocol header/query mutator at or after deduplication (including
    priority overrides), and rejects deferred request-body transformers whose
    final wire bytes were not already established by pre-`before_proxy`
    normalization.
  - **Body-bearing response caching is refused.** `cacheable_methods` now
    accepts only `GET` and `HEAD`; a body-bearing method is rejected at
    admission. At runtime the H1/H2/H3 transport must observe the complete
    upload and privately prove the final pre-`before_proxy` body is empty before
    lookup. Header heuristics cannot prove this for H2/H3 DATA without
    `Content-Length`. Non-empty or unproven bodies bypass lookup and storage,
    and composition admission rejects deferred body transformers that could
    synthesize bytes after lookup.
  - **Canonical length-framed key serialization replaces raw delimiters.**
    `ai_semantic_cache` no longer joins roles, content, and broader fields with
    literal `:`, `|`, and newline bytes, and `response_caching` no longer
    appends `name=value|name=value` Vary suffixes. Keys are digests over typed,
    length-framed fields with explicit sequence counts and presence flags, so a
    legal value containing a delimiter cannot reproduce another request's
    preimage. `response_caching` hashes the *complete* Vary tuple — every name,
    presence flag, and value — rather than only the subset classified as
    sensitive.
  - **Bounded cache maintenance.** `response_caching` overflow eviction now pops
    an insertion-ordered queue in amortized O(1) instead of cloning and sorting
    the entire cache under the accounting mutex for every admitted entry;
    unsafe-method invalidation is an indexed exact lookup plus one ordered range
    over the mutated path's descendants instead of a full-cache scan;
    `vary_index` mappings are reclaimed exactly when their last variant leaves
    instead of by a heuristic sweep; and the uncacheable predictor enforces its
    bound with a FIFO queue instead of a full clone + sort at capacity. Byte-cap
    pressure now evicts oldest-first rather than scanning for expiry.
  - Replay keys, credentials, caller identities, and authorization fingerprints
    are never logged; the remaining diagnostics carry only counts and static
    reasons.
  - **Breaking:** key derivation changed in all three plugins, so entries stored
    by a previous build are unreachable — the intended fail-closed outcome for
    anything keyed under the weaker partition. `response_caching` configs that
    listed a body-bearing `cacheable_methods` entry now fail admission.
    `request_deduplication` and `response_caching` priority overrides and
    deferred body-transform compositions that hide final backend-visible
    request state now fail admission; `mcp_gateway` remains incompatible
    because its response rewrite is derived from mutable live discovery state.
    `ai_semantic_cache` moves
    from priority `2996` to `4057`: a `before_proxy`
    short-circuit that previously lost to a cache hit (`serverless_function`,
    `response_mock`) now wins, and a priority override placing the cache at or
    before a co-located `ai_prompt_compressor` re-opens the bypass this change
    closes.
- Transformer RTDS gates are now bound to the mesh generation that supplied
  their rules (GHSA-83rc-23c9-3g9x). `request_transformer` and
  `response_transformer` read `ferrum.{request,response}_transformer.<scope>.enabled`
  from process-global stores that mesh swapped *after* `ProxyState::update_config`
  had already published the new `RequestEpoch`, and they re-read those stores at
  every request phase. That opened two windows: a plugin built from the new slice
  could read the previous gate during the publication gap, and an already-admitted
  request could read a newly published gate for its whole lifetime — unbounded for
  a slow upload or a slow backend. Scope, rules, defaults, and gate could combine
  into states that existed in neither accepted slice, and one request could
  observe different values at different phases: a request-side marker header
  could be added while its paired body removal was skipped, and a response whose
  buffering preflight answered `false` (selecting streaming) could then have
  header rules applied by a `true` header phase, shipping a response marked as
  sanitized whose body rules never ran.

  The accepted overlay's gate is now materialized into each candidate instance's
  own effective config on the mesh cold path — the same model `fault_injection`
  already used for RTDS fault percentages — as the reserved
  `runtime_overlay_resolved_enabled`. Gate and rules are therefore validated,
  built, and published as one indivisible generation, and each instance resolves
  one immutable decision at construction that every phase reads: buffering
  preflight, request headers/query/body, response streaming/buffering selection,
  response headers/body, retries, and synthetic responses, identically on
  H1/H2/H3. An in-flight request stays wholly on the generation it pinned; a
  rejected slice leaves the previous gate serving in full. Overlay-only changes
  publish as coherent new generations because the affected instances are
  re-stamped for rebuild. The request path no longer performs any overlay lookup,
  removing a per-request `ArcSwap` load. The gate stores are still published
  after acceptance as the provenance surface `response_caching` and
  `request_deduplication` bind retained representations to, and
  `GET /mesh/runtime-overlay` is unchanged. Because that publication lands
  *after* the request epoch, a request whose authenticate/authorize phase spans
  a slice apply keeps the plugin generation it pinned while pinning the newly
  published identity; `response_caching` therefore also binds each stored entry
  to its own generation's effective presentation-policy digest — which now
  covers the materialized gate — so an entry shaped by a superseded generation
  is refetched instead of replayed. An unprovable digest retains nothing.
  `request_deduplication` already bound both halves.
- Route-scoped request/response body ceilings are now enforced by the proxy core
  on every path, not just in body hooks (GHSA-xrfj-852f-645j). The `max_bytes` of
  `request_size_limiting` / `response_size_limiting` is published to the core
  through the plugin cache (precomputed per proxy/protocol) and folded into the
  effective bound of every H1/H2, direct-H2/SNI, native-H3 and H3
  cross-protocol, unary/streaming gRPC, retry, buffering, coalescing, mesh-mTLS,
  and HBONE path *before bytes are forwarded or retained*. Previously
  `request_size_limiting` could not bound an unbuffered chunked, H2/H3
  unknown-length, or streaming-gRPC upload at all — those streamed up to the
  generally larger global ceiling, and to no bound whatsoever when the global
  ceiling was disabled. Specific changes:
  - The effective bound is the strictest *active* (nonzero) value of the route
    ceiling and the applicable global knob, and a global limit of `0`
    ("unlimited") no longer disables an active route ceiling. Multiple instances
    (and a global composed with a proxy-scoped instance) compose to their
    minimum; a looser sibling never relaxes the strictest active bound.
  - Strict buffered response collection (`require_buffered_check: true`) now
    aborts at the route ceiling instead of retaining up to the global allowance
    and only then failing the lower final check, so concurrent requests can no
    longer amplify retained gateway memory toward the global allowance each.
  - Response-size policy now runs over every already-buffered synthetic body
    (mock, `serverless_function`, response/semantic cache, `ai_federation`, dedup
    replay) without depending on another plugin to activate the response
    body-hook gate. A default non-buffering instance previously had no hook on
    that path, so an oversized synthetic body crossed the client boundary.
  - Standards-valid repeated identical `Content-Length` values (RFC 9110 §8.6)
    are parsed per comma-folded member on both request and response fast paths
    via a shared canonical parser, so `Content-Length: 2048, 2048` is compared
    against the ceiling instead of failing a whole-list `parse()` and silently
    skipping the bound. Members are validated as `1*DIGIT` (so `+2048` is not
    honored as a length). A declared length that cannot be reduced to one agreed
    value now fails closed — HTTP 400 on the request side, HTTP 502 on the
    response side — rather than reading as an absent length. Bodyless semantics
    (`HEAD`, `1xx`, `204`/`205`/`304`) remain exempt.
  - Post-transform checks are preserved, and the effective ceiling additionally
    bounds the buffered-representation decode gate and compression admission, so
    a decoding or expanding transform cannot escape the route policy.
  This completes the advisory; [PR #3176](https://github.com/ferrum-edge/ferrum-edge/pull/3176)
  had previously closed only the direct-H2/SNI early-response timing window.
- `soap_ws_security` no longer trusts client media-type selection
  (GHSA-435h-f785-wmm4). Content types are parsed structurally (`type/subtype`
  plus RFC 9110 parameters) and matched by exact essence instead of
  case-insensitive substring search, and the new `content_type.mode` defaults to
  `strict`: every request on a SOAP-protected proxy is governed, so a SOAP
  envelope labelled `application/octet-stream`, `text/plain`, or with no
  `Content-Type` at all is rejected (415) before backend dispatch rather than
  streamed to a backend that routes by path or SOAPAction. `mixed_route` is the
  explicit pass-through opt-out. SOAP 1.1/1.2, `application/xml`,
  `application/xop+xml`, and MTOM/XOP `multipart/related` are supported;
  MTOM validates the root part's envelope (selected by `start`, else the first
  part) and refuses a root part that is mislabelled, re-encoded, or absent.
  A `multipart/form-data; boundary=application/xml` request is no longer
  raw-scanned as an envelope. MTOM package framing is now a strict MIME
  contract, because the parser decides which bytes are the envelope: delimiter
  *lines* are recognized only at the body start or immediately after a CRLF with
  exact CRLF framing and no transport padding (so a `--boundary` sequence inside
  a preamble, a header value, an attachment payload, or the envelope itself is
  inert payload rather than framing); exactly one close-delimiter is required
  and the epilogue after it must not contain the boundary token; part headers
  must be US-ASCII, unfolded, well-formed `token: value` pairs carrying at most
  one `Content-Type` / `Content-ID` / `Content-Transfer-Encoding` each;
  `Content-ID` values must be package-unique and nonblank, and with `start`
  supplied exactly one part may match; and the whole package is framed and every
  part parsed before a root is selected, so no later ambiguity is missed by an
  early return. Part, header, and boundary-candidate ceilings stay fail-closed.
  Previously an unanchored byte-substring search let an attacker plant a
  boundary-shaped sequence in a payload or preamble and have Ferrum validate a
  fabricated envelope — or a truncated one — while the backend executed the real
  root part.
- `soap_ws_security` now authenticates the signer before performing
  attacker-selected XML work (GHSA-9g4v-h9hm-846r). Both the X.509 and SAML
  paths settle certificate trust and `SignatureValue`-over-`SignedInfo`
  verification *before* the first `<Reference>` is resolved, canonicalized, or
  digested, so an untrusted or forged signature costs constant work. Duplicate
  Reference URIs are rejected, the X.509 Reference ceiling drops from 64 to 8,
  SAML accepts exactly one Reference, one bounded id index is built per message
  in place of a full-envelope scan per Reference, the raw-attribute uniqueness
  guard is a single pass for the whole `SignedInfo`, and every canonicalization
  is charged against an aggregate per-message byte budget derived from the body
  length. Previously 64 References to one large element could force well over a
  gigabyte of scanning and canonicalization per unauthenticated request.
- `soap_ws_security` now establishes SOAP identity before authorization
  (GHSA-gfrx-43w6-jq3c). A configuration that establishes a principal
  (`username_token`, `x509_signature`, or `saml`) is an authentication plugin:
  it buffers the body before the authenticate phase, validates there, and
  publishes `authenticated_identity` plus a namespace-correct
  `identified_consumer`, so `access_control`, consumer-scoped `rate_limiting`,
  logging, retries, and chargeback all observe one authoritative SOAP identity
  instead of running before it exists. A timestamp-only policy establishes no
  principal, stays out of the authentication chain, and keeps validating in
  `before_proxy`; the two phases are mutually exclusive by configuration, so no
  message is validated twice. **Breaking:** an identity-establishing instance
  must be the proxy's sole authentication mechanism in either auth mode, and
  composing one with `compression`'s `decompress_request` is rejected at config
  admission; for that identity-establishing form an `on_final_request_body`
  guard additionally refuses to dispatch a message whose bytes changed after
  validation. A timestamp-only instance authenticates nobody and claims no
  integrity over the Body, so it does not bind the representation and stays
  composable with request-body transformers. Also **breaking:** because an
  identity-establishing instance is the proxy's sole authentication mechanism,
  a request the SOAP policy passes through — a non-SOAP media type under
  `content_type.mode: mixed_route`, or a governed envelope with no
  `wsse:Security` header under `reject_missing_security_header: false` —
  reaches the authentication chain with no identity and is answered `401`
  rather than forwarded anonymously; pair those options with a timestamp-only
  instance, or separate anonymous and SOAP-authenticated traffic onto different
  proxies.
- `soap_ws_security` X.509 signatures must now protect the backend-visible SOAP
  Body (GHSA-3mwq-c8j6-9xhp). `Envelope`/`Header`/`Body`/`Security` selection is
  namespace-qualified and positional rather than by local name, duplicate
  namespace-correct envelope elements and misplaced `wsse:Security` headers are
  rejected, and a successful X.509 verification now requires a Reference that
  resolves uniquely to the actual Body. `require_signed_timestamp` rejects a
  message with no Timestamp instead of passing vacuously, and pairing it with
  `timestamp.require: false` is refused at admission. Previously a trusted
  signature over only the Timestamp authorized an arbitrary rewritten operation,
  and a signed lookalike `<Body>` under another namespace could be selected in
  place of the real one. **Breaking:** because Ferrum implements no WS-Security
  attachment-signature transform, an X.509 signature cannot cover the octets an
  `xop:Include` stands for; an enabled `x509_signature` therefore now refuses
  both MTOM/XOP `multipart/related` and bare `application/xop+xml` with `415`
  before dispatch, and an explicit `content_type.allow_mtom: true` alongside it
  is refused at config admission. `username_token` and `saml` keep accepting
  MTOM/XOP — they authenticate who sent the message and never claimed integrity
  over attachment octets. Separately, `reject_missing_security_header: false`
  now governs an *absent header only*: on a governed representation, malformed
  XML, unsupported or ambiguous envelope structure, and XML parsing-budget
  failures reject with `400` regardless of that setting, so a gateway/backend
  parser disagreement can no longer become a pass-through that skips
  authentication, integrity, freshness, and replay for a message the backend
  still executes.
- `soap_ws_security` SAML assertions are now bound and single-use
  (GHSA-f44p-hfqr-cvcc). **Breaking:** `saml.audience`, the new
  `saml.recipient`, and `nonce.replay_scope` are required when SAML is enabled.
  An accepted assertion must carry a mandatory `Conditions` window with both
  `NotBefore` and `NotOnOrAfter` inside the new
  `saml.max_assertion_lifetime_seconds` cap (default 300), must be admitted by
  every `AudienceRestriction`, must carry one supported `SubjectConfirmation`
  (bearer only; `holder-of-key` is refused at admission) whose
  `SubjectConfirmationData` names `saml.recipient`, carries its own bounded
  `NotOnOrAfter`, and omits `InResponseTo`, and its assertion id is claimed for
  single use in the declared replay scope for the same fixed 93 601-second
  horizon as PasswordDigest nonces. `OneTimeUse` needs no special case because
  every accepted assertion is claimed exactly once. `process` scope is a
  single-replica declaration and makes no cross-replica claim; multi-replica
  SAML deployments must use `shared`. Previously a captured signed assertion
  could be replayed indefinitely beside a freshly minted outer Timestamp, and in
  the default configuration an assertion issued for another service by the same
  trusted IdP was accepted. An accepted assertion must also resolve exactly one
  namespace-correct, nonblank Subject `NameID` — the documented SAML principal —
  and that resolution now happens *before* the single-use claim, so an assertion
  that satisfies every binding but authenticates nobody fails closed with `401`
  without consuming replay state. Previously such an assertion was accepted,
  burned its replay id, and returned no principal, silently degrading the
  request to unauthenticated while letting an attacker spend a legitimate
  assertion id.

- `mcp_gateway` aggregate-router mode now validates `tools/call` results against
  discovered tool `outputSchema` values when
  `validation.validate_tool_results` is enabled
  (#3296). Schemas are audited and compiled at catalog construction (local
  references only; depth/node budgets), invalid schemas are refused at admission
  with field-specific diagnostics, and bounded caller-visible results are checked
  before release or audit publication. `structuredContent` and JSON text
  `content` variants are covered without validating a different representation
  than the caller receives; tool `isError` results and well-formed, error-only
  upstream JSON-RPC errors are preserved; event-stream / non-JSON / oversized
  results fail closed with JSON-RPC `-32012`. Transparent mode rejects the
  option because it has no mediated tool catalog. Result bodies are never
  logged.
- Plugin egress no longer inherits ambient proxy configuration
  (GHSA-c4pj-vq6x-53rw). Backend dispatch `reqwest` clients (via
  `BackendTlsConfigBuilder::build_reqwest`), active health-check clients
  (primary, custom-TLS, and degraded DNS-cached fallbacks), the dedicated
  ClickHouse client built by `api_chargeback_sink` for custom CA / mTLS /
  relaxed-verification settings, and the dedicated `spec_expose` and
  `load_testing` clients now call `reqwest::ClientBuilder::no_proxy()` like the
  shared `PluginHttpClient` and its fallback builders. With a proxy selected
  from `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`, Ferrum resolved and screened
  the *proxy* while the proxy resolved and connected to the configured hostname,
  so the ultimate destination never passed `BackendEgressPolicy`. A CI guard
  now fails if any policy-governed `reqwest` builder drops `.no_proxy()`.
- `ws_logging` now enforces backend egress policy on the address it actually
  dials (GHSA-mp2j-gjfp-2vm8). Every connection and reconnection resolves the
  endpoint fresh (bypassing both DNS cache layers), rejects the complete A+AAAA
  answer if any candidate is denied, rechecks each candidate immediately before
  its socket is opened, and dials only screened addresses. The configured
  hostname is retained as the TLS SNI / certificate identity and the WebSocket
  `Host` authority. Previously the endpoint was handed to `tokio-tungstenite`,
  which resolved and dialed it outside the policy, so a hostname could rebind to
  a denied address between admission and any later reconnect.
- `kafka_logging` bootstrap parsing now matches the pinned librdkafka grammar
  (`[proto://]host[:port]`, URL-path truncation, bracketed-IPv6 port rules,
  empty host → `localhost`), so protocol-prefixed denied literals such as
  `PLAINTEXT://169.254.169.254:9092` are rejected instead of evading a
  `host:port`-only screen. Entries whose protocol prefix disagrees with
  `security_protocol` are rejected rather than silently truncating the broker
  list the way librdkafka would.
- ACME issuance and renewal now route every connection through a
  Ferrum-controlled, public-only fresh-DNS connector; reject mixed/private DNS
  answers, answers above 64 addresses, ambiguous legacy numeric IPv4 host
  spellings, endpoint origin drift, credential-directory mismatch, legacy
  credential URL sets, hostile order resource URLs, redirects, and response
  bodies above 1 MiB while preserving HTTPS hostname/certificate verification.
  Fresh DNS plus all TCP candidates share one 30-second wall-clock budget.
  **Breaking:** ACME servers that advertise endpoints on another host or port,
  and pre-0.4 `instant-acme` credentials with embedded `urls`, must be migrated
  to the configured directory origin (#2407).
- `body_validator` now enforces the validation it advertises on all four of its
  surfaces. Configured JSON Schemas are compiled once at plugin construction with
  the `jsonschema` crate under an explicit draft (`json_schema_draft`, default
  `draft2020-12`) instead of being interpreted by a partial handwritten
  evaluator, so `$ref`/`$defs`, union types, conditionals, and other standard
  keywords take effect and malformed schemas, invalid type names, non-local
  references, `$vocabulary` declarations, and over-budget schemas fail
  configuration closed; local JSON Pointer targets are policy-audited even under
  normally literal containers, and no external reference is ever retrieved. XML
  bodies are parsed exactly, without Unicode whitespace trimming, with
  `roxmltree` rather than scanned for balanced tags, so multiple roots, text
  outside the root, invalid names or characters, malformed/unquoted/duplicate
  attributes, and undeclared entity references are rejected. External
  `SYSTEM`/`PUBLIC` identifiers on either the DOCTYPE or an entity declaration
  are refused outright, and `required_xml_elements` matches parsed
  namespace-expanded names. Decoded gRPC protobuf messages must satisfy
  proto2 `required`-field initialization recursively, including inside present
  nested, repeated, map, and extension message values. Unknown top-level config
  keys and unknown keys inside a `protobuf_method_messages` entry are rejected
  before defaults, so a typo can no longer silently replace enforcement with a
  weaker policy. This is a breaking configuration change; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#body-validator-enforcement-hardening).
- **`request_deduplication` Redis ownership is now atomically fenced**
  (GHSA-f72h-jm2p-mc73). Ownership and completion share one versioned operation
  record per logical key. Completion is a compare-and-set on the owner's exact
  in-flight record, so an owner whose `inflight_ttl_seconds` lease expired can
  neither overwrite a successor's completed response nor publish while a
  successor owns the operation; such a completion is discarded locally too
  instead of being replayed as a non-authoritative result. Redis-mode logical
  keys move to `v4`, unconditionally include the matched proxy namespace even
  under an explicitly shared Redis prefix, and the record format is versioned,
  so a rolling upgrade reads and writes disjoint keys instead of mixing
  formats. Current-version records with missing ownership fences, impossible
  state fields, or mismatched inner/outer fingerprints fail closed. A new
  `on_redis_unavailable` field decides outage behavior and **defaults to
  `fail_closed` (HTTP 503)**; deployments that prefer the previous
  process-local fallback must set `on_redis_unavailable: "local_only"`.
- **`request_deduplication` rejects unknown configuration keys**
  (GHSA-h2c3-j3cm-7ghh). The runtime constructor and the OpenAPI
  `RequestDeduplicationConfig` schema now share one closed allowlist, so a
  misspelled `enforce_required` or `sync_mode` fails admission with a
  path-qualified diagnostic instead of silently reverting to a permissive
  default. Redis-only keys are additionally rejected outside
  `sync_mode: "redis"`. Existing configurations carrying stray keys, or
  `redis_*` fields in local mode, must be corrected before upgrade.
- **Completed external operations behind a synthetic response now leave a
  durable completion** (GHSA-8cr6-rw38-7j59). `serverless_function` terminate
  mode and `ai_federation` provider calls declare that their short-circuit
  performed the protected billable operation; deduplication publishes a
  non-replayable 409 completion tombstone — fenced in Redis mode — on buffered,
  empty/HEAD, streamed-fallthrough, and interrupted-delivery outcomes alike.
  Previously an interrupted delivery only held a bare in-flight marker, so an
  identical retry re-executed the operation once `inflight_ttl_seconds` elapsed.
  The tombstone is retained for `max(ttl_seconds, inflight_ttl_seconds)`: it
  replaces a marker that blocked duplicates for `inflight_ttl_seconds`, so a
  deployment configured with `inflight_ttl_seconds > ttl_seconds` never becomes
  re-executable sooner than it was before. Ordinary replayable completions keep
  `ttl_seconds`. The barrier also covers the case where the committed response
  itself cannot be retained as a replay — its request straddled a
  response-presentation-policy publication, or that policy is incomplete or
  `Dynamic` — instead of falling back to the bare in-flight lease. Local
  response-byte admission failure and later protected-completion eviction now
  use an explicit fixed-size execution barrier carrying the completion's own
  authoritative retention clock; neither path can silently restart a shorter
  `inflight_ttl_seconds` lease. Stale owner hooks cannot clear the barrier or a
  successor because every transition remains fingerprint/token fenced. Per-key
  execution barriers are hard-capped at `max_entries`; overflow extends one
  fixed process-global deadline that returns 503 for applicable idempotency-key
  requests, preserving fail-closed retention without unbounded key storage.
  Serverless responses with stable, complete policy provenance are still stored
  as ordinary replays. The provenance contract is documented in
  `docs/plugin_execution_order.md`.
- Versioned standard and `-ebpf` multi-architecture images are now keylessly
  signed in Docker Hub and GHCR and carry final-manifest SLSA provenance plus
  per-platform SPDX SBOM attestations. A fail-closed publication gate requires
  identity, signature, subject-digest, source-commit, provenance, and SBOM
  verification and retracts a GitHub Release if attestation does not succeed
  (compatible with the trusted Cross `create-release.needs` contract).
- `ai_semantic_cache` no longer discards Redis quarantine-`DEL` failures for
  malformed, oversized, empty, or otherwise inadmissible entries. Failed deletes
  are counted with rate-limited warnings that omit keys, payloads, credentials,
  and endpoints, and a bounded per-instance local suppressor (content fingerprint
  + 30s TTL, hard-capped, constant-work capacity eviction) prevents immediate
  re-download/parse/delete amplification of the same poisoned remote value while
  still reconsidering repaired replacements within that bound. Quarantine
  fingerprints are computed only after a Redis value fails admission, so valid
  hits are not hashed for poison markers. Invalid entries remain unserved;
  deletion failure cannot convert a miss into a hit (issue #3213).
- `response_caching` now applies RFC 9111 §3.5 shared-cache admission to the
  live request credential rather than only to a gateway-minted identity, so a
  gateway that forwards `Authorization` to a backend that validates it no longer
  retains the protected response without an explicit `public` /
  `must-revalidate` / `s-maxage` opt-in. `cache_key_include_consumer` remains a
  key-partition option but no longer overrides the origin's storage policy.
  Backend-side revocation, expiry, and scope changes are no longer masked for
  the entry's lifetime (GHSA-7f28-wh4x-5375).
- `Cache-Control` is parsed with quoted-string awareness, so the qualified
  `private="…"` and `no-cache="…"` field-name forms are understood. Named fields
  are removed from the retained entry instead of being replayed from the shared
  cache, and a malformed qualified argument fails closed to the bare directive.
  Connection-scoped and proxy-authentication response fields are also stripped
  before storage (GHSA-fpx2-5v4j-wqxq).
- `1xx`, `206`, and `304` can no longer be configured in
  `cacheable_status_codes`, are refused again at store time, and are never
  replayed; a response carrying `Content-Range` is likewise never stored. A
  caller can no longer poison a shared cache with a partial or validator-only
  representation (GHSA-v7fj-73gm-h625). **Breaking:** existing plugin rows
  containing those statuses must be repaired before upgrade — see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#response-cache-shared-storage-hardening).

### Added

- `fault_injection` now supports UDP and DTLS. Session admission aborts run in
  isolated per-source / per-DTLS-client `on_stream_connect` tasks; per-datagram
  delays and silent abort drops run on `on_udp_datagram` (client→backend) inside
  the established-session hook-ingress worker — never the shared listener recv
  loop — so one peer's delay cannot stall another. UDP/DTLS stream connect skips
  delay so the first-datagram path cannot stack two waits. Delays share the
  existing one-minute ceiling, `FERRUM_MAX_CONCURRENT_FAULT_DELAYS` budget, and
  shutdown cancellation; queued follow-ups remain under the hook-ingress
  byte/datagram caps (#3293).

### Changed

- Kubernetes controller Gateway API and Istio status patch batches now have a
  60-second wall-clock ceiling. A stalled Kubernetes API request can no longer
  retain the reconcile loop indefinitely; unfinished status updates are
  cancelled and retried by a later watch event or periodic full sync.

- Kubernetes controller Gateway API and Istio status writers now share one
  immutable `Arc<[K8sObject]>` generation per reconcile instead of each
  deep-cloning the full unstructured object snapshot. Status semantics,
  bounded update plans, route-conflict handling, and per-writer failure
  isolation are unchanged; deployments with neither writer still pay no
  snapshot clone cost (#3281).

- Gateway API `GRPCRoute` predicates are now translated instead of dropped.
  A pathless `matches[]` entry (method-only, header-only, or a rule with no
  `matches` at all) previously disappeared during translation, so valid gRPC
  rules never routed and their traffic fell through or 404'd. gRPC predicates
  are now represented independently of HTTP paths: an `Exact` `method` with
  both `service` and `method` becomes an exact `=/{service}/{method}` listen
  path, a service-only match becomes a `/{service}/` prefix, and every
  remaining shape materializes on the `/` listener behind a
  `mesh_route_dispatch` URI regex. Every emitted GRPCRoute match — exact-path
  matches included — additionally carries a case-insensitive gRPC
  `content-type` predicate, so a GRPCRoute only ever selects gRPC calls and
  can never capture ordinary HTTP traffic sharing the same hostname and path.
  That gate is the regex transcription of Ferrum's canonical native-gRPC
  content-type contract (`proxy::backend_dispatch::is_native_grpc_content_type`),
  so `application/grpc-web`, `application/grpc-web-text`, and lookalikes such as
  `application/grpcfoo` are refused exactly as the proxy's own dispatcher
  refuses them — gRPC-Web is served by configuring the trusted `grpc_web`
  plugin, which rewrites a verified request to native `application/grpc` before
  backend dispatch. A route-authored `content-type` match still replaces the
  gate, but it is validated against the same native contract first, so an
  operator header can only narrow the protocol boundary. GRPCRoutes share
  HTTPRoute's same-`(hostname, listen path)` collapse **within their own kind**,
  so rule/match ordering and fall-through are preserved. Gateway API v1.5.1
  forbids merging rules between GRPCRoutes and HTTPRoutes: an HTTPRoute and a
  GRPCRoute attached to the same resolved listener with any intersecting
  hostname now resolve to exactly one accepted Route on that listener and
  hostname — oldest `metadata.creationTimestamp`,
  then `{namespace}/{name}`, then `kind` (the last only breaks a total tie: the
  two kinds may share a name and `creationTimestamp` has second granularity),
  independent of rule paths and of the order objects are observed in — and the losing Route materializes no proxy, upstream,
  plugin, or materialized-parent record and is reported `Accepted=False` with
  `reason: Conflicted`. "The same listener" is the *resolved* Gateway listener,
  not the literal `parentRefs[]` selector: a wildcard reference and a reference
  pinning that listener by `sectionName` or `port` contend with each other,
  while two wildcard references that `allowedRoutes.kinds` sends to different
  listeners do not. Ferrum's HTTP-family route representation is
  port-agnostic, so retaining any second parentRef or hostname claim after one
  loss would also retain the Route's proxy on the listener where it lost: the
  entire Route is conservatively withdrawn across every claim as soon as it
  loses on **any** listener. Whole-Route arbitration runs in the same total
  Gateway API order, so a withdrawn Route cannot displace a later valid Route
  elsewhere. Route status always echoes each parentRef the operator wrote.
  Cross-kind routes never collapse, including when separate listeners admit
  them: because the route table is port-agnostic, merging would make each
  backend reachable through the other kind's listener. An identical
  `(hosts, listen path)` therefore fails config validation closed.
  gRPC shapes Ferrum cannot represent exactly
  — `method.type: RegularExpression` (Ferrum cannot constrain a regex operand
  to a single gRPC path segment, so the predicate is refused rather than
  compiled into a matcher that could widen across service/method boundaries)
  or any other non-`Exact` `method.type`, a `method` block with neither
  `service` nor `method`, an `Exact` operand that is empty, over 1024 bytes
  (the CRD `MaxLength=1024`), present but not a string, or outside the v1.5.1
  CRD grammars, a non-native-gRPC `content-type` predicate, a non-`Exact`
  header match, a match entry carrying both `method` and Ferrum's hand-authored
  `path` extension (Ferrum cannot represent their conjunction, so honoring
  either half alone would widen the match), or an explicit
  `method: null` / `headers: null` (an explicit null is malformed input, not an
  omission, and must not widen into the any-gRPC-call or headerless match —
  omitting either field keeps its documented meaning) — are dropped fail
  closed with a field-specific translator warning that never echoes the
  operand.
  See
  [GRPCRoute predicate translation](docs/gateway_api_conformance.md#grpcroute-predicate-translation).

- **Breaking:** `kafka_logging` now fails closed under any restrictive backend
  egress policy, including the default posture. librdkafka resolves bootstrap
  hostnames itself and dials brokers advertised by cluster metadata, and the
  pinned `rdkafka 0.39` exposes no connect/resolve callback, so those addresses
  cannot be screened. The plugin is admitted only under a fully-open policy
  (`FERRUM_BACKEND_ALLOW_IPS=both`, no `FERRUM_BACKEND_DENY_CIDRS`,
  `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false`). Deployments that need Kafka log
  shipping under a restrictive policy should ship through a policy-aware sink
  (`http_logging`, `tcp_logging`, `ws_logging`, `loki_logging`) and bridge to
  Kafka outside the gateway. See
  [Backend Egress / SSRF Protection](docs/configuration.md#kafka_logging-requires-a-fully-open-egress-policy).

- Authenticated `/metrics` now renders TLS certificate gauges from a cached,
  non-secret TLS inventory snapshot and performs no certificate, private-key,
  Kubernetes, HSM, or cloud-secret I/O on the scrape path. The snapshot is
  refreshed by a bounded single-flight background task governed by the new
  `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300, `0` disables it), its
  freshness is exported as `ferrum_tls_inventory_snapshot_timestamp_seconds` /
  `ferrum_tls_inventory_snapshot_max_age_seconds`, and certificate gauges are
  absent until the first snapshot is published. `GET /admin/tls/inventory` still
  collects live.
- Added release governance requiring version tags to match the package version and
  requiring build-out breaking changes to be recorded here.
- Hardened `tcp_connection_throttle` config loading to fail closed for
  unsupported-only global targets, non-TCP scoped attachments, unknown config
  fields, and cleanup intervals above 86400 seconds. Existing deployments must
  remediate these rows before upgrade; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#tcp-connection-throttle-validation-hardening).

## [0.9.0]

Ferrum Edge 0.9.0 represents the current build-out baseline: a multi-protocol
edge proxy with file, database, control-plane, data-plane, mesh, injector, and
node-agent modes plus its plugin and operational tooling. This entry is
intentionally coarse-grained rather than a reconstruction of unreleased history;
see [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) for
published release notes.

[Unreleased]: https://github.com/ferrum-edge/ferrum-edge/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.0
