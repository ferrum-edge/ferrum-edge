# Threat Model

What Ferrum Edge defends, what each trust boundary assumes about the peer on the
other side, which attacker capabilities are in scope, and — explicitly — which
residual risks the shipped controls do **not** cover.

This document describes the gateway as it exists today (`0.9.0`, pre-release). It
is a statement of current posture, not a roadmap. Where a control is partial, the
gap is written down rather than softened. The operational counterpart is
[hardening.md](hardening.md); every control named here is configured there.

Subsystem-local threat models remain authoritative for their own surfaces and are
not restated here:

- [node_agent_security.md](node_agent_security.md#threat-model) — node agent
  capabilities, blast radius, and containment.
- [cp_namespace_tenancy.md](cp_namespace_tenancy.md#threat-model-and-validation-evidence)
  — multi-namespace control-plane tenancy.
- [mesh.md](mesh.md) — mesh identity, topologies, and their maturity matrix.

## Assets

| Asset | Where it lives |
|---|---|
| Client request and response bodies in transit | Proxy data path |
| Backend credentials and mTLS private keys | TLS material sources, [pkcs11_tls.md](pkcs11_tls.md) |
| Admin JWT signing secret and operator bearer tokens | `FERRUM_ADMIN_JWT_SECRET`, admin transport |
| Configuration (routes, upstreams, plugins, consumers) | Config database, file config, or CP-distributed snapshot |
| Consumer credentials for the auth plugins | Config store — see [Residuals](#residuals) |
| Control-plane / data-plane bearer material | `FERRUM_CP_DP_GRPC_JWT_SECRET`, token files, trust bundles |
| Mesh workload identity (SVIDs, JWT signing key) | Mesh identity plane |
| Transaction logs and metrics | Logging plugins, `/metrics` |
| The gateway's own network position | Every egress path |

## Boundary 1 — client ↔ frontend

**Assumption about the peer.** None. Every client is untrusted, including
authenticated ones. Client-supplied identity is whatever a plugin proves, and
client-supplied headers are attacker-controlled unless the direct peer is inside
`FERRUM_TRUSTED_PROXIES`.

**Attacker capabilities in scope.** Arbitrary bytes on every supported protocol
(HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, TCP, UDP, DTLS); malformed and
oversized framing; path traversal and encoding tricks; header smuggling; spoofed
`X-Forwarded-For`; connection and stream exhaustion; slow-loris style handshake
and body stalls; replayed datagrams on stream proxies.

**Controls.**

- TLS termination with a configurable protocol floor and a handshake deadline —
  [frontend_tls.md](frontend_tls.md).
- Optional client-certificate verification (mTLS), with CRL enforcement over the
  full chain — [CRL Policy](frontend_tls.md#crl-policy).
- Path canonicalization before routing —
  [request_path_canonicalization.md](request_path_canonicalization.md).
- Request and response size ceilings — [size_limits.md](size_limits.md).
- Connection and per-IP admission bounds, plus load shedding under pressure —
  [overload_manager.md](overload_manager.md).
- Client-IP resolution that only trusts forwarded headers from configured peers —
  [client_ip_resolution.md](client_ip_resolution.md).
- Authenticated datagram client-address envelopes on stream proxies with a
  bounded replay window — [tcp_udp_proxy.md](tcp_udp_proxy.md).
- Request-level policy plugins: authentication, rate limiting, IP restriction,
  bot detection, CORS, and the WAF — [plugins.md](plugins.md), [waf.md](waf.md).
- No panics on the proxy request path; hostile input is rejected with a
  protocol-appropriate error — [error_classification.md](error_classification.md).
- An adversarial fuzz and property lane over the hostile-input parsers —
  [fuzz.md](fuzz.md).

**Residuals at this boundary.**

- The shipped WAF rule pack is **monitor-only by default**. An operator who
  enables the WAF without switching to enforcement gets detection, not blocking —
  [Default rules ship monitor-only](waf.md#default-rules-ship-monitor-only--and-how-to-enforce-them).
  The WAF's own scope limits are stated in
  [Scope: what the WAF does and does not do](waf.md#scope-what-the-waf-does-and-does-not-do).
- With `FERRUM_TRUSTED_PROXIES` unset, forwarded client addresses are trusted on
  the strength of network position alone. That is sound only where the path to
  the load balancer cannot carry spoofed sources.
- Frontend TLS live reload is **opt-in** (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`
  defaults to `false`), so by default a compromised frontend key is replaced by a
  configuration reload or restart, not by a hot rotation. Inline PEM material is
  static until config reload regardless of the flag.

## Boundary 2 — gateway ↔ backend

**Assumption about the peer.** A backend is a configured destination, not a
trusted one. Its certificate is verified unless verification is explicitly
disabled, and its responses are treated as data.

**Attacker capabilities in scope.** A hostile or compromised backend returning
malformed framing, oversized bodies, or hostile headers; an attacker who can
influence DNS resolution or service discovery to steer the gateway at an internal
address; an on-path attacker between gateway and backend.

**Controls.**

- Backend TLS verification and optional mTLS client identity —
  [backend_mtls.md](backend_mtls.md).
- Backend egress / SSRF policy screened on **every** fresh resolve and cache
  insertion, including background refreshes, and enforced by config validation,
  the resolver, the connection pool, service discovery, and plugin endpoint
  screening — [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection).
- Policy-governed `reqwest` clients are built with `no_proxy()`, so inherited
  `HTTP_PROXY`-style process state cannot redirect screened egress to an
  intermediary.
- Response size limits and streaming bounds — [size_limits.md](size_limits.md),
  [response_body_streaming.md](response_body_streaming.md).
- Timeouts, retry bounds, circuit breaking, and health checking —
  [retry.md](retry.md), [load_balancing.md](load_balancing.md).

**Residuals at this boundary.**

- **Revocation coverage is partial.** CRLs are enforced on frontend and admin
  mTLS, frontend DTLS, mesh peer verifiers, rustls backend server verification,
  verified HTTPS/gRPC health probes, and the rustls logging sinks — but **not** on
  DP-to-CP gRPC and **not** on reqwest-based plugin egress; those stacks expose no
  compatible CRL configuration. `kafka_logging` maps the CRL source to
  librdkafka's `ssl.crl.location` instead. See
  [Surfaces CRLs do not reach](frontend_tls.md#surfaces-crls-do-not-reach).
- **Unknown revocation status is accepted by design.** A chain that no configured
  CRL is authoritative for still verifies. A configured CRL list is the issuers
  you chose to police, not a completeness claim —
  [What the verifier enforces](frontend_tls.md#what-the-verifier-enforces).
- **`kafka_logging` requires a fully open egress policy.** Enabling it means
  librdkafka dials cluster-advertised brokers the gateway never screens; the
  plugin therefore fails closed unless the whole backend egress policy is
  disarmed — [`kafka_logging` requires a fully-open egress policy](configuration.md#kafka_logging-requires-a-fully-open-egress-policy).
- `FERRUM_TLS_CA_BUNDLE_PATH` is **exclusive**: setting it replaces the built-in
  webpki roots rather than adding to them. That is the intended behaviour, but a
  bundle missing a public root silently breaks every public-CA backend.

## Boundary 3 — admin plane

**Assumption about the peer.** An admin client presents a JWT the gateway can
verify. The gateway **validates** tokens and never mints them, so token issuance,
role assignment, and revocation are your identity system's responsibility.

**Attacker capabilities in scope.** Network reachability to the admin listener;
a stolen or replayed operator token; a token minted for a different service or a
different namespace; an operator with a lower role attempting a higher-privileged
mutation; scraping the observability endpoints for internal detail.

**Controls.**

- Loopback bind by default, and a **startup refusal** in `database`/`cp` for a
  non-loopback plaintext bind without an allowlist, admin TLS with the plaintext
  port disabled, or the explicit dev escape hatch —
  [Admin API](configuration.md#admin-api).
- JWT validation with a required role claim, a minimum 32-character secret,
  a bounded accepted token lifetime (`FERRUM_ADMIN_JWT_MAX_TTL`), and strict
  audience handling — [Authentication](admin_api.md#authentication).
- Namespace-claim enforcement on namespace-scoped routes, where a malformed `ns`
  claim fails closed —
  [Per-namespace tenancy](admin_api.md#per-namespace-tenancy-ferrum_admin_require_namespace_claim).
- Transport allowlisting, connection caps, and optional admin mTLS —
  [Admin API](configuration.md#admin-api).
- Tiered observability: `/live` minimal and open; `/health` and `/status`
  status-and-ready only without a credential; `/overload` coarse; `/metrics`
  `401` — [Liveness and Health Checks](admin_api.md#liveness-and-health-checks).
- Read-only mode and audit logging —
  [admin_read_only_mode.md](admin_read_only_mode.md),
  [Admin API](configuration.md#admin-api).

**Residuals at this boundary.**

- **Revocation of an issued admin token is not the gateway's job.** Because the
  gateway only validates, a leaked token stays valid until it expires or the
  signing secret is rotated. `FERRUM_ADMIN_JWT_MAX_TTL` bounds that window;
  choose it deliberately.
- `FERRUM_ADMIN_READ_ONLY=true` blocks mutations but does not reduce read or
  token exposure — unredacted management-plane reads such as `/backup` are still
  served, and a plaintext listener still carries operator bearer tokens.
- In the read-only modes (`file`, `dp`, `mesh`) a non-loopback plaintext admin
  bind produces a high-severity **warning**, not a startup failure.
- The audit path defaults to `fail_open`
  (`FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY`): if the pre-mutation audit handoff
  fails, the mutation proceeds unaudited unless you opt into `fail_closed`.

## Boundary 4 — control plane ↔ data plane

**Assumption about the peer.** A data plane authenticates to the control plane
with a plane credential and receives configuration it will serve. The control
plane is authoritative; the data plane is not trusted to author configuration.

**Attacker capabilities in scope.** An on-path attacker on the config-sync link;
a compromised data plane attempting to read another namespace's configuration; a
stolen plane token; a control plane that becomes unreachable, leaving a data
plane serving an ageing snapshot; stream-exhaustion against the CP.

**Controls.**

- gRPC TLS with CA pinning on the data-plane side, and a refusal to bind
  plaintext on a non-loopback address unless explicitly allowed —
  [Transport security](cp_dp_mode.md#transport-security-tlsmtls).
- Short-lived plane JWTs, a distinct-secret requirement against the admin secret,
  and an externally issued token file option so no signing key need exist on the
  node — [Control Plane / Data Plane](configuration.md#control-plane--data-plane).
- Namespace-bound verification credentials with atomic per-generation rotation
  and a bounded retention for an unrevalidatable verifier —
  [Trust binding](cp_namespace_tenancy.md#trust-binding-ghsa-3f2j-wwqw-grmg).
- Per-namespace broadcast partitioning and per-node stream admission budgets —
  [cp_namespace_tenancy.md](cp_namespace_tenancy.md).
- A stale-config fence that makes a data plane unready and, by default, refuses
  new traffic once its last-known-good snapshot ages out with every CP
  unreachable — [Bounded last-known-good configuration age](cp_dp_mode.md#bounded-last-known-good-configuration-age).

**Residuals at this boundary.**

- **DP-to-CP gRPC applies no CRL.** Revoking a CP or DP certificate does not stop
  the config-sync stack; rotate the pinned CA or the plane credential instead —
  [Surfaces CRLs do not reach](frontend_tls.md#surfaces-crls-do-not-reach).
- A shared `FERRUM_CP_DP_GRPC_JWT_SECRET` authenticates the plane, not an
  individual node: any holder can present as any data plane. Per-namespace trust
  bundles narrow this; a single shared secret does not.
- `FERRUM_CP_DP_TRUST_MAX_STALE_SECONDS` deliberately allows a bounded window
  (default 900s) in which the CP keeps authorizing under a trust generation it
  could not revalidate.

## Boundary 5 — mesh identity plane

**Assumption about the peer.** A mesh peer proves a SPIFFE identity, either from
an external issuer or from the configured CA backend. Identity, not network
position, is the authorization input.

**Attacker capabilities in scope.** A workload attempting to present another
workload's identity; a compromised pod in the same node namespace; a peer
negotiating down to plaintext; cross-cluster discovery from an unauthorized
cluster.

**Controls.**

- `FERRUM_MESH_PRODUCTION_MODE=true` unconditionally refuses the dev-only
  self-signed CA bootstrap, the static attestor, the process-local JWT signing
  key, and the no-workload-identity posture; it also refuses the gateway-wide TLS
  verification bypasses at the shared validation path used by both
  `ferrum-edge validate` and startup, and fails startup closed rather than
  serving plaintext when the inbound mTLS/HBONE listener cannot resolve a usable
  mTLS server config — [Mesh Runtime](configuration.md#mesh-runtime).
- A stable trust-domain JWT authority separate from the X.509 root
  (`FERRUM_MESH_JWT_SIGNING_KEY_PEM`).
- Per-remote-cluster discovery credentials that fail a cluster closed when its
  reference does not resolve.
- Mesh authorization policy and REGISTRY_ONLY outbound scoping —
  [Authorization](mesh.md#authorization).
- SPIFFE issuance through SPIRE — [spire_deployment.md](spire_deployment.md).

**Residuals at this boundary.**

- Mesh capability is **not uniform across topologies**. Read
  [Maturity and Support Status](mesh.md#maturity-and-support-status) and
  [Limitations and Not Supported](mesh.md#limitations-and-not-supported) before
  relying on a topology; node waypoint in particular is marked experimental in
  the [README](../README.md).
- Node-agent deployments require elevated host privileges. Its blast radius is
  documented separately in
  [node_agent_security.md](node_agent_security.md#blast-radius-if-compromised)
  and is materially larger than the gateway's.
- The enrolled-pod tc guard directly admits DNS-shaped UDP replies (source port
  53 to a destination port at least 32768) without relay proofs. It also admits
  TCP to workload-declared probe ports from configured node addresses without
  proving that the sender is kubelet. These lanes do not enforce relay
  `mesh_authz`; see [direct-delivery exceptions](node_agent_security.md#direct-delivery-exceptions-in-the-enrolled-pod-guard)
  for their exact checks, attacker prerequisites, and operational bounds.
- Trust-bundle and PeerAuthentication reload paths do not independently reload
  the CRL set (see [mesh.md](mesh.md)).

## Boundary 6 — plugin outbound

**Assumption about the peer.** A plugin endpoint (AI provider, log sink,
JWKS/OIDC issuer, webhook, Redis, database) is a configured destination subject
to the same egress policy as a backend.

**Attacker capabilities in scope.** A hostile or compromised plugin endpoint; an
attacker who can influence a plugin endpoint hostname's resolution; an operator
who configures an endpoint that reaches an internal service; exfiltration of
request content through a logging or AI plugin.

**Controls.**

- Every resolved plugin endpoint IP is screened by the backend egress policy,
  including at config-load time for literal addresses —
  [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection).
- Plugin `reqwest` clients ignore ambient proxy environment variables.
- LDAP and `ws_logging` re-resolve and re-screen every candidate address on each
  connection, bypassing DNS caches.
- Bounded remote signing-key trust for `jwks_auth`
  (`jwks_max_stale_seconds`, never unlimited) — [SECURITY.md](../SECURITY.md).
- Log field redaction and a process-wide retained-byte ceiling on logging
  plugins — [log_schema.md](log_schema.md),
  [Process-wide retained-byte ceiling](plugins.md#process-wide-retained-byte-ceiling).
- Redis-backed rate limiting fails closed **only** with an explicit
  `redis_failure_policy: fail_closed`; the `rate_limiting` default is
  `local_fallback` — [rate_limiting](plugins.md#rate_limiting).

**Residuals at this boundary.**

- **Consumer credentials for `keyauth`, `jwt`, and `hmac_auth` are stored
  recoverable at rest**; `basicauth` credentials are HMAC-hashed. This asymmetry
  is inherent to how those schemes verify and is a property of the configuration
  store, so protect the config database and any `/backup` output accordingly —
  see [plugins.md](plugins.md).
- **Plugin egress is not CRL-checked.** The reqwest-based plugin stack exposes no
  CRL configuration —
  [Surfaces CRLs do not reach](frontend_tls.md#surfaces-crls-do-not-reach).
- Logging and AI plugins are, by design, a path for request and response content
  to leave the gateway. Their destinations are part of your data-handling
  boundary; review [plugins.md](plugins.md) and
  [log_schema.md](log_schema.md) before enabling one.
- `kafka_logging` cannot be egress-screened at all (see Boundary 2).
- **A `rate_limiting` outage multiplies the configured budget by the number of
  reachable pods.** `rate_limiting` defaults to
  `redis_failure_policy: local_fallback`, so while the centralized store cannot
  be consulted each gateway process enforces the configured quota out of its own
  memory: a caller spread across the fleet gets one budget per pod for the
  duration of the outage. Set `fail_closed` on the policies where refusing is
  preferable to over-admitting; the other five rate-limit plugins already
  default to it — [rate_limiting](plugins.md#rate_limiting).

## Residuals

The residuals above, consolidated. Each is a documented property of the current
release, not an open defect awaiting a fix in this document's scope.

| Residual | Boundary | Reference |
|---|---|---|
| CRLs are not applied to DP-to-CP gRPC | 4 | [Surfaces CRLs do not reach](frontend_tls.md#surfaces-crls-do-not-reach) |
| CRLs are not applied to reqwest-based plugin egress | 6 | [Surfaces CRLs do not reach](frontend_tls.md#surfaces-crls-do-not-reach) |
| A chain no configured CRL covers still verifies | 1, 2 | [What the verifier enforces](frontend_tls.md#what-the-verifier-enforces) |
| `keyauth` / `jwt` / `hmac_auth` consumer secrets are recoverable at rest | 6 | [plugins.md](plugins.md) |
| Frontend/admin TLS live reload is opt-in; inline PEM is static until config reload | 1 | [Configuration Reference](configuration.md#tls-material-sources) |
| The gateway cannot revoke an admin JWT it did not mint | 3 | [Authentication](admin_api.md#authentication) |
| Audit handoff defaults to `fail_open` | 3 | [Admin API](configuration.md#admin-api) |
| `kafka_logging` requires disarming the backend egress policy | 2, 6 | [`kafka_logging` requires a fully-open egress policy](configuration.md#kafka_logging-requires-a-fully-open-egress-policy) |
| A shared plane secret authenticates the plane, not a node | 4 | [Trust binding](cp_namespace_tenancy.md#trust-binding-ghsa-3f2j-wwqw-grmg) |
| Bounded authorization under an unrevalidatable trust generation | 4 | [Retention of an unrevalidatable verifier is bounded (issue #3813)](cp_namespace_tenancy.md#retention-of-an-unrevalidatable-verifier-is-bounded-issue-3813) |
| Mesh capability varies by topology; node waypoint is experimental | 5 | [Maturity and Support Status](mesh.md#maturity-and-support-status) |
| The node agent's blast radius exceeds the gateway's | 5 | [Blast radius if compromised](node_agent_security.md#blast-radius-if-compromised) |
| DNS-shaped UDP replies and node-source TCP probes bypass the relay's identity checks | 5 | [Direct-delivery exceptions](node_agent_security.md#direct-delivery-exceptions-in-the-enrolled-pod-guard) |
| WAF default rules ship monitor-only | 1 | [Default rules ship monitor-only](waf.md#default-rules-ship-monitor-only--and-how-to-enforce-them) |
| A `rate_limiting` Redis outage yields one budget per pod (`local_fallback` default) | 6 | [rate_limiting](plugins.md#rate_limiting) |
| Non-loopback plaintext admin only warns in `file`/`dp`/`mesh` | 3 | [Admin API](configuration.md#admin-api) |

## Out of scope

This model does not defend against:

- **A compromised host or container runtime.** An attacker with code execution
  alongside the gateway reads its memory, its resolved secrets, and its private
  keys. Non-extractable keys ([pkcs11_tls.md](pkcs11_tls.md)) narrow this to
  signing-oracle use for the key material they cover; nothing else in this
  document applies.
- **A malicious operator holding admin-JWT signing material.** Such an operator
  can mint any role and any namespace claim. Audit logging records what they did;
  it does not prevent it.
- **Physical access, hypervisor compromise, or a hostile cloud control plane.**
- **A compromised control plane in CP/DP or mesh mode.** A data plane serves what
  its control plane sends; the stale-config fence bounds outage exposure, not
  malicious configuration.
- **A malicious custom plugin.** Custom plugins run in-process with full gateway
  privileges — see [CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md).
- **Compromise of an upstream dependency's source.** The supply-chain gate
  (blocking advisory scan, vendored-crate drift guard, pinned actions) raises the
  cost and shortens detection time; it is not a proof of integrity. See
  [dependency-policy.md](dependency-policy.md).
- **Denial of service beyond the gateway's own admission bounds.** The overload
  manager sheds load ([overload_manager.md](overload_manager.md)); volumetric
  network attacks are the responsibility of the layer in front.

## Reporting

Suspected vulnerabilities go to the private disclosure process in
[SECURITY.md](../SECURITY.md), not to a public issue.
