# Mesh UDP TPROXY Capture

Detailed reference for Ferrum's UDP TPROXY capture datapath: rule ordering, policy
routing, the per-pod-netns producer and its readiness handshakes, the destination
relay, the fail-closed gate table, and the locally-generated egress loop. The
operator overview lives in [mesh.md → UDP TPROXY capture](mesh.md#udp-tproxy-capture);
the host-network placement and the Ambient UDP upgrade/migration procedure live in
[node_agent.md](node_agent.md#host-network-udp-capture-placement-issue-3288).

TCP mesh capture uses iptables `REDIRECT` in the `nat` table: REDIRECT rewrites the
packet's destination to the proxy port, and the proxy recovers the pre-NAT
original destination per-connection via `SO_ORIGINAL_DST`. **This does not work for
UDP.** UDP is connectionless, REDIRECT rewrites the destination with no
per-datagram recoverable original address, and there is no UDP equivalent of
`SO_ORIGINAL_DST`. Captured UDP therefore uses **TPROXY** instead:

- **TPROXY in the `mangle` table** (`FERRUM_MESH_CAPTURE_UDP_ENABLED=true`): TPROXY
  delivers the datagram to a transparent listener socket **without rewriting its
  destination**, so the capture listener recovers the original destination
  per-datagram from the `IP_RECVORIGDSTADDR` cmsg. New `mangle`-table chains
  mirror the TCP include/exclude/CIDR scoping with `-p udp ... -j TPROXY --on-port
  <FERRUM_MESH_CAPTURE_UDP_PORT> --tproxy-mark <FERRUM_MESH_TPROXY_MARK>/<mask>`,
  jumped from `mangle PREROUTING`. Sidecar UDP capture emits
  `FERRUM_MESH_UDP_OUTBOUND`, `FERRUM_MESH_UDP_INBOUND`, and the
  `FERRUM_MESH_UDP_OUTPUT_MARK` / `FERRUM_MESH_UDP_REINJECT`
  locally-generated-egress loop. **Inbound UDP is fail-closed by default:** direct
  pod-app-bound (`--dst-type LOCAL`) datagrams are captured rather than allowed to
  bypass mesh identity and `mesh_authz`. Until a dedicated plaintext inbound UDP
  relay exists, those direct datagrams do not match the egress route table and are
  dropped by the capture listener; authenticated datagram-over-mesh traffic still
  reaches the destination through the mesh UDP relay. Operators that intentionally
  need plaintext/direct inbound UDP for a port must configure
  `traffic.sidecar.istio.io/excludeInboundPorts`, `ferrum.io/excludeInboundPorts`,
  or `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` so the inbound RETURN rule is
  emitted before the UDP TPROXY catch-all. These dst-based PREROUTING chains are
  **PREROUTING-only**, so — unlike the TCP `nat OUTPUT` outbound chain — they carry
  **no proxy-UID `-m owner --uid-owner` self-exclusion** (owner-match is
  OUTPUT-context only). The pod's **own** locally-generated UDP egress (which never
  hits PREROUTING) is captured separately via a `mangle OUTPUT` MARK chain whose
  proxy-UID owner RETURN provides that self-exclusion — see the OUTPUT-MARK loop
  bullet below. The UDP listener port (default `15011`) is **distinct from the TCP
  outbound port** (`15001`) because UDP and TCP cannot share one listener socket.
- **Direction scoping (both chains ride PREROUTING).** The TCP chains stay
  direction-disjoint by hook (inbound = `nat PREROUTING`, outbound = `nat OUTPUT`);
  TPROXY cannot use that (it is PREROUTING-only), so both UDP chains ride
  `mangle PREROUTING` and are kept disjoint by **destination address type**
  instead: the outbound TPROXY rules carry `-m addrtype ! --dst-type LOCAL` (egress
  = a remote destination) and the inbound catch-all carries `-m addrtype
  --dst-type LOCAL` (inbound = the pod's own IP). The **OUTBOUND jump is installed
  before the INBOUND jump** so pod egress is matched first — otherwise the inbound
  catch-all (xt_TPROXY returns `NF_ACCEPT`, ending PREROUTING traversal) would
  swallow egress and bypass the outbound include/exclude/CIDR/port rules. The
  `addrtype` match needs no extra capability beyond the `NET_ADMIN` the init
  container already grants. **Pod-netns only (host-netns node-agent limitation).**
  The `--dst-type LOCAL` discriminator is correct only in the **pod** network
  namespace, where the pod's own IP is `LOCAL` — exactly the injector init
  container's context. The **node-agent DaemonSet runs `hostNetwork: true`** (host
  netns), where pod IPs are **FORWARDED, not `LOCAL`**, so inbound UDP to a pod
  would match the OUTBOUND chain's `! --dst-type LOCAL` discriminator and be
  mis-captured as egress. There is no host-netns-safe `addrtype`-style
  discriminator, so the **node-agent's host-netns iptables fallback emits NO UDP
  TPROXY rules** (`CaptureConfig::host_netns` short-circuits
  `udp_tproxy_commands_for_family`) and logs the limitation when
  `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`. The node-agent has no UDP listener
  either, and rules without a socket are a black hole, so it stays out of the UDP
  datapath entirely; **eBPF does not cover UDP** — the eBPF capture programs are
  `connect()`-cgroup-hooked and TCP-only (no UDP hooks; see the node-waypoint
  UDP/DTLS limitation in [mesh.md](mesh.md#limitations-and-not-supported)). What DOES capture UDP in the host namespace is the
  mesh proxy's **host-network UDP capture path**
  (`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED`, issue #3288), which replaces the
  `addrtype` split with an **ingress-interface** split — see [node_agent.md → Host-network UDP capture placement](node_agent.md#host-network-udp-capture-placement-issue-3288). UDP capture otherwise lives in the **injector's pod-netns path**
  (its iptables init container
  runs in the pod netns, where the pod IP is `LOCAL` so the direction split holds);
  the node-agent itself installs no UDP capture rules.
- **Transparent-routing plumbing** (raw `ip` commands, not iptables): TPROXY
  delivery additionally needs `ip rule add priority <P> fwmark <mark>/<mask> lookup
  <table>` plus `ip route add local 0.0.0.0/0 dev lo table <table>` (and the `ip -6`
  equivalents under the IPv6 fan-out) so the kernel routes the marked datagram to
  the local socket. **The `ip rule` priority is a low constant (`100`), separate
  from the routing TABLE number (`33133`).** The RPDB is priority-ordered and the
  kernel's built-in `main` table rule is priority `32766`; if the fwmark rule sat
  above it, `main` would resolve the marked datagram to its normal route before the
  fwmark lookup engaged and captured UDP would silently black-hole — so the rule
  must sit BELOW `main`. The **routing table is a Ferrum-owned number (`33133`),
  NOT Istio's inbound-TPROXY table `133`** — a co-resident Istio install owns
  `133`, and Ferrum must never risk that table's routes. **Fail closed when the
  routing is unavailable:** TPROXY local delivery is useless without this `ip
  rule`/`ip route`, so when UDP capture is enabled the setup script (a) **fatally**
  preflights `command -v ip` **before** installing any UDP mangle/TPROXY rule (a
  runtime image without `iproute2` fails the `set -e` script and installs nothing —
  TPROXY rules and routing go in together or not at all, never the silent
  half-state), and (b) the load-bearing routing **ADD** commands are **not**
  `|| true` (a failed add aborts the script). Only the delete-before-add stays
  best-effort. **Idempotent setup:** `ip rule add` appends, so the rule is assigned
  the explicit priority (`100`) and is delete-by-priority **before** add (and the
  route is delete-before-add), so a node-agent fallback crash/retry before cleanup
  never stacks a duplicate rule. **Routing installed BEFORE the PREROUTING jumps.**
  The `ip rule`/`ip route` plumbing is emitted **before** the two `mangle
  PREROUTING -j FERRUM_MESH_UDP_*` jumps (which is what actually starts steering UDP
  into the chains). The injector init container runs the whole `set -e` script with
  **no cleanup trap**, so installing the jumps first and then failing on `ip
  rule`/`ip route` would leave the pod with TPROXY chains live but no policy routing
  — the exact half-installed black-hole this design avoids. Emitting routing first
  means a routing failure aborts the `set -e` script before any capture is wired
  (the chains/rules are inert until the jumps are appended last); the node-agent's
  sequential runner gets the same ordering. The mark (default `0x733`, 1843) is **Ferrum-owned
  and deliberately NOT Istio's conventional TPROXY mark `0x539`**: Ferrum's
  higher-priority fwmark rule (priority `100`) matches the mark and steers it to
  the Ferrum table, so defaulting to `0x539` would hijack a co-resident Istio's
  marked packets into Ferrum's table and break Istio traffic. It also avoids common masked CNI mark classes
  such as `0xF00/0xF00`. The default TPROXY mark `0x733` differs from Ferrum's
  NodeWaypoint marks `0x734`, `0x735`, and `0x736`; the `1337` proxy UID is a
  socket-owner match in a separate namespace from `skb->mark`.
- **Default OFF.** The flag defaults off and, when off, emits **no**
  `mangle`/TPROXY/routing rules and binds **no** listener. **The injector
  produces only Sidecar pods, and Sidecar UDP egress is supported (#1808), so
  when the operator sets `FERRUM_MESH_CAPTURE_UDP_ENABLED` the injector installs
  the UDP TPROXY rules AND sets the sidecar's UDP-enable env** — a single central
  switch (`injector::sidecar_udp_capture_supported()`) enables the
  init container's rule emission, the runtime-enable env, and the
  transparent-bind capability (`NET_ADMIN`) together. This matches the
  mesh-runtime listener gate (Sidecar binds the UDP listener), so an injected
  Sidecar with the flag set both diverts UDP into the capture port and binds the
  listener. The rules and the consuming listener come up together behind the **same** flag, and the
  webhook propagates `FERRUM_MESH_CAPTURE_UDP_ENABLED`,
  `FERRUM_MESH_CAPTURE_UDP_PORT`, and `FERRUM_MESH_TPROXY_MARK` from the **same**
  injector config that drives the init container's TPROXY rules (these are not in
  `SIDECAR_ENV_KEYS`, which only copy the injector's own runtime env). The
  **pod-netns rule generator** still installs no UDP TPROXY rules for
  `host_netns` (`CaptureConfig::host_netns` short-circuits
  `udp_tproxy_commands_for_family` — the `--dst-type LOCAL` direction split is
  unsafe in the host netns). Ambient's UDP source-capture rides one of two
  placements, both consuming the same relay/session machinery:

  * **Per-pod-netns producer** (#2013, the default; see the end-to-end status
    note in the next bullet): installs the UDP TPROXY rules and binds the
    transparent sockets INSIDE each enrolled pod's netns via `setns`.
  * **Host-network capture** (#3288, `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true`;
    see [node_agent.md](node_agent.md#host-network-udp-capture-placement-issue-3288)): installs interface-scoped rules and one
    transparent socket in the proxy's own namespace, entering no pod namespace.

  eBPF UDP capture (#1803) stays a non-goal. **Fail-closed on
  malformed settings:** on a capture-relay
  runtime (Ambient or Sidecar), when the flag is set but a UDP capture var is
  malformed, mesh startup aborts (`serve_mesh_runtime` validates the env before
  binding any listener) rather than silently omitting the listener while diverted
  UDP hits a now-unbound port.
- **Consuming UDP listener + datagram-over-mesh egress (Ambient OR Sidecar).**
  When `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`, the **two topologies that relay
  captured UDP** — Ambient (HBONE) and Sidecar (mesh-mTLS) — emit the
  **`PlaintextUdpCapture` mesh listener**. UDP egress materialization is
  dual-transport on exactly those two, so emitting this listener for a topology
  with no UDP relay (EastWestGateway / EgressGateway / waypoints) would divert the
  pod's UDP into a listener with no relay and **black-hole every captured
  datagram**; instead, such a topology with the flag set logs a **one-time
  warning** and emits **no** capture listener, leaving UDP **un-captured** (it
  passes through) rather than captured-then-dropped. (The injector/init
  TPROXY-rule emission for a Sidecar pod is gated to MATCH this — see "Default
  OFF" above: the injector installs the UDP rules and sets the UDP-enable env
  whenever the operator enables capture, so the init container and the runtime
  agree.) On a capture-relay topology the listener is bound on the
  **dual-stack IPv6 wildcard**
  (`[::]`, independent of the TCP outbound listener family) and
  `FERRUM_MESH_CAPTURE_UDP_PORT` (default `15011`) — a
  wildcard bind because TPROXY (`--on-port` only, no `--on-ip`) leaves each
  datagram's original (non-local) destination intact, so a specific-IP socket
  would never receive them; only a wildcard `IP_TRANSPARENT` socket claims the
  captured non-local dests. A single dual-stack `[::]` socket (V6ONLY disabled,
  both v4+v6 transparency + orig-dst opts set) captures **both** v4-mapped and v6
  datagrams; a v4-only bind would black-hole the v6 half when IPv6 capture rules
  (`ip6tables` TPROXY) are present. On a host without IPv6 the `[::]` bind fails
  and the listener falls back to the v4 wildcard (v6 capture then unavailable,
  logged). The listener (`src/proxy/mesh_udp_capture.rs`, Linux-only):
  binds a **transparent** UDP socket (`IP_TRANSPARENT`/`IPV6_TRANSPARENT`, so it
  can claim the TPROXY-diverted datagrams whose destination is the captured
  pod's real `service:port`, not the listener's own bind address), enables
  **`IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR`** to recover each datagram's
  original destination **per-datagram from the cmsg** (TPROXY delivers without
  rewriting the destination, so — unlike the TCP path's `SO_ORIGINAL_DST`
  getsockopt — the orig-dst rides ancillary data), drains datagrams via
  `recvmmsg` (always, since the orig-dst lives in the cmsg `recv_from` cannot
  surface), and keys a lightweight session by **`(client SocketAddr, orig-dst
  SocketAddr)`**. **Datagram-over-mesh egress (dual-transport).** Each
  captured datagram's recovered original destination is matched **strictly
  against `(service VIP, UDP service port)`** by the route table's
  `mesh_udp_egress` index (a UDP analogue of the raw-TCP VIP table,
  forward-derived from the prepared mesh block: UDP service ports ×
  `cluster_ips`). A routable match relays the datagram over a **`udp`-marked
  HTTP/2 CONNECT tunnel** to the LB-selected workload's app port via a
  **dual-transport branch mirroring raw-TCP egress** (the target carries exactly
  one transport tag): **Ambient `mesh.hbone`** rides the HBONE pool
  (`:15008`, capability-probe-gated, identity-pinned `mesh.spiffe_id` →
  `HboneConnectionPool::get_datagram_tunnel`); **Sidecar `mesh.mtls`** rides a
  fresh mesh-mTLS H2 CONNECT (`:15006`/`mesh.mtls_port`, REQUIRED pinned
  `mesh.spiffe_id`, NO capability registry →
  `MeshMtlsConnectionPool::open_datagram_tunnel`). Either way the tunnel carries
  **length-delimited datagrams** (`[u16 big-endian len][payload]`,
  `src/proxy/mesh_udp_frame.rs`) rather than a raw byte stream. Concurrency is a **per-session mpsc+task** model:
  the recv loop only does the route lookup + a (drop-on-full) channel send (UDP
  backpressure is "drop"), and the per-session task opens the tunnel, frames each
  datagram, and writes it. **Return path:** the per-session task reads framed
  reply datagrams off the tunnel and sends them to the pod from a **per-session
  transparent UDP socket bound (non-locally, via `IP_TRANSPARENT`) to the
  captured original destination**, so replies appear **sourced from the VIP:port
  the pod dialed** (without this the pod would drop every reply as coming from the
  wrong address). On the **destination** side, the peer's inbound HBONE terminator
  recognizes the `udp` marker, **unframes the tunnel into a local `UdpSocket`** to
  the CONNECT `:authority` (the open-relay guard admits only destinations this
  terminator owns — ownership-scoped inventory, Sidecar-only loopback privilege —
  and ordinary UDP then screens concrete DNS answers immediately before dial,
  the same contract as the byte-stream relay),
  and frames replies back. **How a destination relay ends (issues #5765,
  #5781, #5858):** only a relay that finished or went idle closes the CONNECT
  stream with a clean HTTP/2 `END_STREAM`: for the datagram relay, a peer
  close (`tunnel_closed`) or an idle expiry (`idle_timeout`). Every other
  ending cut the tunnel short and resets the stream with
  `RST_STREAM(CONNECT_ERROR)` (RFC 9113 §8.5), so the client can tell it from
  a normal close: a socket error (`tunnel_read_error`, `tunnel_write_error`,
  `app_send_error`, `app_recv_error`), a write stall past the write deadline
  (`tunnel_write_stalled`), or an admission revocation (`revoked`). The
  framing itself has no error record. The byte-stream relay follows the same
  rule. A clean close or the idle timeout (`tcp_idle_timeout_seconds`) ends it
  with `END_STREAM`. A socket error on either side, a backend read or write
  deadline (`backend_read_timeout_ms`, `backend_write_timeout_ms`), the
  half-close cap (`FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS`), or a revocation
  resets it with `CONNECT_ERROR`, so a backend that stalls mid-response no
  longer looks like one that finished. The half-close cap runs from the
  first half-close on either side regardless of activity, so after a client
  half-close it can cut a backend that is still streaming its response; when
  the backend half-closed first, the stream's send side is already closed and
  nothing is reset. A revocation resets
  deliberately: the fence cut a live tunnel mid-stream, and a clean close
  would present the bytes relayed so far as the complete stream. The peer
  sees a stream error, not a complete response; the reset is intentional and
  kept. A revocation counts in `ferrum_mesh_hbone_tunnel_revocations_total`
  (label `reason`), never in `ferrum_mesh_hbone_relay_failures_total`, which
  counts backend and socket failures. A reset is
  only possible while the stream's send side is still open, so a failure
  after the relay already half-closed the stream toward the client (the
  backend sent FIN first) leaves that `END_STREAM` in place. Resetting needs a vendored hyper
  (`docs/upstream-hyper-patches/`). The gateway also records why the relay
  ended: the transaction line carries
  `hbone.udp.termination_reason` (`tunnel_closed`, `idle_timeout`, `revoked`,
  `tunnel_read_error`, `tunnel_write_error`, `tunnel_write_stalled`,
  `app_send_error`, or `app_recv_error`). Only `tunnel_closed` and
  `idle_timeout` record `body_completed=true`; every other ending records
  `body_completed=false` with a `body_error_class` — for example
  `connection_refused` when nothing listens on the workload port and the relay
  socket receives the ICMP port-unreachable. A socket-error ending also logs a
  warning, sampled to at most one per 10 seconds (the per-event detail is at
  `debug`). The destination's inbound relay is **transport-agnostic**:
  `is_udp_hbone_connect` matches the `udp` marker regardless of which listener the
  CONNECT arrived on (Ambient `:15008` or Sidecar `:15006`), funnelling through the
  same `build_inbound_hbone_relay_proxy` + `handle_hbone_udp_request`, so no
  destination-side change is involved. A captured datagram matching **no** declared
  mesh UDP destination — or a declared pair whose upstream did not materialize — is
  **dropped** (fail closed; UDP has no fall-through HTTP path and a non-mesh
  destination must never be tunnelled in on a port coincidence). **Scope:**
  egress is **dual-transport** (the materializer gates `Ambient => HBONE, Sidecar
  => SidecarMtls, _ => return`); other topologies materialize no UDP egress.
  **Both skew directions fail closed:** a destination without UDP relay support has no
  `udp` branch, so a `udp` CONNECT to it 404s (its `is_hbone_connect` rejects the
  `udp` marker). DoS bounds are reused from the
  plain UDP proxy: a bounded session map (`FERRUM_UDP_MAX_SESSIONS`, enforced with
  a lock-free atomic count so a spoofed-source flood never walks every DashMap
  shard), an idle-expiry sweep (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`), and the
  recvmmsg batch cap (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`); GRO-coalesced reads are
  framed **per segment**, not as one superblock. When the mesh proxy itself binds
  the capture port (Sidecar, or Ambient with the host-netns placement), that port
  is added to `reserved_gateway_ports()`, so a mesh UDP/DTLS stream proxy or
  ServiceEntry declaring the same listen port is rejected at validation rather
  than racing the capture listener at startup. Ambient's default per-pod-netns
  placement binds inside each pod and therefore does not reserve the host port.
  The listener carries
  `node_waypoint_policy_scope: None` (UDP has no per-source-pod cookie — see the
  NodeWaypoint UDP/DTLS limitation in [mesh.md](mesh.md#limitations-and-not-supported)). **Linux-only** (`IP_TRANSPARENT` + recvmsg cmsg);
  on other platforms the listener is a no-op stub. With the flag off there is no
  listener and no capture rules. **Destination relay e2e-tested:**
  the inbound relay (`handle_hbone_udp_request` / `relay_hbone_udp`) is exercised
  end-to-end by the `functional_mesh_udp_dest_*` functional tests — a `udp`-marked
  mTLS HTTP/2 CONNECT into a spawned Ambient gateway → framed datagram → local UDP
  echo backend → framed reply byte-for-byte (`..._relays_datagram_round_trip`), plus
  the fail-closed negatives (`..._off_allowlist_authority_is_refused` →
  open-relay-guard refuse; `..._untrusted_peer_fails_closed` → STRICT inbound
  rejects an unchained client SVID). These need no root/netns (the client synthesizes
  the `udp` CONNECT). For enrolled Ambient destination pods, the handler maps the
  resolved destination IP through the pod registry and opens the relay socket inside
  that destination pod netns. The registry lookup is unit-pinned, and the full
  source-capture + enrolled-destination round trip (destination pod-netns relay
  socket and reply path inside the destination pod netns) is live-gated by
  `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` in
  `netns-capture-live`.
- **End-to-end status (#1808, #2013): both topologies have a UDP source-capture
  producer.** The **Sidecar** mesh-mTLS datagram relay (`open_datagram_tunnel`) pairs
  the shared codec / materialization / dest-side unframe with the
  **injector pod-netns TPROXY producer** + the current-netns capture
  listener: capture→frame→mesh-mTLS CONNECT (`:15006`)→peer→unframe→local
  `UdpSocket`→return. For **Ambient** (#2013) the
  proxy runs OUTSIDE the pod netns and the node-agent host-netns path emits no UDP
  TPROXY rules, so the **per-pod-netns producer** (`src/proxy/netns_udp_capture.rs`,
  `NetnsUdpCaptureManager` + `ProxyNetnsUdpBackend`) installs the UDP TPROXY rules
  and binds the transparent capture + reply sockets INSIDE each enrolled pod's netns
  (`setns` on a dedicated OS thread), then runs the SAME
  `run_mesh_udp_capture_on_socket` capture/egress loop with a
  `PodNetnsReplySocketFactory`. It reuses the injector's OUTBOUND rule shapes
  (`IptablesPlan::udp_setup_script` / `udp_teardown_script` over the shared
  `udp_tproxy_commands_for_family`) but is **outbound-only** — it does NOT emit the
  inbound `--dst-type LOCAL` chain the injector does. The producer installs rules
  inside EVERY enrolled pod netns (including DESTINATION pods), where an inbound
  chain would capture and drop the HBONE relay's own delivery to the local app
  (`handle_hbone_udp_request` → local `UdpSocket`) AND the source pod's return-path
  reply to the client — black-holing the relayed UDP both ways. It rides the per-pod
  registry the node-agent publishes (also published for Ambient while UDP is
  disabled so stale-rule cleanup can still resolve current pod netns). Before
  touching stale state or binding the unprivileged capture port,
  it installs a dedicated fail-closed OUTPUT guard that mirrors the exact configured
  outbound capture scope. The guard uses alternating chains so guarded retries build
  and activate a replacement before removing the prior guard; a workload that
  pre-binds the capture port therefore gets DROP, never plaintext bypass. The guard is
  removed only after the socket is adopted and the full TPROXY ruleset is live. Failed
  attempts leave a stable-netns cleanup handle with the manager, so pod removal
  retains ownership of guard cleanup and retries transient errors; shutdown
  attempts cleanup through that same stable handle inside the bounded teardown set.
  Cleanup removes every duplicate guard jump and strictly detaches any
  partial live-capture OUTPUT path before releasing the guard. The guarded-to-live
  switch propagates xtables resource errors and also probes stale IPv6 guard chains
  independently of the current IPv6 setting. First-install detection is portable
  across iptables backends: the guard establishes chain existence with `-S` before
  every OUTPUT-jump probe, including strict release of the inactive generation.
  A fresh pod netns therefore never checks a jump whose target chain does not yet
  exist (a case where nft-backed iptables returns exit status 2 while legacy
  returns 1), while any other non-1 status on an existence or jump probe still
  aborts the install and retains the fail-closed cleanup owner. Enrollment also
  starts closed: the node-agent marks each enrolled pod's BPF pod-IP entry UDP-not-ready before registry
  publication, so the host-veth tc classifier drops pod-originated UDP until the
  producer publishes `.udp-ready/<pod_uid>` after the guarded-to-live transition.
  Re-enrollment removes stale readiness first, and both marker and BPF transitions
  reconcile idempotently. Producer stop first persists
  `.udp-ack-required/<pod_uid>`, invalidates stale acknowledgements, then removes
  readiness and waits for the
  node-agent's `.udp-not-ready/<pod_uid>` acknowledgement that the BPF gate closed;
  if the acknowledgement is unavailable, stop retains the in-netns DROP guard
  instead of reopening plaintext. Successful pod removal also persists a
  node-agent-owned `.udp-gate-cleaned/<pod_uid>` proof. A periodic responder in
  both enabled and disabled reconciliation uses that proof to answer a later
  durable `.udp-ack-required` request after the UID has left live pod state,
  including after node-agent restart; a request without verified cleanup proof
  is never acknowledged. Verified handshakes are retained for ten minutes
  (20 times the ordinary 30-second orphan-marker grace), covering producer polls,
  bounded responder batches, and realistic producer/node-agent restarts without
  leaking marker triples forever after a producer ack timeout. The enabled
  producer keeps polling a timed-out close while the UID remains absent and
  removes its retained guard when a late verified acknowledgement arrives; a
  same-UID re-enrollment instead owns the normal pre-open teardown. Once reaped,
  a late producer must persist a fresh request (which refreshes the retention
  window) and retains its fail-closed guard unless the node-agent can
  re-establish cleanup proof. The privileged
  `netns-capture-live` gate
  verifies the real manager/backend source producer, including its transparent
  bind, full HBONE round trip, return-source spoofing, no-route fail-closed
  behavior, capture-disabled absence, idempotent reconcile, pod-deletion cleanup,
  and bind-collision handling. A status-2 active-guard inspection (after the portable
  first-install check above) is a hard failure. The producer tears down
  only its own rules on pod removal / config change /
  shutdown. Its stop signal is also threaded into every per-session tunnel task;
  producer close signals every session task and awaits `JoinSet::shutdown()`,
  which aborts and joins the tasks before the pod-netns reply factory and stable
  netns handle are released. Per-producer loops observe only the manager's stop
  signal, so global shutdown cannot race ahead of the manager's marker retraction
  and retain-guard decision. Graceful shutdown AWAITS the per-netns teardown.
  When Ambient UDP capture is disabled, mesh startup still runs a best-effort
  cleanup manager over the registry so stale pod-netns `FERRUM_MESH_UDP_*` rules
  from a prior enabled crash/kill are removed instead of black-holing workload
  UDP. If it observes a stale `.udp-ready` marker, cleanup durably records the
  pending ack before retracting readiness and waits for the
  node-agent's closed-gate acknowledgement against one shared deadline; without
  that acknowledgement it preserves the stale rules fail-closed and retries
  instead of reopening plaintext. Startup is **fail-closed**: an
  invalid capture config, a runtime image missing `sh`/`ip`/`iptables`, or a required
  IPv6 `ip6tables` mangle table failure aborts mesh startup rather than silently
  retrying with nothing captured. The producer **disables the proxy-UID owner-match
  RETURN** and clears only the implicit sidecar-port exclude defaults — there is no
  co-located proxy in the pod netns to exclude, so all app UDP egress is captured
  unless the operator explicitly set `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS`; keeping the
  sidecar's `1337` or implicit port exclusions here would fail OPEN.
  **Scoped policy:** the registry-derived source workload SPIFFE ID and pod UID are
  fixed per capture manager and stamped into the already-authenticated HBONE baggage
  on every `udp` CONNECT. Destination `mesh_authz` evaluates the `udp` CONNECT against
  the union of the destination-scoped policy set (the same namespace/selector policies
  normal inbound HBONE enforces for the destination workload) and the per-pod
  **source** namespace/selector scope, applying the latter only after the normal
  trusted-assertor + trust-domain checks and an exact live pod-UID↔SPIFFE binding
  check. A ServiceWaypoint resolves the destination scope from the CONNECT authority's
  bound Service workload rather than the waypoint namespace and rejects the CONNECT if
  that destination scope is missing. A default single-namespace CP never exports
  Ambient UDP source evidence outside its configured namespace. Absent, malformed,
  stale, mismatched, or untrusted evidence discards the
  source stamp and falls back to mesh-wide source scoping (still unioned with the
  destination policy set, never broader). NodeWaypoint UDP/DTLS is a
  SEPARATE channel and is unaffected by this one: it derives its source workload
  from the datagram's kernel-reported ingress interface, not from HBONE baggage
  (issue #3286). Ambient producers share one node-wide session limiter, so
  `FERRUM_UDP_MAX_SESSIONS` is not multiplied by pod count. The reconcile /
  rule-generation / registry logic is unit-tested, and the full Ambient live
  source-capture e2e is enforced by
  `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` in
  `netns-capture-live`: two independently routable veth-backed pod netns →
  production manager/backend TPROXY rules and capture socket in the source pod →
  recovered original destination → HBONE datagram tunnel → enrolled destination
  pod-netns relay (registry-mapped, echo bound inside the destination pod) →
  transparent reply sourced from the original VIP:port, with fail-closed
  destination-registry withdrawal. See note 12 of [mesh.md → Protocol x Topology Support Matrix](mesh.md#protocol-x-topology-support-matrix).
  eBPF UDP capture stays a non-goal (#1803 per-pod TC not resurrected).
- **DTLS passthrough — opaque, never terminated.** There is no
  separate `Dtls` `AppProtocol`: a DTLS service port is declared `protocol: UDP` and
  rides the exact same `mesh_udp_egress` datapath as any other UDP datagram. The mesh
  relays DTLS **opaquely** — it never terminates the DTLS session, parses the
  ClientHello, or routes on DTLS SNI (unlike the standalone `passthrough` UDP/DTLS
  stream proxy, which peeks the first ClientHello for SNI). The inner DTLS handshake
  and records are framed and relayed **byte-for-byte** (`mesh_udp_frame`); the
  **outer** mesh hop's confidentiality/integrity come from HBONE / mesh-mTLS, while the
  inner DTLS stays end-to-end between the two workloads: UDP through the mesh is
  datagram-over-stream (Istio likewise does not terminate mesh DTLS). **East-west pod→peer only** for DTLS; external
  **DTLS** egress via the EgressGateway stays out of scope. External `protocol: UDP`
  ServiceEntry egress IS materialized (issue #3263) — see "External UDP egress (EgressGateway)" in [mesh.md](mesh.md#egress-gateway) — including the source-side producer that originates the
  `udp` CONNECT. The opaque relay is regression-pinned by
  `dtls_handshake_datagram_round_trips_opaque` in `mesh_udp_frame`.
- **Fail-closed contract — every relay decision drops/rejects on
  doubt.** The UDP datapath mirrors the raw-TCP egress fail-closed table
  gate-for-gate. Each gate has a regression pin:

  | Gate | Enforced at | Failure mode | Pinned by |
  |---|---|---|---|
  | **Routability** — orig-dst ∈ `mesh_udp_egress` (strict VIP : UDP service port) | source capture, **before** any slot/task is reserved | drop datagram; no session created | `unroutable_destination_is_dropped_without_a_slot` |
  | **Gateway SVID present** | egress dial (HBONE / mesh-mTLS) | end session; **never plaintext** | `open_datagram_tunnel_fails_closed_without_svid` |
  | **Capability probe** — Ambient `Udp` enrolled before dial | egress session (Ambient branch) | drop; no blind dial | probe gate widened to `Http\|Tcp\|Udp`; `egress_transport_branch_selects_by_tag` |
  | **Pinned-peer SPIFFE** | egress dial | refuse dial on missing/corrupt pin | `mtls_expected_peer_is_required_and_fails_closed` |
  | **Transport selection** — materializer stamps exactly one of `mesh.hbone` / `mesh.mtls`; runtime precedence is HBONE → mesh-mTLS | egress session | end session if neither tag (a both-tags target — only reachable via a corrupted upstream, never the materializer — resolves to HBONE by precedence, which never relaxes a gate) | `egress_transport_branch_selects_by_tag` |
  | **Authenticated peer** (dest) — `peer_spiffe_id.is_some()` | dest handler, before any socket opens | 403 | predicate by `authenticated_hbone_*_without_peer_is_rejected` + inline handler reject (`ctx.peer_spiffe_id.is_none()`); the fail-closed OUTCOME is e2e-tested by `functional_mesh_udp_dest_untrusted_peer_fails_closed` (under STRICT inbound the unchained peer is rejected at the TLS layer; the handler's own 403 stays predicate-pinned) |
  | **Open-relay guard** (dest) — ownership-scoped termination inventory; Sidecar-only loopback namespace privilege; DNS answers screened immediately before ordinary TCP/UDP dial (mixed answers keep only safe candidates, all-loopback fails closed); re-checked on the **post-route-override** effective destination from the current RequestEpoch | dest handler | 403 | `inbound_hbone_relay_guard_allows_only_the_terminators_own_destinations`, `inbound_hbone_relay_guard_admits_the_waypoint_termination_inventory_only` |
  | **Marker discipline** — `udp`/`hbone` predicates disjoint; an unknown / future / malformed (incl. non-UTF-8) marker → neither | dispatch | 405 — the non-WebSocket-CONNECT gate (`!is_hbone_connect_any`) rejects an unrecognized CONNECT before routing; both skew directions | `connect_marker_classification_is_exhaustive_and_fail_closed`, `udp_and_hbone_predicates_are_disjoint` |
  | **Session DoS bounds** — count + queued-bytes + idle sweep | source capture | shed / reap | `session_cap_sheds_new_flows_but_serves_existing`, `egress_enqueue_caps_queued_bytes_not_just_count` |
  | **Return-path isolation** — per-session transparent socket bound to orig-dst, send-only, reply only to the captured client | return path | structural (one socket ↔ one client) | `canonicalize_unmaps_v4_mapped_clients_only`, `teardown_does_not_clobber_replacement_session` |

  There is **no plaintext or alternate-hop fallback** anywhere on the relay: every
  dial error path ends the session. The inbound open-relay guard matches declared
  names without resolving them, then both the byte-stream HBONE relay's `connect_backend` and
  the UDP dest handler screen concrete DNS answers immediately before dial
  (`screen_inbound_relay_resolved_ips` on the current RequestEpoch mesh
  snapshot). Mixed answers retain only non-loopback candidates; all-loopback
  answers fail closed. Sidecar retains own-namespace loopback privilege.
  Sidecar `ingress[]` remaps and separately authorized EgressGateway external
  UDP remain distinct and skip that local-termination screen.
- **Locally-generated pod UDP egress: OUTPUT-MARK → lo-reroute → PREROUTING-TPROXY
  loop.** TPROXY runs **only in `PREROUTING`**, never for locally-generated (OUTPUT)
  packets — jumping into a `-j TPROXY` chain from `mangle OUTPUT` is invalid and can
  make iptables setup fail outright. But Linux routes a pod's **own** application UDP
  egress through **OUTPUT → POSTROUTING and never through PREROUTING**, so the
  PREROUTING TPROXY chains alone would never see the primary egress case (outbound
  UDP capture would be inert in the pod netns). Ferrum closes this with the standard
  "TPROXY for locally-generated traffic" pattern (the injector / pod-netns path):
  - A `mangle OUTPUT` chain `FERRUM_MESH_UDP_OUTPUT_MARK` **MARKs** the pod's egress
    (`-j MARK --set-mark <mark>/<mask>`, **not** TPROXY) using the **same fwmark** the
    PREROUTING TPROXY rules use, with the same include/exclude/CIDR/port scoping. It
    leads with a `-m mark --mark <mark>/<mask> -j RETURN` anti-loop guard and a
    proxy-UID `-m owner --uid-owner <uid> -j RETURN` self-exclusion — **owner-match
    IS valid in OUTPUT** (it is invalid in PREROUTING, which is why the dst-based
    OUTBOUND chain carries no owner RETURN). **The MARK rules ALSO carry the SAME
    `-m addrtype ! --dst-type LOCAL` egress scope** as the PREROUTING
    OUTBOUND TPROXY rules — the two render from one shared selector set so the OUTPUT
    capture scoping matches PREROUTING exactly. In the OUTPUT context the pod's own IP
    AND loopback are `--dst-type LOCAL` (locally generated *and* locally destined),
    while genuine egress to other hosts is non-LOCAL; without the scope the catch-all
    `-p udp -d 0.0.0.0/0 -j MARK` would also fwmark pod-to-self / loopback UDP, reroute
    it to `lo`, and TPROXY-capture it — but self/loopback UDP must **never** be captured
    (only real egress). The proxy's own egress is still separately excluded by the
    owner RETURN above; the `! --dst-type LOCAL` scope additionally covers a **non-proxy
    local destination** (another UID's pod-to-self / loopback datagram) the owner RETURN
    cannot. So locally-generated pod UDP egress is captured **only to real, non-local
    destinations**.
  - The **existing** fwmark `ip rule` (priority `100` → table `33133`) + `ip route add
    local 0.0.0.0/0 dev lo table 33133` then reroute the marked datagram to loopback.
    A `local`-type route makes the kernel treat the datagram as destined for this
    host, so it is diverted to the **INPUT** path (not re-emitted via OUTPUT) — OUTPUT
    is therefore traversed **exactly once** and there is **no loop**.
  - The rerouted datagram re-enters and traverses **PREROUTING** once, where a
    dedicated `FERRUM_MESH_UDP_REINJECT` chain (jumped from PREROUTING **first**)
    holds a single **mark-match** `-p udp -m mark --mark <mark>/<mask> -j TPROXY
    --on-port <udp_port> --tproxy-mark <mark>/<mask>` rule that captures it to the UDP
    capture port. It matches by the **mark** (the only reliable selector — TPROXY /
    loopback do **not** rewrite the header, so the datagram still carries its
    **original remote destination** and would otherwise also match the dst-based
    OUTBOUND chain); xt_TPROXY returns `NF_ACCEPT` and ends traversal, so jumping into
    the reinject chain before the OUTBOUND/INBOUND chains guarantees the rerouted
    datagram is TPROXY'd **exactly once** and never double-processed. The reinject
    rule lives in its own custom chain (reaped by name, mark-independent) rather than
    as a bare PREROUTING rule, so the create+flush idempotency that protects the other
    chains against a changed `FERRUM_MESH_TPROXY_MARK` (the built-in PREROUTING chain
    cannot be flushed) covers it too.

  This is the **injector (pod-netns) path only**. The **node-agent host-netns
  fallback emits NO UDP rules at all** (the `addrtype` direction split is wrong
  in the host netns — see the pod-netns-only limitation above; eBPF capture is
  TCP-only), so the OUTPUT MARK chain is likewise not emitted there. **Full datapath
  correctness** of the OUTPUT-MARK → lo-reroute → PREROUTING-TPROXY loop (and of the
  PREROUTING-visible inbound/forwarded capture) is validated by the
  **`netns-capture-live` e2e**; unit tests assert only the emitted rule shapes.

Cleanup (`IptablesPlan::cleanup_commands(udp_capture_enabled)`) removes all four
`mangle` chains (`FERRUM_MESH_UDP_INBOUND` / `FERRUM_MESH_UDP_OUTBOUND` /
`FERRUM_MESH_UDP_OUTPUT_MARK` / `FERRUM_MESH_UDP_REINJECT`), deletes their
PREROUTING jumps **and the `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump**,
and tears down routing state by deleting **only the EXACT Ferrum-owned rule** (`ip
rule del priority 100 lookup 33133`) and **the exact route** (`ip route del local
0.0.0.0/0 dev lo table 33133`) — never `ip rule del lookup <table>` or `ip route
flush table <table>`, which could drop a co-resident route. Every iptables target
is an exact Ferrum-owned object (chain by name, jump by exact `-j <chain>` spec),
so teardown is **mark-independent** and reaps stale state even across a changed
`FERRUM_MESH_TPROXY_MARK` (the mark-match TPROXY rule lives inside the reinject
chain, reaped by name, never as a bare PREROUTING rule). Cleanup deletes stay
best-effort (`|| true`) — unlike the load-bearing setup adds, teardown must never
fail on already-absent state or a missing `ip` binary. The UDP teardown is **gated
on `udp_capture_enabled`**, so a non-UDP install never touches routing state it
never created. The init container already grants `NET_ADMIN`, which covers the
TPROXY/MARK targets, the `addrtype` direction scoping, the owner-match, and the `ip
rule`/`ip route` plumbing — no extra capability is needed.
