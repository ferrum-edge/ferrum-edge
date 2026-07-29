# Multicluster federation live datapath test

This harness validates **bidirectional authenticated cross-cluster east-west
traffic** between two SPIRE-federated Kubernetes clusters on the **real captured
datapath**, plus a trust-boundary negative. It is the live counterpart of the
in-process functional test
`functional_mesh_sidecar_cross_cluster_egress_routes_a_to_c_over_east_west`,
which deliberately COLLAPSES the destination-side iptables redirect; this fixture
runs the real app-port → `:15006` capture across two real clusters with real
SPIRE-issued SVIDs that cross-verify through federated trust bundles.

It is intentionally not self-skipping: the CI job that calls it must provide two
disposable kind clusters on a shared docker network and `docker`, `kind`,
`kubectl`, `curl`, and `python3`.

## What it proves (Stages 2–3 of the M5 cross-cluster roadmap)

Two clusters, `ferrum-fed-a` (trust domain `cluster-a.test`) and `ferrum-fed-b`
(`cluster-b.test`), each run an identical, symmetric topology so traffic can be
driven in BOTH directions:

- a destination service `svc` fronted by a hand-crafted Ferrum **sidecar**
  (`FERRUM_MESH_TOPOLOGY=sidecar`) whose inbound iptables init container
  REDIRECTs the app port `8080` to the proxy's mesh-mTLS inbound listener
  `:15006` — the real captured path the functional test cannot exercise and the
  reason this fixture exists;
- an **east-west gateway** (`FERRUM_MESH_TOPOLOGY=east_west_gateway`, SNI
  passthrough on `:15443`, exposed as a NodePort) that forwards the destination
  service FQDN's SNI to the local `svc` pod's app port;
- a **client** sidecar whose file-config `MultiClusterConfig` points at the PEER
  cluster's east-west gateway NodePort, plus a `curl` container that drives the
  captured request directly at the outbound capture listener `:15001` (mirroring
  the functional test's `plaintext_http_get`);
- a **rogue** client identical to the client and ALSO registered with
  `-federatesWith` the peer trust domain — so its SVID completes valid
  cross-cluster mTLS and the negative proves a DESTINATION-SIDE rejection (the
  peer `svc`'s `deny-peer-rogue` MeshPolicy → 403), not a client-side TLS failure.

The A→B path: cluster A's client captures a plaintext request → cross-cluster
target dialing B's east-west NodePort with `svc.ferrum.svc.cluster.local` as the
ClientHello SNI and trust-domain-only mTLS → B's SNI passthrough → B's `svc` pod
app port `8080` → B's pod inbound iptables REDIRECT `8080`→`:15006` → B's `svc`
sidecar STRICT inbound (verifies cluster A's client SVID via the FEDERATED
bundle) → B's local app → `200 svc-b`. B→A mirrors it.

## SPIRE federation

Each cluster runs its own SPIRE server in its own trust domain (the shared
`tests/k8s/lib/spire.sh` fixture, extended for federation). Bundle exchange is
bootstrapped MANUALLY over `kubectl exec` (`spire-server bundle show -format
spiffe` piped into the peer's `spire-server bundle set`) rather than live
`https_spiffe` bundle-endpoint polling — the manual path is synchronous, needs no
cross-cluster bundle-endpoint reachability, and avoids the chicken-and-egg of
both endpoints having to be up before either can poll. After exchange, each
server holds the peer's federated bundle. EVERY workload entry — `svc`,
`ew-gateway`, `client`, AND `rogue` — is registered with `-federatesWith
spiffe://<peer-td>` so its SPIRE-issued SVID carries the peer trust bundle and the
proxy can verify cross-cluster peers. `rogue` is federated on purpose: the negative
proves a DESTINATION-SIDE rejection, not an incidental client-side TLS failure.
Because both `client` and `rogue` present a valid peer SVID once the trust domain is
federated, STRICT PeerAuthentication alone cannot tell them apart; the destination's
`deny-peer-rogue` MeshPolicy (an identity-scoped DENY on the peer trust domain's
`sa/rogue` principal) is what rejects exactly `rogue` — `mesh_authz` returns `403`
with body `{"error":"Mesh authorization denied"}`, while the federated `sa/client`
still gets `200 svc-<dest>`. The Ferrum proxies fetch
their SVID and federated bundle from the local SPIRE agent
(`FERRUM_MESH_CA_BACKEND=spire_agent`,
`FERRUM_MESH_SPIRE_AGENT_SOCKET=/run/spire/sockets/agent.sock`).

Inbound and outbound cross-cluster trust resolve from DIFFERENT sources in
Ferrum, so the two directions are configured separately:

- **Outbound** (client → peer svc): the mesh-mTLS pool verifies the peer's
  server SVID against the gateway SVID bundle, which DOES include the SPIRE
  Agent's `-federatesWith` peer bundles. So the client needs nothing extra — the
  SPIRE federation above is sufficient for outbound.
- **Inbound** (the peer svc's `:15006` STRICT verifier validating the client
  cert): Ferrum's inbound SPIFFE verifier sources federated trust ONLY from the
  slice's `trust_bundles` — `merge_trust_overlay_into_svid_bundle` intentionally
  DROPS the SVID's `-federatesWith` bundles for inbound, treating the slice as
  authoritative for inbound federation policy. So the `dest` mesh document
  declares the peer trust domain's bundle explicitly (`render_dest_config` fetches
  it live from the peer SPIRE server as base64-DER `x509_authorities`); without
  it the inbound handshake fails "no trust bundle for peer's trust domain". The
  `ew` gateway is SNI passthrough (terminates no TLS) and the `client` is
  outbound-only, so neither declares `trust_bundles`.

## Cross-cluster networking

The two kind clusters share the `kind` docker network. The east-west `Service`
is exposed as a `NodePort` (`31443`); the harness discovers each cluster's kind
node docker IP (`docker inspect`) and feeds the peer's `node-IP:31443` into the
client's `MultiClusterConfig.east_west_gateways[].host`/`port` at runtime. (The
ferrum-mesh Helm chart's `eastWest` Service is ClusterIP-only and not
cross-cluster reachable; this fixture uses hand-crafted manifests with a NodePort
Service instead.)

## Config delivery

All three Ferrum DP roles run with `FERRUM_MESH_CONFIG_PROTOCOL=file` and a mesh
document mounted from a ConfigMap that the harness renders at runtime (the peer
east-west endpoint and the local `svc` pod IP are not known until both clusters
are up). Cross-cluster remote classification rides `MultiClusterConfig.local_cluster`
plus the remote workload's `cluster` field (the `workload_is_remote` cluster-name
fallback), so no live remote-discovery poll is required. The mesh document shape
is `{version?, mesh}` (`MeshConfig`); these documents were validated against the
real `load_mesh_slice_from_file` deserializer + `validate_mesh_fields`.

## Live assertions

Each run writes `target/multicluster-federation/live-assertions.json` using the
shared schema from `tests/k8s/lib/live_assertions.sh`. The required IDs (gated by
`ferrum_live_assertions_require_all_passed`, exactly as the node-waypoint eBPF
live suite gates its `node_waypoint.*` IDs in its own run.sh REQUIRED array):

| Assertion ID | Meaning |
|---|---|
| `multicluster.spire.federation_ready_a` | cluster A's SPIRE server holds cluster B's federated bundle |
| `multicluster.spire.federation_ready_b` | cluster B's SPIRE server holds cluster A's federated bundle |
| `multicluster.federation.trust_bundle_exchange` | both servers hold the peer bundle |
| `multicluster.spire.workload_entries` | federated `svc`/`ew-gateway`/`client`/`rogue` entries registered in both clusters |
| `multicluster.eastwest.gateway_reachable` | TCP connect succeeds to both east-west NodePorts cross-cluster |
| `multicluster.eastwest.a_to_b_authenticated` | A's captured request reaches B's `svc` (200, body `svc-b`) over the federated mTLS path |
| `multicluster.eastwest.b_to_a_authenticated` | the mirror direction (200, body `svc-a`) |
| `multicluster.eastwest.bidirectional_authenticated_traffic` | both directions pass |
| `multicluster.eastwest.untrusted_peer_rejected` | the federated `rogue` client is rejected at the DESTINATION by MeshPolicy (403 `Mesh authorization denied`, not 200/`svc-b`) |
| `multicluster.federation.bundle_revoked_rejected` | (Stage 3) after dropping cluster A's federated bundle from B's dest slice + reload, A→B fails closed (no 200/`svc-b`) |
| `multicluster.federation.trust_restored_recovers` | (Stage 3) re-adding the federated bundle + reload restores A→B (200, body `svc-b`) |
| `multicluster.eastwest.endpoint_blackhole_when_dest_down` | (Stage 3) with B's `svc` scaled to 0, A→B returns a real upstream error (a 5xx from the client sidecar — not a `000` curl-timeout hang, not 200) |
| `multicluster.eastwest.endpoint_recovers_when_dest_returns` | (Stage 3) scaling `svc` back up + re-rendering the gateway for the new pod IP restores A→B (200, body `svc-b`) |

Cross-cluster east-west SNI passthrough + trust federation is GA in
`docs/mesh.md` / `ga_contract.yaml` (issue #2459). The dedicated live workflow
validates this artifact against the contract after the fixture. Poller-driven
cross-cluster endpoint discovery remains Experimental and is excluded from those
rows.

## Run manually

```bash
FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true \
  tests/k8s/multicluster-federation/run.sh
```

Set `FERRUM_MULTICLUSTER_DEPLOY_ONLY=1` to run only the SPIRE/workload deploy
(no traffic, no gate). Set `FERRUM_SKIP_IMAGE_BUILD=1` when the
`ferrum-edge:multicluster-federation` image is already loaded into both clusters
(CI builds + packages it via `.github/actions/package-ferrum-runtime-image`).

## Stage 3 (failure injection)

After the positive/negative traffic tests, the script injects two failure
scenarios (A→B only; each mutates state then self-restores so the next starts
healthy), gated by the `multicluster.federation.*`/`...endpoint_*` assertions
above:

- **Trust revocation** — re-render cluster B's dest mesh document with LOCAL
  trust only (drop the federated cluster-A bundle), `rollout restart` `svc` so it
  loads the revoked config, and assert A→B now fails closed; then restore the
  federated bundle and assert recovery. Proves `slice.trust_bundles` is
  load-bearing for inbound cross-cluster mTLS.
- **Endpoint black-hole** — scale B's `svc` to 0 and assert A→B fails fast (the
  gateway's pinned backend is gone) rather than hanging; then scale back up,
  re-render the gateway for the new pod IP, and assert recovery.

Reloads use `rollout restart`, not SIGHUP: the Ferrum runtime image is distroless
(no shell/`kill`), and the new pod reads the updated ConfigMap at startup
(deterministic, no ConfigMap-mount-propagation race). Because a `svc` restart
changes the pod IP and this file-config fixture's east-west gateway pins a
**static** svc pod IP (no live endpoint discovery), each `svc` replacement also
re-renders + restarts the gateway.

**Deferred — network partition / last-good retention.** Bounded-staleness
last-good retention is a property of the federation / remote-discovery POLLER,
which this static file-config fixture does not run (endpoints are statically
declared, not polled), so a partition here would only prove "down→fail, up→
recover," not the M5 retention machinery. A meaningful partition/last-good test
needs poller-driven remote discovery (a separate fixture); kind also has no
NetworkPolicy enforcement (kindnet), so a clean in-cluster partition primitive is
unavailable here regardless.
