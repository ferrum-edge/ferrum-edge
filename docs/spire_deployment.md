# SPIRE Deployment for Ferrum Edge

This guide is for operators standing up SPIFFE-based workload identity for a
production Ferrum Edge mesh deployment. Ferrum is an **identity consumer**, not
a SPIFFE control plane: it delegates SVID issuance and trust-bundle
distribution to a separately operated [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
installation, then watches the local SPIRE Agent's Workload API socket (or, for
the gateway-to-mesh transport, mounted SVID files) to pick up rotated
credentials.

Everything Ferrum needs from SPIRE is well-defined and small:

- An X.509-SVID for the workload (mesh sidecar, ambient node-agent / waypoint,
  egress gateway, or north-south gateway).
- The trust bundle for the local trust domain.
- Optionally, federated trust bundles for cross-cluster mTLS verification.

This document describes how to wire that up, what Ferrum does when SPIRE is
unavailable, and the operational signals to alert on.

## Table of Contents

1. [Why SPIRE for production](#why-spire-for-production)
2. [Topology options](#topology-options)
3. [Step-by-step install](#step-by-step-install)
4. [Ferrum configuration](#ferrum-configuration)
5. [SVID rotation cadence](#svid-rotation-cadence)
6. [Multi-cluster federation](#multi-cluster-federation)
7. [Failure recovery runbook](#failure-recovery-runbook)
8. [Pre-prod checklist](#pre-prod-checklist)

## Why SPIRE for production

[SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/) is the open
specification for workload identity. A SPIFFE ID like
`spiffe://cluster.local/ns/payments/sa/checkout` names a workload independently
of its IP, hostname, or session — every SVID (SPIFFE Verifiable Identity
Document) is bound to that ID via an X.509 URI SAN or a JWT `sub` claim.
[SPIRE](https://spiffe.io/docs/latest/spire-about/) is the reference
implementation: a control-plane Server that signs SVIDs after a workload has
been *attested* (proven by a per-platform plugin to be the workload claiming
that ID), plus per-node Agents that expose a local
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
Unix-domain socket so workloads can fetch their identity without storing
long-lived secrets.

Ferrum supports two CA backends selected by [`FERRUM_MESH_CA_BACKEND`](configuration.md):

| Backend | Use it for | What it does |
|---|---|---|
| `internal` | **Development, single-node tests, demos.** Ferrum self-issues SVIDs from a root key on disk. | Holds the CA private key locally, signs SVIDs in-process. Convenient because there are no external dependencies, but the operator owns the root key and has no rotation story beyond restarting Ferrum with new files. |
| `spire` | **Production.** | Delegates issuance and rotation to a separately-operated SPIRE Agent over its Workload API UDS. Ferrum never sees a CA private key. |

Production deployments should always use `spire`. The implementation is in
[`src/identity/ca/spire.rs`](../src/identity/ca/spire.rs) — at startup, Ferrum
opens the streaming `FetchX509SVID` RPC against the agent socket and parks a
background task that continuously refreshes a lock-free `ArcSwap` snapshot of
the current SVID and trust bundles. All identity reads (TLS resolvers,
backend-pool key derivation) come from that snapshot.

For the **gateway-to-mesh** path (a north-south `database`/`file`/`dp`-mode
gateway that originates HBONE traffic into the mesh), Ferrum reads SVID
material from mounted files instead of the Workload API. See
[Step 4. Ferrum configuration](#ferrum-configuration) for the file paths and
SPIFFE ID derivation.

## Topology options

### Single-cluster SPIRE

The default and simplest option. One SPIRE Server (highly available behind a
Service in `spire-system` or similar) plus a SPIRE Agent DaemonSet running on
every node that needs to host Ferrum workloads.

```
              +---------------------+
              |  SPIRE Server (HA)  |   <-- attests Agents, signs Agent SVIDs,
              +----------+----------+        signs workload SVIDs at Agent request
                         |
            +------------+------------+
            |                         |
     +------+------+           +------+------+
     | SPIRE Agent |  (node 1) | SPIRE Agent | (node 2)
     +------+------+           +------+------+
            |  (UDS)                   |  (UDS)
     +------+------+           +------+------+
     | Ferrum pod  |           | Ferrum pod  |   <-- reads /run/spire/sockets/agent.sock
     +-------------+           +-------------+
```

Each cluster gets one trust domain (for example `cluster.local`,
`production.example.com`, or `us-east-1.prod`). Pick a trust domain name that
is stable, unique across all clusters you may ever federate, and matches
whatever you set for [`FERRUM_INJECTOR_TRUST_DOMAIN`](configuration.md) (default
`cluster.local`) so injected sidecars derive matching SPIFFE IDs.

### Multi-cluster federated SPIRE

Each cluster runs its own SPIRE Server + Agent DaemonSet under its own trust
domain. Trust bundles are exchanged so workloads in cluster A can verify peer
SVIDs from cluster B during cross-cluster mTLS.

Ferrum consumes federated bundles two ways:

1. **CP-pushed via mesh slice**: the control plane delivers
   `MeshSlice.trust_bundles` (a `TrustBundleSet` carrying `local` plus a
   `federated: Vec<TrustBundle>`) to data planes. Each entry in `federated`
   names its `trust_domain` and the X.509/JWT authorities for that remote
   cluster. This is the bootstrap path.
2. **Pull-based federation poller** ([`src/modes/mesh/federation.rs`](../src/modes/mesh/federation.rs),
   shipped in [PR #880](https://github.com/ferrum-edge/ferrum-edge/pull/880)):
   a background task hits each `RemoteCluster.federation_endpoint` over HTTPS
   on [`FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS`](configuration.md)
   (default 300s) and overlays the fetched bundle onto `TrustBundleSet.federated`
   without a CP push. Endpoints can serve either the native Ferrum
   `TrustBundle` JSON shape or the SPIFFE Trust Domain and Bundle JWKS profile
   (`{"keys": [{"use": "x509-svid", "x5c": [...]}], "spiffe_refresh_hint": 60}`)
   that SPIRE Server exposes at `/.well-known/spiffe`.

See [Multi-cluster federation](#multi-cluster-federation) below for the full
wiring.

```
   trust domain: us.example.com                  trust domain: eu.example.com
   +----------------------+                       +----------------------+
   | SPIRE Server (us)    |  <-- federation -->   | SPIRE Server (eu)    |
   +----------+-----------+   bundle exchange     +----------+-----------+
              |                                              |
   +----------+-----------+                       +----------+-----------+
   | SPIRE Agent + Ferrum |                       | SPIRE Agent + Ferrum |
   +----------------------+                       +----------------------+
                  \                              /
                   \--- HBONE / mTLS (peer SVID verified -+
                                      against federated   |
                                      bundle pulled by    |
                                      Ferrum's poller)   <+
```

## Step-by-step install

### 1. Choose a trust domain

- **One trust domain per cluster.** Federation breaks if two clusters share a
  trust domain — peer SVID verification cannot tell same-named identities in
  different clusters apart.
- Use a DNS-style name (`cluster.local`, `eu-west-1.prod.example.com`) that
  matches what Ferrum's injector derives. Ferrum's injector builds SPIFFE IDs
  as `spiffe://{trust_domain}/ns/{namespace}/sa/{serviceaccount}`
  ([`docs/mesh.md` SPIFFE ID derivation](mesh.md)).
- If you anticipate federation, write the trust-domain name into your
  cluster-naming standard so you do not need to re-issue every SVID later.

### 2. Install SPIRE Server

Do **not** fork or vendor SPIRE. Install the upstream chart that the SPIFFE
community publishes:

- Helm chart: [`spiffe/spire`](https://artifacthub.io/packages/helm/spiffe/spire)
  (the `spire` umbrella chart includes Server, Agent, and the SPIFFE CSI driver).
- Reference docs:
  [SPIRE quick start for Kubernetes](https://spiffe.io/docs/latest/try/getting-started-k8s/),
  [SPIRE Helm chart](https://github.com/spiffe/helm-charts-hardened).

A minimal `values.yaml` override for production:

```yaml
global:
  spire:
    clusterName: prod-us-east-1
    trustDomain: us-east-1.prod.example.com   # match what Ferrum will use
    recommendations:
      enabled: true                            # turn on production defaults

spire-server:
  ca_key_type: ec-p256
  ca_ttl: 24h                                  # CA cert lifetime
  default_x509_svid_ttl: 1h                    # workload SVID lifetime
  default_jwt_svid_ttl: 5m
  controllerManager:
    enabled: true                              # CRD-driven registration

spire-agent:
  socketPath: /run/spire/sockets/agent.sock    # Ferrum's default
  workloadAttestors:
    k8s:
      enabled: true                            # required for Ferrum pod attestation
```

Pin the chart version. CRDs in the controller-manager change between minor
releases; mixing chart versions across clusters in a federation is the easiest
way to get a "looks installed but doesn't issue" failure mode.

### 3. Install SPIRE Agent DaemonSet

The SPIRE Agent is bundled in the same chart (`spire-agent` sub-chart). It must
run on every node where a Ferrum workload (mesh sidecar, ambient node-agent,
waypoint, gateway, egress gateway) will be scheduled.

The Agent exposes the Workload API socket at the path you set above (default
`/run/spire/sockets/agent.sock`). Pods reach it via a `hostPath` mount or the
[SPIFFE CSI driver](https://github.com/spiffe/spiffe-csi); the CSI approach is
preferred because it avoids granting `hostPath` to every Ferrum pod.

### 4. Register Ferrum workloads

A registration entry tells SPIRE "this attested workload should be issued
SVIDs for this SPIFFE ID". You write one entry per workload-shaped thing
(per ServiceAccount, typically).

#### 4a. North-south gateway entry (one per gateway deployment)

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: ferrum-gateway
spec:
  spiffeIDTemplate: spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ferrum-edge
      ferrum.io/role: gateway
  workloadSelectorTemplates:
    - "k8s:ns:{{ .PodMeta.Namespace }}"
    - "k8s:sa:{{ .PodSpec.ServiceAccountName }}"
  x509SVIDTTL: 1h                          # X.509-SVID lifetime
  federatesWith: []                        # add federated trust domains here
```

`x509SVIDTTL` is the current field on the SPIRE controller-manager
`ClusterSPIFFEID` CRD. Older chart versions accept a deprecated `ttl` shorthand
— prefer the explicit field name on any fresh install.

For one-off gateways (no controller-manager), the equivalent CLI is:

```bash
kubectl exec -n spire-system spire-server-0 -- \
  spire-server entry create \
    -spiffeID    spiffe://us-east-1.prod.example.com/ns/gateway/sa/ferrum-edge \
    -parentID    spiffe://us-east-1.prod.example.com/spire/agent/k8s_psat/prod-us-east-1/<agent-node-uuid> \
    -selector    k8s:ns:gateway \
    -selector    k8s:sa:ferrum-edge \
    -ttl         3600
```

#### 4b. Mesh workload entry (per ServiceAccount)

Use a `ClusterSPIFFEID` keyed by namespace + ServiceAccount, scoped by
namespace selector. One entry covers every pod that runs as that SA:

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: ferrum-mesh-workloads
spec:
  spiffeIDTemplate: spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}
  podSelector:
    matchExpressions:
      - key: ferrum.io/mesh
        operator: In
        values: ["enabled"]
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values: [kube-system, kube-public, kube-node-lease, spire-system]
  workloadSelectorTemplates:
    - "k8s:ns:{{ .PodMeta.Namespace }}"
    - "k8s:sa:{{ .PodSpec.ServiceAccountName }}"
  x509SVIDTTL: 1h
```

The Ferrum injector accepts two opt-in markers
([`docs/mesh.md` injector section](mesh.md)): the `ferrum.io/inject=true`
*annotation* and the `ferrum.io/mesh=enabled` *label*. SPIRE's
`ClusterSPIFFEID` `podSelector.matchExpressions` matches Kubernetes labels
only — so the registration entry MUST key off the label, not the annotation.
Operators that drive injection exclusively via the annotation should also
stamp `ferrum.io/mesh: enabled` (or some other agreed label) on the same
pods so SPIRE can pick them up. Alternatively, broaden `podSelector` to
match an `app.kubernetes.io/part-of` or per-ServiceAccount label that you
already set on workload pods.

#### 4c. Verify issuance

```bash
# Confirm the entry is present
kubectl exec -n spire-system spire-server-0 -- \
  spire-server entry show -spiffeID spiffe://us-east-1.prod.example.com/ns/gateway/sa/ferrum-edge

# From a pod that should have an SVID, ask the local agent
kubectl exec -n gateway deploy/ferrum-edge -- \
  /opt/spire/bin/spire-agent api fetch x509 \
    -socketPath /run/spire/sockets/agent.sock
```

The `api fetch` command should print one or more `Received N svid after Xs`
lines. If it hangs, the pod is not being attested — check that the
ServiceAccount and namespace labels line up with the `ClusterSPIFFEID`
selectors and that the SPIRE Agent on that node is healthy.

## Ferrum configuration

### Mesh-mode pods (sidecar, ambient, waypoint, egress)

These consume the Workload API directly:

```bash
FERRUM_MODE=mesh
FERRUM_MESH_CA_BACKEND=spire
FERRUM_MESH_SPIRE_AGENT_SOCKET=/run/spire/sockets/agent.sock
FERRUM_MESH_CERT_TTL_SECONDS=3600        # hint only; SPIRE clamps to its own policy
```

Mount the agent socket into the pod. Two equivalent options:

```yaml
# Option A: hostPath mount (simplest, requires hostPath PSP/PSA allowance)
volumes:
  - name: spire-agent-socket
    hostPath:
      path: /run/spire/sockets
      type: DirectoryOrCreate
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire/sockets
    readOnly: true

# Option B: SPIFFE CSI driver (preferred when available)
volumes:
  - name: spire-agent-socket
    csi:
      driver: csi.spiffe.io
      readOnly: true
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire/sockets
    readOnly: true
```

The startup contract is implemented in [`SpireAgentCa::new`](../src/identity/ca/spire.rs):
Ferrum waits up to 30s for the first SVID to arrive from the agent. If it does
not arrive in time, startup continues with the CA in a degraded state and
serves once the agent pushes one — incoming mTLS handshakes fail until then.

### North-south gateway pods (database / file / dp / cp modes)

The gateway uses the same gateway-SVID file-watch path that PR-#880's
trust-bundle changes documented. SPIRE writes the SVID to disk for the gateway
to pick up, and Ferrum polls the files for atomic content changes once per
second (see `run_gateway_svid_file_rotation_loop` in
[`src/proxy/mod.rs`](../src/proxy/mod.rs)).

```bash
FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/gateway-chain.pem
FERRUM_GATEWAY_SVID_KEY_PATH=/etc/ferrum/svid/gateway-key.pem
FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH=/etc/ferrum/svid/trust-bundle.pem
# Fallback only when the leaf cert has no SPIFFE URI SAN:
# FERRUM_GATEWAY_SPIFFE_ID=spiffe://us-east-1.prod.example.com/ns/gateway/sa/ferrum-edge
```

Cert chain must be leaf-first PEM. Key must be unencrypted PKCS#8
(`BEGIN PRIVATE KEY`) — legacy `BEGIN RSA PRIVATE KEY` and
`BEGIN EC PRIVATE KEY` are rejected. Use the SPIFFE Helper sidecar
([github.com/spiffe/spiffe-helper](https://github.com/spiffe/spiffe-helper))
to write the agent-supplied SVID into these paths on rotation. The helper's
`add_intermediates_to_bundle = true` option is recommended so intermediates are
included in the trust bundle.

Alternative: a small init/sidecar container that runs `spire-agent api fetch
x509 -write /etc/ferrum/svid/` is simpler if you do not need long-running
helpers.

### JWT-SVIDs

Ferrum's current SPIRE Agent client only consumes **X.509-SVIDs** — see
[`fetch_x509_svid_stream` in `src/identity/workload_api/client.rs`](../src/identity/workload_api/client.rs)
which leaves `jwt_authorities: Vec::new()` on the bundle it returns. The
`jwks_auth` plugin used by mesh `RequestAuthentication` does its own JWKS fetch
via plugin HTTP, independent of SPIRE. There is therefore no JWT-SVID
registration entry you need to add for Ferrum, and `default_jwt_svid_ttl` on
the Server is irrelevant for Ferrum's identity consumption today.

If you also issue JWT-SVIDs to non-Ferrum workloads in the same SPIRE
deployment, that is unaffected.

## SVID rotation cadence

The defaults are conservative and match SPIFFE community guidance:

| Material | SPIRE default TTL | SPIRE rotation trigger | Ferrum behavior |
|---|---|---|---|
| Agent SVID | 1h | Agent rotates at half-life (~30m) | Transparent to Ferrum — the Workload API stream continues across rotation |
| Workload X.509-SVID | 1h (configurable per entry) | Agent pushes a fresh SVID over the streaming `FetchX509SVID` RPC roughly halfway through the TTL | `SpireAgentCa`'s background task `ArcSwap::store`s the new snapshot; reads are lock-free |
| Trust bundle | rotates with CA TTL (24h default) | Pushed in the same stream when it changes | Ferrum re-validates and stores; mTLS verifiers pick it up via the same `ArcSwap` |
| Gateway file SVID | matches the file producer (SPIFFE Helper TTL, typically 1h) | File producer writes new content | Ferrum's 1s file-fingerprint poll detects change → bundle reloaded → `backend_svid_rotation_tx` revision bumped → backend TLS configs drained, active HTTP health probes restarted, optional pool drain after [`FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`](configuration.md) |

The narrow live-reload carve-out documented under "TLS Rotation" in
`CLAUDE.md` is the **only** TLS material Ferrum hot-reloads from disk. Other
TLS files (frontend cert, frontend key, backend CA bundle outside the gateway
SVID flow) remain restart-required.

### Monitoring

Ferrum exposes these mesh identity series on the Prometheus endpoint
([`src/plugins/mesh/prometheus_helpers.rs`](../src/plugins/mesh/prometheus_helpers.rs)):

| Metric | What it tracks |
|---|---|
| `ferrum_mesh_cert_expiry_seconds{spiffe_id,source}` | Seconds until the observed X.509-SVID expires. `source="spire_agent"` for the Workload API path, `source="rotation"` for Ferrum-as-issuer, `source="workload_api"` for the in-process Workload API server. |
| `ferrum_mesh_cert_rotation_failures_total{spiffe_id,source}` | Counter of failed SVID fetches or rotation attempts. |
| `ferrum_mesh_ca_health{ca_type}` | `1` healthy, `0` unhealthy. `ca_type="spire_agent"` flips to `0` on stream disconnect or fetch failure. |
| `ferrum_mesh_trust_bundle_version{trust_domain,source}` | Monotonic version incremented when the observed trust bundle roots change. |

The Helm chart's
[`PrometheusRule`](../charts/ferrum-mesh/templates/alerts-prometheusrule.yaml)
adds alerts on cert-expiring-soon, rotation failures, CA unhealthy, and SVID
expiry below one hour out of the box — see
[Alerting reference](#alerting-reference) below. When the bundled Grafana
dashboards land under `charts/ferrum-mesh/dashboards/`, the certificate-posture
dashboard renders all four series with operator-friendly variable selectors.

## Multi-cluster federation

This builds on the federation poller from
[PR #880](https://github.com/ferrum-edge/ferrum-edge/pull/880).

### 1. Choose distinct trust domains per cluster

Already covered in [Step 1](#1-choose-a-trust-domain). The names you choose
here flow into all of (a) SPIFFE IDs minted in each cluster, (b)
`MeshConfig.trustDomain` for each Ferrum mesh deployment, (c)
`MultiClusterConfig.remote_clusters[].trust_domain` entries that name the peer
clusters.

### 2. Expose each cluster's federation endpoint

The SPIRE Server can expose its trust bundle in the SPIFFE Trust Domain JWKS
profile. The Ferrum federation poller accepts both that format and Ferrum's
native `TrustBundle` JSON shape. Common deployment patterns:

- **SPIRE Server `federation.bundle_endpoint`** — built into SPIRE Server,
  serves the JWKS at the configured address. Documented in
  [SPIRE Federation](https://github.com/spiffe/spire/blob/main/doc/spire_server.md#federation-configuration).
- **Custom HTTPS endpoint** — a small ingress in front of SPIRE that exposes
  the trust bundle via `spire-server bundle list -format spiffe -output json`.

Both must be reachable from the *consuming* clusters' Ferrum pods over HTTPS.
The poller rejects link-local, loopback, and cloud metadata IPs at slice apply
for SSRF safety.

### 3. Configure each Ferrum mesh deployment

Declare the remote clusters in `MultiClusterConfig.remote_clusters` (CP-pushed
config or native MeshSubscribe):

```yaml
multi_cluster:
  local_cluster: us-east-1
  remote_clusters:
    - name: eu-west-1
      trust_domain: eu-west-1.prod.example.com
      network: network-eu
      control_plane_url: https://cp.eu-west-1.internal:50051
      federation_endpoint: https://spire-server.eu-west-1.example.com/.well-known/spiffe
```

Set the poller env knobs (defaults are usually fine):

```bash
FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=300   # 5 min; 0 disables the poller
FERRUM_MESH_FEDERATION_POLL_TIMEOUT_SECONDS=30
# FERRUM_MESH_FEDERATION_FAIL_OPEN=false           # false blocks CP fallback until a bundle is polled; true allows bootstrap fallback
```

If your federation requires alias trust domains during a migration (for
example, two SPIRE servers transitionally issuing under both `legacy.example`
and `us-east-1.prod.example.com`), set:

```bash
FERRUM_MESH_TRUST_DOMAIN_ALIASES=legacy.example,us-east-1.prod.example.com
```

This relaxes the strict same-trust-domain check on HBONE baggage
`source.principal` — it does not change peer-cert verification, which still
needs a matching root in the federated bundle set.

### 4. Verify

```bash
# JWT-auth admin endpoint exposing the cached federated bundles
curl -H "Authorization: Bearer $FERRUM_ADMIN_JWT" \
  https://ferrum-admin.us-east-1.internal:9443/mesh/federation
```

Expected: each declared remote cluster appears with a `bundle_age_seconds`
below your poll interval and a non-empty `x509_authorities` count.

Watch the Prometheus series:

- `ferrum_mesh_federation_last_success_timestamp_seconds{trust_domain="eu-west-1.prod.example.com"}` should advance every `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS`.
- `ferrum_mesh_federation_bundle_age_seconds{trust_domain="..."}` should stay below `2 * FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` under healthy operation.
- `ferrum_mesh_federation_poll_failures_total{trust_domain,endpoint}` should stay flat.

End-to-end test: drive a request from a workload in cluster `us-east-1` to a
service in `eu-west-1` through HBONE; if the cross-cluster mTLS handshake
succeeds and `ferrum_mesh_mtls_handshake_failures_total` does not increment,
the federated bundle is being honored.

## Failure recovery runbook

### SPIRE Agent UDS unreachable

**Symptoms**: `ferrum_mesh_ca_health{ca_type="spire_agent"} == 0`,
`ferrum_mesh_cert_rotation_failures_total` increasing,
`"SPIRE agent CA: failed to connect"` / `"stream RPC failed"` log lines.

**Ferrum behavior**: the background task in [`SpireAgentCa::stream_loop`](../src/identity/ca/spire.rs)
keeps the last-good SVID snapshot serving for as long as the leaf certificate
remains valid, while it reconnects with jittered exponential backoff
(1s → 30s cap). Reads from `issue_svid` / `trust_bundle` return successfully
until the cached SVID expires. Once the cached SVID expires and the agent is
still unreachable, new mTLS handshakes fail closed (the rustls verifier has
no usable chain).

**Recovery**:

1. Check the agent pod on the same node — `kubectl get pod -n spire-system -l app=spire-agent --field-selector spec.nodeName=<node>`.
2. Check the socket mount inside the Ferrum pod — `kubectl exec <ferrum-pod> -- ls -l /run/spire/sockets/agent.sock`. A missing file means the volume mount or CSI driver failed.
3. Verify the registration entry is still present — `spire-server entry show -spiffeID <ferrum-spiffe-id>`. If a recent SPIRE Server failover dropped the entry, recreate via your controller-manager `ClusterSPIFFEID` or CLI.
4. Watch `ferrum_mesh_ca_health` flip back to `1` once the stream re-establishes.

### Trust bundle rotation failure

**Symptoms (local CA)**: `ferrum_mesh_trust_bundle_version` is stale,
`ferrum_mesh_cert_rotation_failures_total{source="spire_agent"}` is
increasing.

**Symptoms (federated bundles)**: `ferrum_mesh_federation_bundle_age_seconds`
climbs past `2 * FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS`,
`ferrum_mesh_federation_poll_failures_total{trust_domain,endpoint}` is
increasing.

**Impact**: cross-cluster mTLS continues to verify against the last-good
cached bundle (fail-closed). New peer SVIDs minted under a rotated *remote* CA
will not validate until the bundle refreshes. Same-cluster traffic is
unaffected.

**Recovery**:

1. For local bundle staleness: chase the same SPIRE-Agent path as above —
   the Workload API stream delivers bundle updates inline with SVID updates.
2. For federated bundle staleness: hit the remote endpoint from inside the
   consuming cluster — `kubectl exec <ferrum-pod> -- curl -fsS https://spire-server.eu-west-1.example.com/.well-known/spiffe`. Expect a JSON body containing `keys` or `x509_svid` material.
3. If the endpoint is reachable but returns a malformed body, the poller logs
   a structured warning naming the offending field and rejects the bundle (the
   last-good snapshot stays in service).
4. Once the upstream is healthy, the next poll tick fetches the fresh bundle
   automatically.

### SVID expiration

**Symptoms**: `ferrum_mesh_cert_expiry_seconds{spiffe_id=<self>}` trending to
zero, `FerrumMeshSvidExpiringCritical` firing
([alert below](#alerting-reference)).

**Impact**: when the leaf SVID expires and no replacement has arrived, mTLS
handshakes for that identity start failing closed (rustls cannot present an
expired chain).

**Recovery**:

1. Check `ferrum_mesh_cert_rotation_failures_total` — if non-zero, the agent
   stream is unhealthy (run the [SPIRE Agent UDS unreachable](#spire-agent-uds-unreachable)
   runbook).
2. If `ca_type=spire_agent` is healthy but no fresh SVID arrived, the SPIRE
   Server's *server-side* TTL math may be the issue. Check
   `spire-server entry show -spiffeID <ferrum-spiffe-id>` and verify `ttl`
   matches your operational target — an accidentally large `ttl` combined with
   server-side rate limiting can stall rotation.
3. For the gateway file path: confirm whatever process writes the SVID files
   (`spiffe-helper` sidecar, init job, custom controller) is still running and
   logging successful renewals. Check `kubectl exec <gateway> -- stat -c '%Y' /etc/ferrum/svid/gateway-chain.pem` — the mtime should advance roughly every `ttl/2`.

## Alerting reference

The Helm chart at [`charts/ferrum-mesh`](../charts/ferrum-mesh) ships a
`PrometheusRule` ([alerts-prometheusrule.yaml](../charts/ferrum-mesh/templates/alerts-prometheusrule.yaml))
that includes the identity / federation alerts when
`observability.alerts.enabled=true`. The defaults shipped are:

| Alert | Severity | Expression |
|---|---|---|
| `FerrumMeshCertificateExpiringSoon` | warning | `min by (spiffe_id, source) (ferrum_mesh_cert_expiry_seconds) < observability.alerts.certExpiringSeconds` (default 7d) |
| `FerrumMeshSvidExpiringCritical` | critical | `min by (spiffe_id, source) (ferrum_mesh_cert_expiry_seconds) < observability.alerts.svidExpiringCriticalSeconds` (default 1h) |
| `FerrumMeshCertificateRotationFailures` | critical | `sum by (spiffe_id, source) (increase(ferrum_mesh_cert_rotation_failures_total[10m])) > 0` |
| `FerrumMeshCaUnhealthy` | critical | `min by (ca_type) (ferrum_mesh_ca_health) == 0` |
| `FerrumMeshFederationBundleStale` | warning | `max by (trust_domain) (ferrum_mesh_federation_bundle_age_seconds) > observability.alerts.federationBundleStaleSeconds` (default 5m, or `2 * poll_interval`) |
| `FerrumMeshFederationPollFailures` | warning | `sum by (trust_domain, endpoint) (increase(ferrum_mesh_federation_poll_failures_total[10m])) > 0` |

`FerrumMeshCaUnhealthy` is your single-best signal that the SPIRE Agent UDS
is unreachable — it derives from the same `ferrum_mesh_ca_health{ca_type="spire_agent"}`
gauge that the [SPIRE Agent UDS unreachable](#spire-agent-uds-unreachable)
runbook references.

## Pre-prod checklist

Before declaring a cluster ready for production mesh traffic:

- [ ] **Trust domain pinned** in your standards doc and matches across SPIRE
      Server, SPIRE Agent, `FERRUM_INJECTOR_TRUST_DOMAIN`, and every
      `MultiClusterConfig.remote_clusters[].trust_domain` that names this
      cluster.
- [ ] **SPIRE Agent DaemonSet** runs on every node that will host Ferrum
      workloads. `kubectl get ds -n spire-system spire-agent` shows
      `DESIRED == READY` and matches your node count.
- [ ] **Registration entries** exist for: each Ferrum gateway deployment, the
      mesh ServiceAccounts the injector covers, and every ambient
      node-agent / waypoint ServiceAccount. `spire-server entry count` should
      match your inventory.
- [ ] **SVID issuance verified** with `spire-agent api fetch x509` from inside
      at least one pod of each Ferrum role.
- [ ] **Ferrum env vars** set: `FERRUM_MESH_CA_BACKEND=spire`,
      `FERRUM_MESH_SPIRE_AGENT_SOCKET` matches the Agent's socket path,
      `FERRUM_MESH_CERT_TTL_SECONDS` aligned with SPIRE entry TTLs. For
      gateways: all three `FERRUM_GATEWAY_SVID_*_PATH` vars and a working
      file-writer sidecar.
- [ ] **Federation reachable** (multi-cluster only) — `GET /mesh/federation`
      returns a populated entry for every remote cluster, with
      `bundle_age_seconds < 2 * poll_interval`.
- [ ] **Monitoring alerts wired**: Prometheus is scraping Ferrum, the
      `PrometheusRule` is loaded, and Alertmanager has a route for the
      `severity: warning` / `severity: critical` Ferrum mesh labels.
- [ ] **Dashboards imported**: once the Grafana dashboards land under
      `charts/ferrum-mesh/dashboards/`, the `certificate-posture` dashboard
      shows data for the new cluster. Until then, plot
      `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`,
      `ferrum_mesh_ca_health`, and `ferrum_mesh_federation_bundle_age_seconds`
      in your existing Grafana / Prometheus UI.
- [ ] **Runbook in your on-call wiki** links to the
      [Failure recovery runbook](#failure-recovery-runbook) section above (or
      a copy of it).

Once these check out, you are ready for production mesh traffic with a
SPIRE-backed identity story.

## References

- [SPIFFE specifications](https://github.com/spiffe/spiffe)
- [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [SPIRE Kubernetes quick start](https://spiffe.io/docs/latest/try/getting-started-k8s/)
- [SPIRE Helm charts (community)](https://github.com/spiffe/helm-charts-hardened)
- [SPIFFE CSI driver](https://github.com/spiffe/spiffe-csi)
- [SPIFFE Helper](https://github.com/spiffe/spiffe-helper) — file-based SVID delivery for non-Workload-API workloads
- [Ferrum mesh architecture](mesh.md)
- [Ferrum Kubernetes deployment guide](kubernetes_deployment.md)
- [Ferrum configuration reference](configuration.md)
