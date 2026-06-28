# Kubernetes Deployment Guide

This guide assumes a standard Kubernetes environment with `Deployment`, `Service`, `Ingress`, `ConfigMap`, and `Secret` support.

## Port Layout

| Container Port | Purpose | Recommended Exposure |
|---|---|---|
| `8000` | Proxy HTTP listener | Public or internal |
| `8443` | Proxy HTTPS listener | Public or internal |
| `9000` | Admin HTTP listener | Cluster-internal only |
| `9443` | Admin HTTPS listener | Cluster-internal only |
| `50051` | Control Plane gRPC | Cluster-internal only |
| Custom `listen_port` | TCP/UDP stream proxy listeners | Explicit per-port `Service` entries |

Recommended pattern:

- Expose `8000` and `8443` through an `Ingress` or public `LoadBalancer`.
- Keep `9000` and `9443` on a private `ClusterIP` service.
- Expose `50051` only to Data Plane pods.
- For raw TCP/UDP proxy listeners, add each configured `listen_port` to the pod and service spec explicitly.

> **Admin bind address (safe-by-default).** The admin listeners bind to loopback
> (`127.0.0.1`) by default, so admin is not reachable through the pod IP. This
> affects two things:
>
> 1. **Health probes.** A kubelet `httpGet` probe connects to the pod IP and
>    cannot reach a loopback-bound admin listener. Use the **exec** probe
>    (`["/app/ferrum-edge","health","-p","9000","--host","127.0.0.1"]`), shown in
>    the example below, which runs inside the pod and works with the loopback
>    default. (Distroless has no shell, but the `ferrum-edge health` subcommand is
>    a real exec target.)
> 2. **Cluster-internal admin/metrics access.** To reach admin through a
>    `ClusterIP` Service or scrape `/metrics` from another pod, set
>    `FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0` (or `::`). In the writable `database`/`cp`
>    modes a non-loopback **plaintext** admin bind additionally requires one of:
>    `FERRUM_ADMIN_ALLOWED_CIDRS` (an allowlist that must include the probe/scrape
>    source ranges), admin TLS (`FERRUM_ADMIN_TLS_CERT_PATH`/`KEY_PATH`, and set
>    `FERRUM_ADMIN_HTTP_PORT=0` to drop plaintext), or — when network isolation is
>    enforced by a `NetworkPolicy` — the explicit `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true`
>    opt-in. Otherwise the gateway refuses to start. Always pair a `0.0.0.0` admin
>    bind with a `NetworkPolicy` restricting access to the admin port.
>    >
>    > **Allowlist + exec probe.** If you set `FERRUM_ADMIN_ALLOWED_CIDRS`, it
>    > **must also include `127.0.0.1` and `::1`**: the exec `ferrum-edge health`
>    > probe connects from loopback inside the pod, and the admin IP filter
>    > (checked before `/health` is served) drops any source outside the
>    > allowlist — so an allowlist scoped only to pod/scrape ranges would fail the
>    > probe and leave the pod permanently `NotReady`. Loopback alone is never
>    > network-reachable, so allowing it does not widen exposure.

## Ferrum Mesh Helm Chart Contract

The `charts/ferrum-mesh` chart defaults to scaffolding only. It creates the
shared ServiceAccount, but runtime components that need external material are
disabled by default:

- `controlPlane.enabled=false`
- `injector.enabled=false`
- `ca.enabled=false`

This is intentional. `FERRUM_MODE=cp` cannot start without all of:

- `FERRUM_DB_TYPE`
- `FERRUM_DB_URL`
- `FERRUM_ADMIN_JWT_SECRET`
- `FERRUM_CP_DP_GRPC_JWT_SECRET`

The chart validates these requirements during `helm template` and `helm
install` when `controlPlane.enabled=true` or `ca.enabled=true`. Do not put these
reserved variables under `controlPlane.env`; use the first-class chart values so
the rendered Deployment has a clear secret contract:

```yaml
controlPlane:
  enabled: true
  database:
    type: postgres
    existingSecret:
      name: ferrum-mesh-production-db
      urlKey: url
  credentials:
    adminJwtSecret:
      existingSecret:
        name: ferrum-mesh-production-credentials
        key: admin-jwt-secret
    cpDpGrpcJwtSecret:
      existingSecret:
        name: ferrum-mesh-production-credentials
        key: cp-dp-grpc-jwt-secret
```

Development installs can use SQLite with operator-generated random JWT
secrets:

```bash
kubectl create namespace ferrum --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ferrum create secret generic ferrum-mesh-dev-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=cp-dp-grpc-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum ./charts/ferrum-mesh -n ferrum --create-namespace \
  -f charts/ferrum-mesh/examples/development-values.yaml
```

Production-style installs should use existing Secrets for both JWT material and
the database URL:

```bash
kubectl create namespace ferrum --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ferrum create secret generic ferrum-mesh-production-db \
  --from-literal=url='postgres://ferrum:<percent-encoded-password>@postgres.ferrum.svc:5432/ferrum'
kubectl -n ferrum create secret generic ferrum-mesh-production-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=cp-dp-grpc-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum ./charts/ferrum-mesh -n ferrum \
  -f charts/ferrum-mesh/examples/production-existing-secrets-values.yaml
```

The chart never generates JWT secrets. That avoids predictable credentials and
also avoids Helm upgrade churn from random template functions. If you need
structured database settings instead of a single URL Secret, `controlPlane.database`
also supports `host`, `port`, `name`, direct `username` / `password`, and
`params`; direct credentials are percent-encoded into `FERRUM_DB_URL`. For
Secret-backed database credentials, store the fully percent-encoded URL in a
Secret and reference it through `controlPlane.database.existingSecret` or
`controlPlane.database.urlFrom`.

## Mesh Injector Chart Defaults

When `injector.enabled=true`, the `charts/ferrum-mesh` injector Deployment runs
with a non-root, read-only runtime, `allowPrivilegeEscalation: false`, all Linux
capabilities dropped, `RuntimeDefault` seccomp, and CPU/memory requests and
limits. Override `injector.podSecurityContext`, `injector.securityContext`, or
`injector.resources` only when your custom image or cluster policy requires it.

The injector webhook also ships with a default `namespaceSelector` that excludes
`kube-system`, `kube-public`, `kube-node-lease`, `istio-system`, and namespaces
labelled `ferrum.io/injection=disabled`. The injector still requires per-pod
opt-in by default through `FERRUM_INJECTOR_REQUIRE_ANNOTATION=true`.
Managed clusters may expose additional platform namespaces such as
`gke-managed-system`, `openshift-*`, or other `kube-*` names; add those to
`injector.namespaceSelector` or label them `ferrum.io/injection=disabled` before
enabling broader injection.

The chart mounts the injector serving certificate through a Secret volume when
the injector is enabled; the injector process does not read Kubernetes Secrets
through the API, so the default service account does not need Secret RBAC for
that mount.

## Liveness and Readiness Probes

Ferrum Edge serves unauthenticated `/health` and `/status` on the admin listener. The response includes `status`, `mode`, `database`, `cached_config`, and `admin_writes_enabled`.

Important behavior:

- The endpoint returns HTTP `200` when the admin listener is healthy.
- The JSON `status` field changes to `"degraded"` when the process is alive but running with a degraded dependency state, such as a disconnected database while serving from cached config.

### Startup Timing

At startup, the gateway runs DNS warmup followed by optional connection pool warmup (`FERRUM_POOL_WARMUP_ENABLED=true` by default) before accepting traffic. With many backends, this can add a few seconds to startup. If your startup probe is too aggressive, increase `failureThreshold` or `initialDelaySeconds` to accommodate warmup time. See [connection_pooling.md](connection_pooling.md#connection-pool-warmup) for details.

### Default Probe Strategy

Use this when cached config is acceptable and you mainly want to know whether the process and admin listener are alive. The probes use the **exec** `ferrum-edge health` check, which connects to `127.0.0.1` inside the pod and therefore works with the safe loopback admin default (an `httpGet` probe targets the pod IP and would miss a loopback-bound listener — see "Admin bind address" above):

```yaml
livenessProbe:
  exec:
    command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  exec:
    command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
  initialDelaySeconds: 5
  periodSeconds: 10

startupProbe:
  exec:
    command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
  failureThreshold: 30
  periodSeconds: 5
```

### Strict Readiness

An `httpGet` probe returns success for any 2xx status from `/health` (the gateway returns 200 with `{"status":"ok"}` when healthy). However, `httpGet` probes connect to the **pod IP**, so they only work when admin is bound non-loopback (`FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0`) — which in `database`/`cp` modes also requires an allowlist, admin TLS, or the explicit insecure opt-in (see "Admin bind address" above). With the loopback default, use the **exec** `ferrum-edge health` probe shown above instead.

> **Note**: The distroless image has no shell or curl. Exec probes using `/bin/sh` and `curl` are not available. Use `httpGet` probes (shown above) or the built-in `ferrum-edge health` subcommand.

If you need to inspect the response body (e.g., verify `"status":"ok"` or check DP config sync), use the `ferrum-edge health` exec probe:

```yaml
readinessProbe:
  exec:
    command: ["/app/ferrum-edge", "health"]
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Data Plane Readiness After Config Sync

In DP mode, the pod can start before the Control Plane pushes config. The `httpGet` probe on `/health` will succeed once the admin API is listening, even before config is received. For most deployments this is acceptable — the DP returns 404 for unrouted paths until config arrives.

If your deployment requires at least one proxy before the pod becomes ready, use a sidecar or init container with curl to inspect the health response body:

```yaml
# Example with an ephemeral debug container or sidecar
readinessProbe:
  httpGet:
    path: /health
    port: admin-http
  initialDelaySeconds: 10
  periodSeconds: 10
```

`proxy_count` is reported inside `cached_config` in the `/health` JSON response, not as a top-level field.

If you enable admin TLS and want probes over HTTPS, point the probe at `9443` with `scheme: HTTPS`:

```yaml
readinessProbe:
  httpGet:
    path: /health
    port: admin-https
    scheme: HTTPS
```

For TLS-only deployments where `FERRUM_ADMIN_HTTP_PORT=0` (plaintext admin disabled), you **must** use either `scheme: HTTPS` probes or the `ferrum-edge health --tls` exec probe:

```yaml
readinessProbe:
  exec:
    command: ["/app/ferrum-edge", "health", "--tls", "--tls-no-verify"]
  initialDelaySeconds: 5
  periodSeconds: 10
```

> **Auto-detection**: When `FERRUM_ADMIN_HTTP_PORT=0` is set in the container environment, `ferrum-edge health` automatically uses TLS + port 9443 without needing the `--tls` flag.

## Single-Node Database Mode Example

This example exposes proxy traffic publicly and keeps the admin API private.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ferrum-edge-secrets
type: Opaque
stringData:
  db-url: postgres://ferrum:change-me@postgres.default.svc.cluster.local:5432/ferrum
  admin-jwt-secret: change-me
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ferrum-edge
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ferrum-edge
  template:
    metadata:
      labels:
        app: ferrum-edge
    spec:
      terminationGracePeriodSeconds: 30
      containers:
        - name: ferrum-edge
          image: ghcr.io/ferrum-edge/ferrum-edge:latest
          imagePullPolicy: IfNotPresent
          args: ["run"]
          env:
            - name: FERRUM_MODE
              value: database
            - name: FERRUM_DB_TYPE
              value: postgres
            - name: FERRUM_DB_URL
              valueFrom:
                secretKeyRef:
                  name: ferrum-edge-secrets
                  key: db-url
            - name: FERRUM_ADMIN_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: ferrum-edge-secrets
                  key: admin-jwt-secret
            - name: FERRUM_LOG_LEVEL
              value: info
          ports:
            - name: proxy-http
              containerPort: 8000
            - name: proxy-https
              containerPort: 8443
            - name: admin-http
              containerPort: 9000
            - name: admin-https
              containerPort: 9443
          # Admin binds to loopback by default, so probes use the in-pod exec
          # health check (the kubelet's httpGet would target the pod IP and miss
          # a loopback listener). See "Admin bind address" above before switching
          # to httpGet probes.
          startupProbe:
            exec:
              command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
            failureThreshold: 30
            periodSeconds: 5
          livenessProbe:
            exec:
              command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            exec:
              command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
            initialDelaySeconds: 5
            periodSeconds: 10
          # Note: preStop with shell-based sleep is not available in distroless.
          # Use terminationGracePeriodSeconds (set on the pod spec) to allow
          # in-flight requests to drain before SIGKILL. The gateway handles
          # SIGTERM gracefully.
          resources:
            requests:
              cpu: 250m
              memory: 64Mi
            limits:
              cpu: "2"
              memory: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-proxy
spec:
  type: ClusterIP
  selector:
    app: ferrum-edge
  ports:
    - name: http
      port: 80
      targetPort: proxy-http
    - name: https
      port: 443
      targetPort: proxy-https
---
# Optional cluster-internal admin Service. This only works if the gateway binds
# admin to the pod IP — the Deployment above uses the safe loopback default, so
# this Service would route to a port where nothing is listening. To use it, add
# to the Deployment env: FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0 plus a protection
# control (FERRUM_ADMIN_ALLOWED_CIDRS including the consumer ranges, admin TLS,
# or FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true with a NetworkPolicy), per the
# "Admin bind address" note above. Otherwise omit this Service and reach admin
# in-pod (exec health check / `kubectl exec`). Always pair it with a
# NetworkPolicy restricting access to the admin port.
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-admin
spec:
  type: ClusterIP
  selector:
    app: ferrum-edge
  ports:
    - name: http
      port: 9000
      targetPort: admin-http
    - name: https
      port: 9443
      targetPort: admin-https
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ferrum-edge
  annotations:
    # Add ingress-controller-specific annotations here if needed.
spec:
  rules:
    - host: edge.example.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ferrum-edge-proxy
                port:
                  name: http
```

If your cluster publishes services directly instead of using ingress, change `ferrum-edge-proxy` to `type: LoadBalancer`.

### MongoDB Variant

For MongoDB, replace the Secret and Deployment `env` section:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ferrum-edge-secrets
type: Opaque
stringData:
  # For Atlas: mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum
  db-url: mongodb://ferrum:change-me@mongodb.default.svc.cluster.local:27017/ferrum?replicaSet=rs0
  admin-jwt-secret: change-me
```

Key `env` changes in the Deployment:

```yaml
env:
  - name: FERRUM_DB_TYPE
    value: mongodb
  - name: FERRUM_DB_URL
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: db-url
  - name: FERRUM_MONGO_DATABASE
    value: ferrum
  - name: FERRUM_MONGO_REPLICA_SET
    value: rs0
```

**Notes:**
- `FERRUM_DB_READ_REPLICA_URL` is SQL-only and not used by MongoDB; Ferrum's MongoDB config store forces primary reads
- `FERRUM_DB_POOL_*` settings are ignored for MongoDB
- For MongoDB on Kubernetes, consider the [MongoDB Community Kubernetes Operator](https://github.com/mongodb/mongodb-kubernetes-operator)
- See [docs/mongodb.md](mongodb.md) for the full deployment guide

## Control Plane / Data Plane Layout

For CP/DP mode, keep the Control Plane private and expose only the Data Plane proxy service.

> **Admin bind for CP/DP admin Services.** The admin Services below publish ports
> `9000`/`9443`, but admin binds to loopback by default (see "Admin bind address"
> above), so these Services only work if the pod sets
> `FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0`. The Control Plane is a **writable** admin
> (`cp` mode), so a non-loopback plaintext bind also needs `FERRUM_ADMIN_ALLOWED_CIDRS`
> (including `127.0.0.1`/`::1` for the exec probe), admin TLS, or
> `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` + a `NetworkPolicy` — both shown below.
> Omit the admin Service entirely if you only need in-pod (`kubectl exec`) admin
> access; the gRPC Service (`50051`) is independent.

### Control Plane

- Container ports: `9000`, `9443`, `50051`
- Service type: `ClusterIP`
- Key env vars:

```yaml
env:
  - name: FERRUM_MODE
    value: cp
  - name: FERRUM_DB_TYPE
    value: postgres
  - name: FERRUM_DB_URL
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: db-url
  - name: FERRUM_ADMIN_JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: admin-jwt-secret
  # Bind admin to the pod IP so the ferrum-edge-cp ClusterIP Service can reach it
  # (admin defaults to loopback). cp is writable, so a non-loopback plaintext
  # admin bind also requires the allowlist below (or admin TLS / the insecure
  # opt-in). Include 127.0.0.1/::1 so the exec health probe is not dropped.
  - name: FERRUM_ADMIN_BIND_ADDRESS
    value: "0.0.0.0"
  - name: FERRUM_ADMIN_ALLOWED_CIDRS
    value: "127.0.0.1/32,::1/128,10.0.0.0/8" # replace 10.0.0.0/8 with your scrape/CP-admin source ranges
  - name: FERRUM_CP_GRPC_LISTEN_ADDR
    value: 0.0.0.0:50051
  - name: FERRUM_CP_DP_GRPC_JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: cp-dp-grpc-jwt-secret
```

Control Plane service example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-cp
spec:
  type: ClusterIP
  selector:
    app: ferrum-edge-cp
  ports:
    - name: admin-http
      port: 9000
      targetPort: 9000
    - name: grpc
      port: 50051
      targetPort: 50051
```

### Data Plane

- Container ports: `8000`, `8443`, `9000`, `9443`
- Public service: proxy ports only
- Private service: admin ports only
- Key env vars:

```yaml
env:
  - name: FERRUM_MODE
    value: dp
  # Single CP (simple):
  - name: FERRUM_DP_CP_GRPC_URLS
    value: http://ferrum-edge-cp:50051
  # Multi-CP failover (recommended for HA):
  # - name: FERRUM_DP_CP_GRPC_URLS
  #   value: "https://cp-east:50051,https://cp-west:50051,https://cp-central:50051"
  # - name: FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS
  #   value: "300"
  - name: FERRUM_CP_DP_GRPC_JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: cp-dp-grpc-jwt-secret
  - name: FERRUM_ADMIN_JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ferrum-edge-secrets
        key: admin-jwt-secret
  # Bind admin to the pod IP so the private admin Service can reach it (admin
  # defaults to loopback). dp admin is read-only, so a non-loopback plaintext
  # bind only warns (no hard error), but still pair it with a NetworkPolicy — and
  # if you also set FERRUM_ADMIN_ALLOWED_CIDRS, include 127.0.0.1/::1 for the exec
  # health probe. Omit this and the admin Service to keep admin in-pod only.
  - name: FERRUM_ADMIN_BIND_ADDRESS
    value: "0.0.0.0"
```

For multi-region Kubernetes deployments with CP failover across clusters, see [multi_region_ha.md](multi_region_ha.md).

Data Plane proxy service example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-dp-proxy
spec:
  type: LoadBalancer
  selector:
    app: ferrum-edge-dp
  ports:
    - name: http
      port: 80
      targetPort: 8000
    - name: https
      port: 443
      targetPort: 8443
```

Data Plane admin service example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-dp-admin
spec:
  type: ClusterIP
  selector:
    app: ferrum-edge-dp
  ports:
    - name: http
      port: 9000
      targetPort: 9000
```

## Managing Stream Proxy Port Exposure

Ferrum Edge can bind dedicated TCP or UDP ports through `listen_port`. Kubernetes will only route traffic to those listeners if you publish matching service ports.

Example: exposing a TCP proxy on `15432`:

```yaml
ports:
  - name: tcp-15432
    containerPort: 15432
    protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: ferrum-edge-stream
spec:
  type: LoadBalancer
  selector:
    app: ferrum-edge
  ports:
    - name: tcp-15432
      port: 15432
      targetPort: 15432
      protocol: TCP
```

For UDP, keep the same pattern but set `protocol: UDP` on both the container port and the service port.

## File Mode on Kubernetes

File mode works well with a `ConfigMap`, but Kubernetes does not send `SIGHUP` automatically when the mounted config changes.

Recommended options:

- Roll the `Deployment` after updating the `ConfigMap`.
- Use a sidecar or reloader controller that updates the config and sends `SIGHUP`.
- Keep readiness on `/health` so pods stay in rotation during a clean rolling restart.

## TLS Certificate Rotation on Kubernetes

Ferrum Edge can hot-reload frontend/admin TLS sources that are configured as
`k8s://<namespace>/<secret>#<key>` and
`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`. This is the recommended path
for cert-manager-managed frontend/admin certificates because Ferrum watches the
named `Secret` directly and queues a validated reload when the Secret changes.

Ferrum Edge does **not** hot-reload arbitrary file-based TLS certificates or
keys outside the frontend/admin live-reload surface.

This applies to:

- frontend TLS / admin TLS certs and keys unless live reload is enabled and the
  fields are configured as paths, `file://`, `k8s://`, provider, or managed
  sources
- DTLS certs and keys unless frontend TLS live reload is enabled
- backend TLS CA bundles and backend mTLS client certs/keys unless backend TLS
  live reload is enabled
- database TLS CA bundles and client certs/keys unless database TLS live reload
  is enabled in database or CP mode
- CP gRPC TLS cert/key/client-CA material unless the CP is configured with
  file/provider/Kubernetes-backed sources
- DP gRPC TLS CA/client cert/client key material unless the DP is configured
  with file/provider/Kubernetes-backed sources

Important Kubernetes nuance:

- Kubernetes can update mounted `Secret` and projected volume contents in a running Pod.
- Ferrum Edge only rebuilds TLS state for surfaces with live reload enabled. Updating a Secret at the same mount path is therefore **not sufficient by itself** for static TLS surfaces.

Operational recommendation:

- For frontend/admin TLS and frontend DTLS, prefer `k8s://` sources with live reload enabled so a Secret update applies without a pod restart.
- For backend HTTP-family TLS, keep `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED=true` and prefer `k8s://` sources so a Secret update applies without a pod restart.
- For database TLS in database/CP modes, set `FERRUM_DB_TLS_LIVE_RELOAD_ENABLED=true` and prefer `k8s://` sources so a Secret update reconnects DB pools/clients without a pod restart.
- For CP gRPC server TLS, prefer `k8s://` sources; a Secret update swaps the active server TLS slot for new gRPC handshakes without a pod restart.
- For DP gRPC TLS, prefer `k8s://` sources; a Secret update forces the CP stream to reconnect with rotated CA/client cert/key material.
- Keep readiness probes enabled so traffic stays on healthy Pods during the rollout.

If you use `subPath` mounts for cert files, note that Kubernetes does not propagate Secret updates to those paths in running Pods. In that setup, a restart is required even to get the new file content into the container filesystem.

## Database Outage Restart Protection

If you run database or Control Plane mode and want pods to restart cleanly while the database is temporarily unavailable, mount a backup config and set:

```yaml
env:
  - name: FERRUM_DB_CONFIG_BACKUP_PATH
    value: /etc/ferrum/backup-config.json
```

This lets Ferrum Edge start with a previously exported config while database polling keeps retrying in the background.

## Kubernetes Service Discovery

Ferrum Edge can discover upstream targets directly from Kubernetes `EndpointSlice` objects. When you use that feature, the service account needs permission to list EndpointSlices in the target namespace.

RBAC example:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ferrum-edge
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferrum-edge-endpointslices
rules:
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ferrum-edge-endpointslices
subjects:
  - kind: ServiceAccount
    name: ferrum-edge
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ferrum-edge-endpointslices
```

Ferrum config example:

```yaml
upstreams:
  - id: users
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: kubernetes
      kubernetes:
        namespace: default
        service_name: users-api
        port_name: http
        poll_interval_seconds: 15
```
