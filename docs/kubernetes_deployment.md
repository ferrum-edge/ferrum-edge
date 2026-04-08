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

## Liveness and Readiness Probes

Ferrum Edge serves unauthenticated `/health` and `/status` on the admin listener. The response includes `status`, `mode`, `database`, `cached_config`, and `admin_writes_enabled`.

Important behavior:

- The endpoint returns HTTP `200` when the admin listener is healthy.
- The JSON `status` field changes to `"degraded"` when the process is alive but running with a degraded dependency state, such as a disconnected database while serving from cached config.

### Startup Timing

At startup, the gateway runs DNS warmup followed by optional connection pool warmup (`FERRUM_POOL_WARMUP_ENABLED=true` by default) before accepting traffic. With many backends, this can add a few seconds to startup. If your startup probe is too aggressive, increase `failureThreshold` or `initialDelaySeconds` to accommodate warmup time. See [connection_pooling.md](connection_pooling.md#connection-pool-warmup) for details.

### Default Probe Strategy

Use this when cached config is acceptable and you mainly want to know whether the process and admin listener are alive:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: admin-http
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /health
    port: admin-http
  initialDelaySeconds: 5
  periodSeconds: 10

startupProbe:
  httpGet:
    path: /health
    port: admin-http
  failureThreshold: 30
  periodSeconds: 5
```

### Strict Readiness

Use this when you want readiness to fail unless the JSON body reports `"status":"ok"`:

```yaml
readinessProbe:
  exec:
    command:
      - /bin/sh
      - -ec
      - |
        body="$(curl -fsS http://127.0.0.1:9000/health)"
        echo "$body" | grep -q '"status":"ok"'
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Data Plane Readiness After Config Sync

In DP mode, the pod can start before the Control Plane pushes config. If your deployment expects at least one proxy before the pod becomes ready, extend the probe:

```yaml
readinessProbe:
  exec:
    command:
      - /bin/sh
      - -ec
      - |
        body="$(curl -fsS http://127.0.0.1:9000/health)"
        echo "$body" | grep -q '"status":"ok"'
        echo "$body" | grep -q '"cached_config":{"available":true'
        echo "$body" | grep -Eq '"proxy_count":[1-9][0-9]*'
```

`proxy_count` is reported inside `cached_config`, not as a top-level health field.

If a zero-proxy config is valid in your environment, use a different readiness rule instead of the `proxy_count` check.

If you enable admin TLS and want probes over HTTPS, point the probe at `9443` with `scheme: HTTPS`. Many operators still keep port `9000` private inside the cluster just for probes and operational access.

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
          startupProbe:
            httpGet:
              path: /health
              port: admin-http
            failureThreshold: 30
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /health
              port: admin-http
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /health
              port: admin-http
            initialDelaySeconds: 5
            periodSeconds: 10
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "sleep 15"]
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
  # For Atlas: mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum?readPreference=secondaryPreferred
  db-url: mongodb://ferrum:change-me@mongodb.default.svc.cluster.local:27017/ferrum?replicaSet=rs0&readPreference=secondaryPreferred
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
- `FERRUM_DB_READ_REPLICA_URL` is not needed — use `readPreference=secondaryPreferred` in the connection string
- `FERRUM_DB_POOL_*` settings are ignored for MongoDB
- For MongoDB on Kubernetes, consider the [MongoDB Community Kubernetes Operator](https://github.com/mongodb/mongodb-kubernetes-operator)
- See [docs/mongodb.md](mongodb.md) for the full deployment guide

## Control Plane / Data Plane Layout

For CP/DP mode, keep the Control Plane private and expose only the Data Plane proxy service.

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
  - name: FERRUM_DP_CP_GRPC_URL
    value: http://ferrum-edge-cp:50051
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
```

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
