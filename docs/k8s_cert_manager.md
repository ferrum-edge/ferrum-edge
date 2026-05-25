# Kubernetes Secret TLS Sources

Ferrum can consume cert-manager output directly with `k8s://` TLS material
sources. Use this for frontend/admin TLS when you want Secret rotation to apply
without remounting files or restarting the pod.

Example:

```bash
export FERRUM_FRONTEND_TLS_CERT_SOURCE="k8s://edge/edge-tls#tls.crt"
export FERRUM_FRONTEND_TLS_KEY_SOURCE="k8s://edge/edge-tls#tls.key"
export FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true
```

The `k8s://<namespace>/<secret>#<data-key>` form reads the Secret's `data`
entry. If the data key is omitted, Ferrum uses cert-manager-compatible defaults:
`tls.crt` for certificates, `tls.key` for private keys, `ca.crt` for CA bundles,
`tls.crl` for CRLs, `jwks.json` for JWKS material, and `ocsp.der` for OCSP
responses.

When frontend/admin live reload is enabled, Ferrum registers a Kubernetes watch
for each referenced Secret and queues an immediate source reload on Secret
`Apply` or `Delete` events after the initial watch sync. The reload pipeline
still fingerprints material bytes, so a Secret update with identical bytes does
not churn TLS configs. Periodic polling remains active as a backstop and for
providers that do not offer push notifications.

Minimum RBAC for the gateway service account:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferrum-tls-secret-reader
  namespace: edge
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ferrum-tls-secret-reader
  namespace: edge
subjects:
  - kind: ServiceAccount
    name: ferrum-edge
    namespace: edge
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ferrum-tls-secret-reader
```

Mounted Secret files still work as ordinary path sources, but Kubernetes does
not update `subPath` mounts in running pods and mounted-file propagation can lag.
For cert-manager-managed frontend/admin TLS, prefer `k8s://` sources so Ferrum
observes the Kubernetes API update directly.
