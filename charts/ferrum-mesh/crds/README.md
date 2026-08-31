# Ferrum-owned CRDs moved to templates/

`UDPResponseAmplificationPolicy` is no longer installed from this directory.
Helm's `crds/` files are applied once on `helm install` and are never upgraded,
so a cluster that installed an older chart kept a stale schema through every
successful `helm upgrade`.

The CRD now lives at
`templates/crds-udpresponseamplificationpolicy.yaml`, gated by `crds.install`
(default `true`). `helm upgrade` applies schema changes. Uninstall keeps the
object (`helm.sh/resource-policy: keep`).

Compare the live CRD to the chart:

```bash
kubectl get crd udpresponseamplificationpolicies.gateway.ferrum.io \
  -o jsonpath='{.metadata.annotations.gateway\.ferrum\.io/crd-schema-version}'
```

The chart ships `v1alpha1-1` (`crds.udpResponseAmplificationPolicy.schemaVersion`).
A mismatch is a loud operator failure: either upgrade with `crds.install=true`,
or apply the template YAML with `kubectl apply --server-side` and set
`crds.skipInstallAcknowledged=true`.

Existing clusters that still have the CRD from this directory must adopt it
once. **Operator action:**

```bash
helm upgrade <release> ./charts/ferrum-mesh -n <namespace> \
  --take-ownership --set crds.adoptExisting=true
```

See `docs/upgrade_guide.md`.
