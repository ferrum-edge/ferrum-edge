# Agent 17 — kind / Helm / Gateway API / NodeWaypoint / eBPF

Investigation only. No production Rust changes.

| Field | Value |
|---|---|
| Agent | Ferrum Edge Launch-Readiness Agent 17 |
| Tested SHA | `bf05855f8429e466511610f9072f666b45cd309a` (`bf05855f8 Merge pull request #4319 from ferrum-edge/codex/issue-4311-cli-fips-doc`) |
| Branch | `cursor/agent-17-kind-helm-0949` |
| PR | https://github.com/ferrum-edge/ferrum-edge/pull/4387 |
| Ports reserved | `127.0.0.1:22600-22699` (unused — no cluster) |
| Resource prefix | `fe-agent-17-` (unused — no cluster) |
| Date | 2026-08-30 |
| Verdict | **BLOCKED** on kind/live cluster; **FAIL** on two new K8S install/watch gaps; Helm templates + schema + Gateway API CRD source inventory **PASS** |

## Verdict

kind/docker are **BLOCKED** on this VM. Helm chart lint/template/schema and Gateway API v1.5.1 CRD source validation still ran. Three findings:

1. **New** — documented `ferrum-mesh` development install emits a `GatewayClass` and never tells the operator to install the pinned Gateway API CRD channel (standard vs experimental).
2. **New** — Ferrum watches `TLSRoute` only at `v1alpha2`. Gateway API v1.5.1 `standard-install.yaml` serves `TLSRoute` at **`v1` only**, so a standard-channel cluster silently drops TLSRoute.
3. **New** — `ferrum-gateway` `mode=cp` starts the in-cluster K8s controller (T2-B default-on) with no `ClusterRole`.

`#4021` NodeWaypoint UDP follow-ups: **HOLD** (CLOSED via #4071; landed on this SHA). Do not duplicate.

Existing open Helm issues that still reproduce from source and were **not** refiled: `#4290` (`preStop.sleep` on kube 1.28).

## Environment

```
uname: Linux 6.12.94+ x86_64
docker: MISSING  (no /var/run/docker.sock)
kind:   MISSING
kubectl: MISSING
helm:   v3.18.4 (installed locally for this run; not present at VM boot)
rustc:  1.98.0 (88d9e12ae 2026-08-18)
cargo:  1.98.0 (797e8a9bc 2026-08-05)
protoc: libprotoc 3.21.12 (apt-installed for compile-light; not present at boot)
```

kind cluster: **BLOCKED**. `tests/k8s/lib/kind.sh` requires docker + kind + kubectl + `docker info`. None of those exist. Ports `22600-22699` and prefix `fe-agent-17-` were not bound.

## Compile light (Agent 11 style)

Attempted `cargo check --lib` only (no tests, no `--release`).

| Step | Result |
|---|---|
| Missing `sccache` rustc-wrapper (`.cargo/config.toml`) | Override `RUSTC_WRAPPER=` / `CARGO_BUILD_RUSTC_WRAPPER=` |
| Missing `mold` (`-C link-arg=-fuse-ld=mold`) | `apt-get install mold` |
| Missing `protoc` | `apt-get install protobuf-compiler` |
| `rdkafka-sys` cmake | **FAIL** — `/usr/bin/c++` cannot link `-lstdc++` (`libstdc++` not installed) |

Compile-light status: **BLOCKED** on this VM after the first native crate (`rdkafka-sys`). Not filed as a product issue (environment, not tree). `#4361` already covers the missing-`protoc` diagnostic on the product side.

## Helm validation (source)

Helm 3.18.4, charts at SHA `bf05855f`.

| Check | Result |
|---|---|
| `scripts/check_helm_values_schema_parity.py` | **PASS** — both charts |
| `helm lint charts/ferrum-mesh` (default, development, production examples) | **PASS** (INFO: Chart.yaml icon recommended) |
| `helm lint charts/ferrum-gateway` (file/database/cp/dp examples) | **PASS** |
| `helm template` mesh default + development + ambient+node-agent | **PASS** |
| `helm template` gateway file + cp examples | **PASS** |
| ambient without `nodeAgent.enabled` | **PASS** (fail-closed: `ambient topology requires nodeAgent.enabled=true`) |
| `helm template --kube-version 1.28.0` gateway file | **REPRODUCES #4290** — render succeeds; `lifecycle.preStop.sleep` still emitted |

### `ferrum-mesh` development-values (documented kind/minikube path)

Rendered kinds: `ClusterRole`, `ClusterRoleBinding`, `Deployment`, **`GatewayClass`**, `Service`, `ServiceAccount`.

```yaml
kind: GatewayClass
metadata:
  name: "ferrum"
spec:
  controllerName: ferrum.io/gateway-controller
```

CP env includes `FERRUM_K8S_CONTROLLER_NAMESPACE=ferrum` and `FERRUM_MODE=cp`. It does **not** set `FERRUM_K8S_CONTROLLER_ENABLED` (T2-B defaults that to `true` inside a pod).

The chart ships one CRD: `charts/ferrum-mesh/crds/udpresponseamplificationpolicies.yaml` (`gateway.ferrum.io/v1alpha1`). Helm installs `crds/` on first install. It does **not** ship Gateway API CRDs.

### `ferrum-gateway` cp-values (documented CP+DP pair)

Rendered kinds: `Deployment`, `PodDisruptionBudget`, `Service`, `ServiceAccount`.

- `ClusterRole` count: **0**
- `FERRUM_K8S_*` env: **none**
- `FERRUM_MODE=cp`

## Gateway API CRDs from source (v1.5.1 pin)

Fetched (not applied — no cluster):

- https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
- https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/experimental-install.yaml

Repo pin: `GATEWAY_API_VERSION: v1.5.1` in `.github/workflows/ci.yml`, `scripts/gateway_api_data_plane_conformance.sh`, `scripts/gateway_api_conformance_lab_setup.sh`. Conformance lab uses **experimental-install** and warns that mixing standard + a standalone experimental L4 CRD fails with "multiple gateway API CRDs channels detected".

| Kind | standard-install served | experimental-install served | Ferrum `GATEWAY_API_CRDS` watch |
|---|---|---|---|
| GatewayClass | v1, v1beta1 | v1, v1beta1 | v1 + v1beta1 |
| Gateway | v1, v1beta1 | v1, v1beta1 | v1 + v1beta1 |
| HTTPRoute | v1, v1beta1 | v1, v1beta1 | v1 + v1beta1 |
| GRPCRoute | v1 | v1 | v1 |
| ReferenceGrant | v1, v1beta1 | v1, v1beta1 | v1 + v1beta1 |
| ListenerSet | v1 | v1 | v1 |
| BackendTLSPolicy | v1 | v1, v1alpha3 | v1 + v1alpha3 |
| **TLSRoute** | **v1 only** | v1, v1alpha2, v1alpha3 | **v1alpha2 only** |
| TCPRoute | *absent* | v1alpha2 | v1alpha2 |
| UDPRoute | *absent* | v1alpha2 | v1alpha2 |
| XBackendTrafficPolicy | *absent* | v1alpha1 (`x-k8s.io`) | v1alpha1 |
| BackendLBPolicy | *absent* | *absent* (removed) | v1alpha2 historical |
| UDPResponseAmplificationPolicy | n/a (Ferrum) | n/a | v1alpha1 (`gateway.ferrum.io`) |

`find_crd_resource` (`src/k8s_controller/watcher.rs`) looks up `api_group.versioned_resources(crd.version)` and matches kind+plural. A served `TLSRoute/v1` on the standard channel does **not** satisfy the `v1alpha2` watch entry. Discovery then `debug!`-skips the watcher. Status mapping is the same pin: `("TLSRoute", "v1alpha2")` only (`src/k8s_controller/status.rs`).

HTTPRoute/TCPRoute translation itself is implemented and CI-gated (unit + live TCPRoute black-box on experimental). The gap is **channel/version + operator install**, not missing translators.

## Helm / docs gap (Gateway API CRDs)

`grep` of `docs/` and `charts/` for `standard-install`, `experimental-install`, `kubectl apply.*gateway-api`: **no operator-facing hits**. The only mentions are CI/conformance scripts.

`docs/kubernetes_deployment.md` documents:

```bash
helm install ferrum ./charts/ferrum-mesh -n ferrum --create-namespace \
  -f charts/ferrum-mesh/examples/development-values.yaml
```

That render includes `GatewayClass` (`gateway.networking.k8s.io/v1`). A real `helm install` against a cluster that has not already installed Gateway API CRDs fails with "no matches for kind GatewayClass". Could not execute `helm install` here (no API server); the failure mode is the Kubernetes apply contract for an unknown GVK.

TCPRoute / TLSRoute / UDPRoute / `XBackendTrafficPolicy` additionally require the **experimental** channel. `standard-install` is not enough for the L4 surfaces Ferrum documents in `charts/ferrum-gateway/README.md` and `docs/gateway_api_conformance.md`.

## ferrum-gateway CP + T2-B controller

`src/config/env_config.rs`: `FERRUM_K8S_CONTROLLER_ENABLED` and `FERRUM_K8S_POD_DISCOVERY_ENABLED` default **true** when `KUBERNETES_SERVICE_HOST` is set. `src/modes/control_plane.rs` starts the controller after `/health` is ready.

`start_crd_watchers` then always starts **core** watches for Gateway API (namespaces, services, secrets, configmaps, endpointslices) plus Istio + Gateway API CRD discovery. Missing CRD groups warn and skip. **Core watches do not skip** — without RBAC they 403-retry for process lifetime. The mesh chart comment on `xbackendtrafficpolicies` already names that 403 loop as the reason the grant exists.

`ferrum-gateway` has no RBAC templates. Operators can set `FERRUM_K8S_CONTROLLER_ENABLED=false` via `env` (not reserved), but the documented `examples/cp-values.yaml` does not.

## NodeWaypoint UDP / eBPF / ambient

`#4021` CLOSED 2026-08-22 via `#4071`. On this SHA the five follow-ups are present:

1. `src/ebpf/cgroup.rs` treats `ErrorKind::NotFound` as a shrunken tree.
2. `parse_relay_pod_uid` + construction-time rejection path in `node_waypoint_udp_reply_source.rs`.
3. Kernel-floor wording is a docs item (not re-opened).
4. Compile-time assert: `CGROUP_TREE_MAX_INODES == ferrum_ebpf_common::UDP_RELAY_CGROUP_MAX_ENTRIES`.
5. Threat-model wording was accepted in #4071.

**HOLD — do not duplicate #4021.**

Helm ambient/node-agent contract on this SHA:

- `ambient.enabled` requires `nodeAgent.enabled` (registry hostPath even when UDP capture is off).
- UDP placement ConfigMap + node-proof generation (`templates/udp-placement-contract.yaml`, issue #3809).
- NodeWaypoint SPIRE IDs must include `$(FERRUM_K8S_NODE_NAME)`.
- `FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID` is chart-managed from downward API.
- eBPF image suffix: node-agent uses `-ebpf`; ambient UDP / NodeWaypoint UDP listeners use `-ebpf-tools`.

No new NodeWaypoint UDP product bug found beyond #4021 HOLD.

## Duplicate search

Searched GitHub issues (open + closed) for Helm/Gateway API/NodeWaypoint/K8S launch-readiness overlap.

| Issue | State | Why not refiled |
|---|---|---|
| [#4021](https://github.com/ferrum-edge/ferrum-edge/issues/4021) | CLOSED | Charter HOLD; landed in #4071 |
| [#4290](https://github.com/ferrum-edge/ferrum-edge/issues/4290) | OPEN (PR #4332) | `preStop.sleep` / no `kubeVersion`; reproduced `--kube-version 1.28.0` |
| [#4288](https://github.com/ferrum-edge/ferrum-edge/issues/4288) | OPEN | mesh observability scrape path |
| [#4289](https://github.com/ferrum-edge/ferrum-edge/issues/4289) | OPEN | gateway `FerrumGatewayDatabasePollStale` in file/dp |
| [#4157](https://github.com/ferrum-edge/ferrum-edge/issues/4157) | CLOSED | gateway metrics path (now shipped) |
| [#4171](https://github.com/ferrum-edge/ferrum-edge/issues/4171) | CLOSED | NetworkPolicy now ships |
| [#3273](https://github.com/ferrum-edge/ferrum-edge/issues/3273) / [#3274](https://github.com/ferrum-edge/ferrum-edge/issues/3274) / [#3275](https://github.com/ferrum-edge/ferrum-edge/issues/3275) | CLOSED | TCP/TLS/UDPRoute implementation |

No open issue described the missing operator CRD install, the TLSRoute v1 vs v1alpha2 watch pin, or the ferrum-gateway CP RBAC hole.

## Issues filed

| Issue | Title |
|---|---|
| https://github.com/ferrum-edge/ferrum-edge/issues/4382 | [Launch readiness][K8S] Documented ferrum-mesh helm install emits GatewayClass but never installs (or names) the pinned Gateway API CRD channel |
| https://github.com/ferrum-edge/ferrum-edge/issues/4383 | [Launch readiness][K8S] TLSRoute watcher is pinned to v1alpha2; Gateway API v1.5.1 standard-install serves TLSRoute v1 only |
| https://github.com/ferrum-edge/ferrum-edge/issues/4384 | [Launch readiness][K8S] ferrum-gateway mode=cp starts the in-cluster K8s controller (T2-B default-on) with no ClusterRole |

## What was not verified

- Live `helm install` / `kubectl apply` (no API server).
- kind cluster, eBPF bpffs, NodeWaypoint UDP datapath, Gateway API conformance lab.
- HTTPRoute/TCPRoute live traffic on `127.0.0.1:22600-22699`.
- Full `cargo test` / clippy (out of scope; compile-light blocked on `libstdc++`).
