# Mesh Multicluster Federation Runbook

This runbook covers the real-cluster validation surface for Ferrum mesh trust
federation and cross-cluster endpoint discovery. It is the operator and CI
companion to `docs/mesh.md` sections "Trust Federation" and
"Cross-Cluster Endpoint Discovery".

## Current Validation Status

Authoritative validation for bidirectional two-cluster federation is the
repository harness and its GitHub Actions workflows — not a one-off local
Docker/kind install report.

| Mode | Entry | Workflow / job |
|---|---|---|
| Live datapath (SPIRE-federated two kind clusters, bidirectional traffic + negatives + Stage-3 failure injection; fail-closed required-assertion gate) | `tests/k8s/multicluster-federation/run.sh` | `.github/workflows/multicluster-federation-live.yml` — path-filtered on PRs, force-run on every `main` push / `workflow_dispatch` (requires `FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true`) |
| Deploy-only smoke (rollouts, no traffic) | same script with `FERRUM_MULTICLUSTER_DEPLOY_ONLY=1` | Legacy path-filtered `Mesh Multicluster Federation` CI job; a packaging/rollout check, not the authoritative datapath/release gate |

In-process federation/discovery unit and integration coverage remains necessary
but is not a substitute for the two-cluster harness. Preflight requires
`docker`, `kind`, `kubectl`, `curl`, and `python3`; a skipped local run is not
validation evidence.

**Residual:** poller-driven partition / last-good-retention live coverage is
still owed — the current file-config fixture does not run federation/remote
discovery pollers ([#3331](https://github.com/ferrum-edge/ferrum-edge/issues/3331)).

Remediation that made federation activation bidirectional and observable
(effective trust-bundle set for outbound mTLS and inbound SPIFFE verification;
`FERRUM_MESH_FEDERATION_FAIL_OPEN` bootstrap/fail-closed semantics; last-good
preservation on transient poll failure; `GET /mesh/remote-clusters` discovery
and trust freshness) is part of the current product contract documented in
`docs/mesh.md` and exercised by the harness above.

## Required Topology

Use two independent clusters:

| Cluster | Trust domain | Ferrum CP | Ferrum DP/east-west | Workload |
|---|---|---|---|---|
| A | `cluster-a.test` | `ferrum-a` | sidecar/waypoint + east-west gateway | `client-a`, `echo-a` |
| B | `cluster-b.test` | `ferrum-b` | sidecar/waypoint + east-west gateway | `client-b`, `echo-b` |

Each cluster must have its own root, control-plane database, CP/DP JWT secret,
gateway SVID, `MultiClusterConfig.remote_clusters[]` entry for the peer, peer
`federation_endpoint`, peer `control_plane_url`, and east-west gateway address.

## Failure-Mode Matrix

| Scenario | Expected result |
|---|---|
| Bootstrap, fail-closed | Before the first successful bundle poll, `trust_source=blocked_pending_poll`, `outbound_trust_active=false`, `inbound_trust_active=false`, and authenticated cross-cluster traffic fails. |
| Bootstrap, fail-open | Before the first successful bundle poll, CP fallback is active, `trust_source=control_plane`, and traffic can pass if the CP bundle is valid. |
| First successful bundle poll | `trust_source=polled`; both outbound and inbound trust become active when the gateway has a SPIFFE verifier slot. |
| Root rotation with overlap | Traffic continues while old and new roots overlap; status `trust_bundle_age_seconds` refreshes after poll. |
| Root removal after overlap | Traffic signed by the removed root fails after the new polled bundle is active. |
| Invalid bundle delivery | Invalid remote bundle is rejected; last-good bundle remains active; age increases; poll-failure metrics/logs identify the endpoint. |
| Prolonged federation disconnection | Last-good bundle is preserved until expiry policy is defined by operators; alert on stale bundle age. |
| Endpoint addition | Remote endpoint appears under `discovered`, service/workload counts increase, and the local LB can fail over to it. |
| Endpoint removal | Removed remote endpoint disappears after a successful discovery poll or cluster removal; stale endpoints are evicted on accepted config/trust withdrawal. |
| Local-first routing | With source locality present, local endpoints are preferred while healthy. |
| Remote failover | When local endpoints are unavailable, traffic fails over to remote endpoints. |
| Network partition / DNS failure / latency | Pollers back off and keep last-good bundles/endpoints; status age increases; recovery refreshes age and data. |
| Stale CP data | Received-but-rejected slices do not affect poller membership or discovered status; accepted last-good slice continues serving. |
| CP restart | DPs retain last-good slice and reconnect; status shows stale slice age during outage. |
| Gateway restart | Gateway restarts with no partial trust state; it bootstraps according to fail-open/fail-closed policy and then converges from CP/poller data. |
| Asymmetric trust | `GET /mesh/remote-clusters` distinguishes outbound and inbound trust, so missing inbound SPIFFE verifier material is visible as `outbound_trust_active=true`, `inbound_trust_active=false`. |

## Operator Checks

For each cluster:

```bash
kubectl --context "$CTX" -n ferrum get pods -o wide
kubectl --context "$CTX" -n ferrum rollout status deployment/ferrum-mesh-control-plane --timeout=180s
kubectl --context "$CTX" -n ferrum rollout status deployment/ferrum-mesh-east-west --timeout=180s
kubectl --context "$CTX" -n ferrum logs deployment/ferrum-mesh-control-plane --tail=200
```

Query mesh status through the authenticated admin API:

```bash
curl -fsS -H "Authorization: Bearer $ADMIN_JWT_A" \
  "https://$ADMIN_A/mesh/remote-clusters" | jq .
curl -fsS -H "Authorization: Bearer $ADMIN_JWT_B" \
  "https://$ADMIN_B/mesh/remote-clusters" | jq .
```

The configured peer row must show:

- `discovered=true` after endpoint discovery converges;
- `trust_source=polled` after bundle polling converges;
- `outbound_trust_active=true`;
- `inbound_trust_active=true`;
- a fresh `trust_bundle_age_seconds`.

## Harness

The scheduled harness entry point is:

```bash
tests/k8s/multicluster-federation/run.sh
```

It runs in two modes:

- **Live datapath (default):** creates two SPIRE-federated kind clusters
  (per-cluster trust domains `cluster-a.test`/`cluster-b.test`, manual
  `bundle show | bundle set` trust-bundle exchange), injects Sidecar mesh-mTLS
  workloads — a `svc` whose inbound iptables init REDIRECTs the app port to
  `:15006`, an east-west SNI-passthrough gateway on a NodePort, and
  `client`/`rogue` sidecars — then drives BIDIRECTIONAL authenticated
  cross-cluster traffic (A→B and B→A both return `200 svc-<dest>`) plus a
  destination-side negative (the federated `rogue` is denied by a
  `deny-peer-rogue` MeshPolicy → `403`/`Mesh authorization denied`). It emits and
  gates on `multicluster.*` live assertions. Identity comes from the local SPIRE
  Agent (`FERRUM_MESH_CA_BACKEND=spire_agent`) with REAL SVIDs provisioned, so
  `FERRUM_MESH_ALLOW_NO_CA` is NOT set. The dest mesh document declares the peer
  trust domain's bundle as a federated `trust_bundles` entry (Ferrum's inbound
  verifier sources federated trust from the slice, not the SVID). This mode runs
  in the dedicated `.github/workflows/multicluster-federation-live.yml` workflow
  against disposable kind clusters and requires
  `FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true`. That workflow is the
  authoritative PR/main/release gate (issue #2459): relevant PRs and every
  `main` push run the full datapath, and `release.yml` requires a successful
  push run for the exact tag SHA.

  The GA-contract enforcement has three blocking layers. The live job itself
  runs no validator: the trusted Cross build policy compares that job's digest
  against `main`, so neither adding a cargo step to it nor editing it is
  permitted in an ordinary PR. Validation lives in the separate `gate` job,
  which carries no toolchain or build step at all.

  - **In the fixture.** `run.sh` ends in `ferrum_live_assertions_require_all_passed`
    over its `REQUIRED_LIVE_ASSERTIONS` array, so a required `multicluster.*`
    assertion that is missing, failed, or *skipped* fails the live job — and with
    it the `Multicluster Federation Live` aggregate gate.
  - **In the emitted artifact, in the `gate` job.** After a relevant live run
    succeeds, the gate downloads the published `multicluster-federation-results`
    artifact with a full-SHA-pinned `actions/download-artifact` and validates
    `live-assertions.json` with `.github/scripts/validate_live_assertions.py`
    (standard library only). It fails closed on a missing or non-regular
    artifact, malformed JSON, a wrong schema version, suite, `github.sha`
    commit, or `kind-spire-multicluster-federation` platform profile, an
    invalid, future, or more-than-six-hour-old timestamp, duplicate ids, a
    missing or extra required `multicluster.*` id, or any required assertion
    whose status is not `pass`. This is what proves the artifact the run
    *published* belongs to this commit — something the fixture-side check
    cannot establish. An irrelevant pull request skips the download entirely.
  - **In the hosted Rust conformance suite.** `tests/conformance/live_contract.rs`
    (`live_contract_real_contract_declares_the_multicluster_suite_rows`,
    `live_contract_multicluster_fixture_requires_exactly_the_enforced_rows`,
    `live_contract_multicluster_release_gate_requires_exactly_the_enforced_rows`)
    and `tests/conformance/mesh_multicluster_federation.rs` pin both the
    fixture's array and the gate's `--require` list to the enforced,
    non-`live_deferred` `multicluster-federation` rows of `ga_contract.yaml` on
    the `kind-spire-multicluster-federation` platform profile. These run in the
    ordinary `Tests` aggregate, alongside `verify_required_ci.py`, which
    independently pins the gate's wiring and runs the validator's self-tests.

  The cargo-based `live_contract_artifact_gate` is only invoked by
  `.github/workflows/mesh-e2e-sidecar-live.yml`; it self-skips everywhere else.
- **Deploy-only smoke (`FERRUM_MULTICLUSTER_DEPLOY_ONLY=1`):** stops after the
  SPIRE/workload deploy and rollouts, before driving traffic. The legacy
  path-filtered `Mesh Multicluster Federation` CI job keeps this narrower
  packaging/rollout check; it is distinct from, and never substitutes for, the
  dedicated full-datapath PR/main/release gate. The Helm chart is NOT a trigger
  and is NOT deployed — this fixture uses hand-crafted NodePort manifests
  because the chart's east-west Service is ClusterIP-only and not cross-cluster
  reachable; the chart is covered by the dedicated `Helm Chart` CI job.

Diagnostics are recorded under `${ARTIFACT_DIR:-.context/multicluster-federation}`.
Preflight requires `docker`, `kind`, `kubectl`, `curl`, and `python3` and
intentionally fails when they are unavailable; do not treat a skipped local run
as validation evidence. The live mode also runs two Stage-3 failure-injection
scenarios (gated): peer-trust revocation (drop the federated bundle from the dest
slice + reload → A→B fails closed → restore → recover) and dest endpoint
black-hole (scale `svc` to 0 → A→B fails fast → scale up + re-render gateway →
recover). Network-partition / last-good retention is deferred (#3331): it is a
federation/remote-discovery POLLER property, which this static file-config
fixture does not run (it needs a separate poller-driven fixture; kind also has no
NetworkPolicy enforcement for a clean in-cluster partition).
