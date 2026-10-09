---
paths:
  - "src/admin/**"
  - "src/config/db_backend.rs"
  - "src/config/db_loader.rs"
  - "src/config/mongo_store.rs"
  - "openapi.yaml"
  - "docs/admin_api.md"
  - "docs/admin_batch_api.md"
  - "docs/admin_backup_restore.md"
  - "docs/admin_metrics.md"
  - "docs/admin_read_only_mode.md"
  - "docs/api_specs.md"
  - "tests/unit/admin/**"
  - "tests/integration/admin*"
  - "tests/integration/*api_specs*"
  - "tests/functional/functional_admin*"
  - "tests/functional/functional_credential_rotation_test.rs"
---

# Admin API And Spec Rules

## Admin API Invariants

- Admin API validates JWTs but never mints them; operators pre-sign tokens externally. DB and CP modes require `FERRUM_ADMIN_JWT_SECRET` of at least 32 chars because their admin APIs are writable.
- File and DP admin surfaces are read-only where configured and must reject writes.
- `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true` makes namespace-scoped admin routes require a JWT `ns` claim (same shapes as the CP/DP gRPC plane) authorizing the `X-Ferrum-Namespace` value; the default (off) keeps the header a routing selector only for claim-less tokens. Enforcement: `is_namespace_scoped_route` + `enforce_namespace_claim` in `src/admin/mod.rs`. Malformed `ns` claims fail closed at authentication.
- A token that carries an `ns` claim is namespace-bounded whatever the flag says (`AuditActor::is_namespace_bounded`): the claim always bounds namespace-scoped routes and the `/namespaces` registry, the token never unlocks the observability detail tier (`/health`+`/status` give it the tenant tier: `status`, `ready`, `mode`, `admin_writes_enabled`, plus the always-present `namespace` block from `namespace_serving_block`, with `active` redacted to `null` when `namespace_bound_admits` rejects the data plane's namespace while `serving_scope`/`data_plane_single_namespace` stay mode-derived, never omitted and never another name; same field names/shapes as the detailed tier, `HealthTenantResponse` in `openapi.yaml`), and `authorize_namespace_bounded_global_route` refuses it on every global route outside `ns_claim_global_route_is_allowed` (viewer-key ceiling tokens use the stricter `ceiling_global_route_is_allowed`). The allowlists fail closed: a new global route is refused to bounded tokens until classified there and in `docs/admin_api.md`.
- Observability surfaces are tiered (`MetricsAuthPolicy` + `observability_detail_allowed` in `src/admin/mod.rs`): `/live` is always unauthenticated and returns only `{"status":"ok"}`; `/health`+`/status` return `status`+`ready` unauthenticated and full diagnostics only when authenticated; `/overload` returns coarse `{level}` unauthenticated and the full snapshot only when authenticated; `/metrics` returns `401` unless authenticated. "Authenticated" = valid admin JWT that is not namespace-bounded OR matching `FERRUM_METRICS_BEARER_TOKEN` OR a `FERRUM_METRICS_ALLOWED_CIDRS` source IP. On `/metrics` a presented namespace-bounded JWT is refused `403` before the CIDR check: the CIDR allowance covers only scrapes without such a token. Do not regress these to unauthenticated detail.
- `/health` (and `/overload`) still respond unauthenticated so liveness/LB probes work. The DB check stays cached for 15s in the lock-free `AdminState.cached_db_health` (`ArcSwap<Option<CachedDbHealthResult>>`) so unauthenticated probes cannot flood the pool. Refreshes are single-flight (`AdminState.db_health_refresh` + `cached_db_health_connected()`) with a 5s probe timeout: at most one DB health query runs per refresh window while cache hits stay lock-free.
- The `/health` response includes `database.pool` stats when connected, but only in the authenticated (detailed) tier.
- `/metrics/runtime` remains JWT-authenticated and cached through `runtime_metrics_cache()`.
- `GET /cluster` is JWT-authenticated. CP returns connected DPs from `DpNodeRegistry`; DP returns CP connection state including primary/fallback and `last_config_received_at`.
- DP backend egress attestation (#6020): DPs report presence-only egress metadata on `SubscribeRequest.backend_egress_policy`; `DpNodeInfo.backend_egress_policy` holds it (`None` = unknown). `DpNodeRegistry` is keyed per stream (`DpStreamKey`: namespace, principal, node id, process-wide stream seq); never re-key by node id, which let one stream hide another. The CP's `GET /backend-egress-policy` adds the optional `data_plane_attestation` (namespace-filtered) and `GET /cluster` the per-DP fields plus aggregate, both via `grpc::backend_egress_attestation`. Unknown DPs and empty sets never count as public-only; never add CIDRs to the report; the CP's own `public_only_guaranteed` stays false on `admission-only`.
- `GET /backend-capabilities` and `POST /backend-capabilities/refresh` are JWT-authenticated and expose only classifications plus probe timestamps.

## OpenAPI Parity

- Admin request/response changes, new endpoints, new fields, new status codes, and any new plugin schema must update `openapi.yaml`.
- UI integrations consume `openapi.yaml`; spec drift silently breaks downstream tooling.
- Keep docs under `docs/admin*.md` aligned with endpoint behavior.

## API Spec Management

- API specs are admin-only metadata. They must never be loaded by gateway runtime.
- Supported submissions are OpenAPI 2.0 and 3.0.x/3.1.x/3.2.x JSON or YAML.
- `x-ferrum-proxy` is required. `x-ferrum-upstream` and `x-ferrum-plugins` are supported extensions.
- Endpoints: `POST/PUT/GET/DELETE /api-specs[/{id}]`, `GET /api-specs/by-proxy/{proxy_id}`, and `GET /api-specs`.
- DB and CP modes are read/write for specs. DP and file mode reject spec endpoints.
- Original specs are gzip-compressed and stored with sha256/resource hash metadata.

## Hot-Path Guards

- Do not add `ApiSpec` to `GatewayConfig`.
- Do not add API spec blobs to `src/config/db_loader.rs` load/poll paths.
- Do not add API specs to `src/grpc/cp_server.rs` broadcasts. DPs never receive specs.
- Do not add API specs to periodic refresh, runtime snapshots, `ArcSwap`, or caches.
- Integration guard: `tests/integration/admin_db_api_specs_tests.rs`.

## Extraction And Validation

- Spec-extracted resources must use the same admission path as direct admin POSTs.
- Reuse `Proxy::normalize_fields()`, `validate_fields()`, the `plugins::validate_plugin_config*` helpers, and the `check_*_unique` uniqueness checks.
- Do not fork validation logic for specs.
- Pipeline: `extract_admitted()` (bounded admission) runs `extract_with_external_refs()` from `src/admin/api_specs/extractor.rs`, then `validate_bundle()` in `src/admin/api_specs/handlers.rs` applies the shared admission checks.
- Reject `x-ferrum-consumers`; consumers and credentials are managed through consumer endpoints.
- Reject plugin `scope != proxy` inside specs.
- Reject plugin `proxy_id` that differs from the spec proxy ID.
- Reject embedded credential keys by recursively walking the plugin `config` value. Do not reject merely because a plugin name contains `jwt`.

## Ownership And Replacement

- Nullable `api_spec_id` on proxies, upstreams, and plugin configs marks spec-owned resources.
- PUT `/api-specs/{id}` deletes resources owned by that spec and reinserts extracted resources.
- Hand-added resources with `api_spec_id NULL` survive PUT replacement.
- DELETE cascades through proxy foreign keys and manually cleans spec-owned upstreams; the upstream back-link intentionally has no FK.
- `replace_api_spec_bundle` compares `resource_hash`, excluding `api_spec_id`, `created_at`, and `updated_at`.
- If the resource hash matches on PUT, update only the `api_specs` row. Do not advance `updated_at` on proxies/upstreams/plugin configs.
- Matching resource hash must not trigger router/plugin cache rebuild, pool warmup, capability refresh, or DP broadcast.
- When changing the hash function, update SQL `db_loader.rs` and `mongo_store.rs` together.

## Storage Caps

- Request body cap is `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB`, default 25 MiB.
- MongoDB is also constrained by the 16 MB BSON document limit. Specs over about 14 MiB compressed should use SQL backends.
- MongoDB multi-document atomicity for spec replacement requires `FERRUM_MONGO_REPLICA_SET`.

## Backup, Restore, And Audit

- Restore entrypoints must normalize fields the same way as admin and loaders.
- Backup/restore changes that affect admin shapes require `openapi.yaml` and docs updates.
- Preserve audit behavior for security-sensitive admin operations.
- Validate path traversal and archive/file hostile input before reading or writing backup/spec artifacts.
