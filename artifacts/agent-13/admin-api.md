# Launch-readiness Agent 13 — Admin API

Investigation only. No production code changes.

| Field | Value |
| --- | --- |
| Agent | Ferrum Edge Launch-Readiness Agent 13 |
| Domain | Admin API, OpenAPI parity, JWT/RBAC, CRUD, batch, API specs, namespaces, referential integrity, read-only modes |
| SHA | `bf05855f8429e466511610f9072f666b45cd309a` (`origin/main`, 2026-08-30) |
| Binary | `ferrum-edge 0.9.0` built with `CARGO_BUILD_JOBS=1 RUSTFLAGS='-C debuginfo=0'` |
| Ports | file `127.0.0.1:22200/22201`; database `22210/22211`; ns-claim `22220/22221` |
| Prefix | `fe-agent-13-` |
| Live probe | 84/84 pass (`artifacts/agent-13/probe-results.json`) |
| Verdict | **PASS** with residual in-flight items already tracked (do not duplicate) |

## Verdict

The Admin API surface on `bf05855f` matches the live router, docs, and charter contracts for JWT/RBAC, CRUD+batch, referential integrity, file-mode read-only, API-spec importer vs file-mode, and namespace header/registry behavior.

Three residual launch items remain **open with repair PRs**. This pass reconfirmed them and did **not** file new issues:

| Issue | Status | Repair PR | This pass |
| --- | --- | --- | --- |
| [#4287](https://github.com/ferrum-edge/ferrum-edge/issues/4287) OpenAPI omits `X-Ferrum-Config-Cursor` on sync 2xx/503 | OPEN | [#4339](https://github.com/ferrum-edge/ferrum-edge/pull/4339) | Live: served-namespace `POST /upstreams` 201 carries `X-Ferrum-Config-Cursor: 1:2`. Spec still declares the header only on `202`. |
| [#4284](https://github.com/ferrum-edge/ferrum-edge/issues/4284) global-route audit namespace is caller-controlled | OPEN | [#4335](https://github.com/ferrum-edge/ferrum-edge/pull/4335) | Static: still present in `src/admin/mod.rs` (`is_namespace_scoped_route` excludes TLS/mesh reset; audit still stamps request header). |
| [#4377](https://github.com/ferrum-edge/ferrum-edge/issues/4377) batch reference-check DB `Err` → 400 | OPEN | [#4379](https://github.com/ferrum-edge/ferrum-edge/pull/4379) | Static: `batch_validate` still folds lookup `Err` into `validation_errors` / 400. OpenAPI already lists 503 on `POST /batch`. |

Hot-zone issues from the charter are **closed and still fixed** on this SHA (see below). First-class namespace CRUD from historical [#3955](https://github.com/ferrum-edge/ferrum-edge/issues/3955) / [#3960](https://github.com/ferrum-edge/ferrum-edge/pull/3960) **is implemented**.

## 1. OpenAPI vs live router vs docs

### Path / method inventory

`openapi.yaml` declares **112** operations. `src/admin/mod.rs` implements the same 112:

- 105 `(Method, segments)` match arms
- 7 early GET guards: `/live`, `/health`, `/status`, `/overload`, `/metrics`, `/charges`, `/charges/sink/status`

No missing or extra endpoints. This inventory is also pinned by `tests/unit/openapi_yaml_tests.rs` (`every_documented_operation_matches_an_admin_dispatch_route`).

### Status codes / fields / enums / additionalProperties

Static review plus the existing OpenAPI parity suite:

- Resource create/update bodies use `deny_unknown_fields` (Proxy, Consumer, PluginConfig, Upstream, batch envelope).
- `BatchCreateRequest` is `additionalProperties: false` and accepts backup metadata keys so `GET /backup` remains a valid additive import. Unknown keys such as `updates` / `deletes` / `dry_run` are 400 (closed #4042).
- `ProxyCreate` uses `anyOf`: `upstream_id` **or** `backend_host`+`backend_port`. Live `POST /proxies` with only `upstream_id` returns 201 (closed #4029).
- Consumer ordinary responses redact `keyauth.key` as `[REDACTED]`; OpenAPI models this with separate Create/Update/Consumer/Backup schemas.
- `GET /api-specs` list envelope is `{items, limit, offset, next_offset, total}` — matches `ApiSpecListResponse`, not the generic `data`/`pagination` envelope.
- `/live` OpenAPI 401 is the documented #3857 client-cert withdrawal exception, not an endpoint auth requirement. Plaintext `/live` is unauthenticated `{"status":"ok"}`.

### Residual spec drift (already tracked)

`X-Ferrum-Config-Cursor` is attached at runtime by `complete_live_config_mutation_after_commit` on served-namespace sync 2xx and committed-but-not-live 503. `openapi.yaml` still only lists it on `AcceptedDeferred` (202). Docs (`docs/admin_api.md` live-apply section) already describe the 2xx/202/503 contract. That is #4287; do not file a second issue.

Writes to a namespace this process does **not** serve correctly omit the header (documented: no local generation to wait for). Observed: `POST /upstreams` in `fe-agent-13-tenant` → 201, no cursor; same call in served `ferrum` → 201 + `X-Ferrum-Config-Cursor: 1:2`.

## 2. Admin JWT / RBAC / namespace claims

Live on file mode and database mode (same secret, issuer `ferrum-edge`, HS256).

| Case | Observed |
| --- | --- |
| Missing Authorization | 401 `Missing Authorization header` |
| Malformed token | 401 `InvalidToken` |
| Wrong secret | 401 `InvalidSignature` |
| `alg=none` | 401 (jsonwebtoken rejects `none`) |
| `alg=HS384` | 401 `InvalidAlgorithm` (runtime is HS256-only) |
| Expired `exp` | 401 `ExpiredSignature` |
| Future `nbf` | 401 `ImmatureSignature` |
| Wrong `iss` | 401 `InvalidIssuer` |
| Missing `role` | 401 `Missing admin role claim; expected viewer, operator, or admin` |
| Unexpected `aud` (audience unset) | 401 `InvalidAudience` (RFC 7519 §4.1.3) |
| viewer GET `/proxies` | 200 |
| viewer POST `/proxies` | 403 required `operator` |
| viewer GET `/backup` | 403 required `admin` (unredacted export) |
| viewer GET `/api-specs` | 200 (metadata list) |
| viewer GET `/api-specs/{id}` | 403 required `admin` (raw document) |
| operator POST `/consumers` | 403 required `admin` |
| operator GET `/audit` | 403 required `admin` |
| admin GET `/health` | 200 detailed (`mode`, DB/pool when present) |
| unauth GET `/health` | 200 `{status, ready}` only |

### `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`

| Case | Observed |
| --- | --- |
| Token `ns=fe-agent-13-claim-a`, header match | POST `/proxies` 201 |
| Same token, header `fe-agent-13-claim-b` | 403 `JWT ns claim does not authorize namespace '...'` |
| Token with no `ns` on scoped route | 403 require-namespace-claim message |
| GET `/namespaces` with scoped token | 200 filtered to `["fe-agent-13-claim-a"]` (not 403) |
| GET `/namespaces/{other}` | 403 |
| GET `/cluster` (global) | 200 (not gated) |

Invalid `X-Ferrum-Namespace: ../evil` → 400 grammar rejection.

## 3. CRUD, batch, referential integrity, file-mode RO

Database SQLite, JWT admin/operator as required.

| Case | Observed | Tracking |
| --- | --- | --- |
| POST `/namespaces` empty tenant | 201 | #3955 implemented |
| POST `/upstreams` + POST `/proxies` with only `upstream_id` | 201, `backend_host=""` / `backend_port=0` | closed #4029 |
| DELETE referenced upstream | 409 `Upstream is referenced by one or more proxies...` | closed #4044 |
| POST `/consumers` keyauth | 201, key `[REDACTED]` | — |
| POST `/plugins/config` `access_control.allowed_consumers` | 201 | — |
| POST `/plugins/config` with `name` | 400 unknown field, expected `plugin_name` | closed #4031 |
| DELETE consumer still listed in `allowed_consumers` | 409 `...access_control plugin_configs...` | closed #4045 |
| POST `/batch` `updates`/`deletes`/`dry_run` | 400 unknown field | closed #4042 |
| POST `/batch` valid graph | 201 `created: {proxies:1,consumers:1,plugin_configs:1,upstreams:0}` | — |
| Cross-namespace GET | 404 | header isolation |
| DELETE last proxy → default orphan-clean hand-owned upstream | 204 then GET upstream 404 | closed #4046 / #4064 default |
| DELETE `?cleanup_orphaned_upstream=false` | 204 then GET upstream 200 | closed #4064 opt-out |

Implicit namespace (write with a new `X-Ferrum-Namespace` and no prior `POST /namespaces`) still isolates and appears in `GET /namespaces` as a derived name. Registry CRUD exists in addition to that implicit path.

### File mode

| Case | Observed | Docs |
| --- | --- | --- |
| POST `/proxies`, `/batch`, `/namespaces` | 403 `Admin API is in read-only mode` | `docs/admin_read_only_mode.md` |
| POST `/restore?confirm=true` | 503 `No database` | `docs/admin_backup_restore.md` (closed #4027) |
| GET `/backup` | 200 `source=cached` | same |
| GET `/proxies` | 200 | reads allowed |

## 4. API specs importer vs file-mode

| Mode | Write | Read | Observed |
| --- | --- | --- | --- |
| database | supported | supported | POST `/api-specs` 201; extracted proxy GET 200; viewer list 200; viewer raw GET 403 |
| file | 403 read-only | 503 no database | POST 403 `Admin API is in read-only mode`; GET 503 `No database configured` |

Matches `docs/admin_api.md` mode table. Spec endpoints never load into `GatewayConfig` (unchanged hot-path isolation).

Slight message spelling: restore uses `No database`; spec GET uses `No database configured`. Both 503. Not filed — documented shapes, not a contract break.

## 5. Namespaces

Historical #3955 asked for a registry. It shipped via #3960 and is live:

- `GET /namespaces` paginated `data: string[]` (union of registry + derived)
- `POST /namespaces` creates an empty tenant (201)
- `GET`/`PUT`/`DELETE /namespaces/{name}` exist; writes are admin-only; file mode 403
- `X-Ferrum-Namespace` still selects scoped resources; implicit create-by-header still works
- `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` filters list and 403s unauthorized registry get/rename/delete

No new “missing registry” issue.

## Hot-zone retest (closed)

| Issue | Closed by | Retest on `bf05855f` |
| --- | --- | --- |
| #3926 DB-mode 201 not live | #3987 | Served-namespace write returns 201 + covering cursor `1:2` |
| #4027 file restore 403 vs 503 | #4070 | File restore 503 `No database`; other writes 403 |
| #4029 dummy `backend_host` | #4070 | `upstream_id` alone → 201 |
| #4031 batch `name` vs `plugin_name` | #4070 | `name` → 400 |
| #4042 batch unknown keys | #4070 | `updates`/`deletes`/`dry_run` → 400 |
| #4043 restore omitted IDs | #4070 | Docs now state restore IDs required; not re-probed |
| #4044 DELETE upstream 409 | #4062 | 409 + unchanged upstream |
| #4045 DELETE consumer ACL | #4062 | 409 |
| #4046/#4064 orphan upstream | #4062 / #4073 | default 404; `cleanup_orphaned_upstream=false` keeps it |
| #3955 namespace CRUD | #3960 | POST/GET registry live |

## What was not live-probed

- CP/DP/mesh/Mongo/MySQL/Postgres admin surfaces (charter used SQLite + file)
- Injected database failure on batch reference checks (#4377 — needs a fault backend)
- TLS/ACME mutation audit-bucket spoof (#4284 — needs a TLS write + `GET /audit`)
- ACME/managed-TLS CRUD bodies beyond OpenAPI/router inventory
- Client-certificate withdrawal 401 on `/live` (#3857 transport path)

## New issues filed

None. Residual findings commented on existing tracking:

- https://github.com/ferrum-edge/ferrum-edge/issues/4287#issuecomment-5467740812
- https://github.com/ferrum-edge/ferrum-edge/issues/4284#issuecomment-5467740873
- https://github.com/ferrum-edge/ferrum-edge/issues/4377#issuecomment-5467740894
- Closed hot-zone retests: #3926, #3955, #4027, #4029, #4031, #4042, #4044, #4045, #4046, #4064

## Artifacts

- `artifacts/agent-13/admin-api.md` (this file)
- `artifacts/agent-13/probe_admin_api.py` (live probe harness)
- `artifacts/agent-13/probe-results.json` (84/84)

## Return

- **SHA:** `bf05855f8429e466511610f9072f666b45cd309a`
- **Status:** PASS (residual in-flight: #4287, #4284, #4377)
- **Issue URLs:** no new issues; comments on existing tracking
- **PR URL:** https://github.com/ferrum-edge/ferrum-edge/pull/4394
- **Verdict:** Admin API launch-ready on this SHA except the three already-tracked repair items.
