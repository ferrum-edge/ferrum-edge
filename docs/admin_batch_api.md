# Batch Admin API

## Overview

The `POST /batch` endpoint enables bulk creation of gateway resources in a single request. The whole submitted graph is inserted in **one** database transaction, eliminating per-row transaction overhead and dramatically improving write throughput at scale.

**Performance**: ~3,400-5,500 resources/s with batch API vs ~5-116 resources/s with individual API calls (47x-687x improvement).

## Atomicity Guarantee

**A batch is applied all-or-nothing.** Every dependency phase — consumers and
upstreams, then proxies, then plugin configs, then the proxy↔plugin
associations — and every internal 1,000-record chunk share one transaction and
one commit.

- If any part fails, **no resource from the request is durable**. The response
  carries no `created` counts, and `"rollback": "not_needed"` records that there
  was never a partial graph to compensate for.
- Because a failed batch leaves nothing behind, **retrying the identical payload
  is idempotent** — the resources from a failed attempt cannot conflict with the
  retry.
- The endpoint never returns a partial success. There is no `207 Multi-Status`
  response.
- The namespace config-admission lease that authorized the batch is re-verified
  inside the persisting transaction. If it lapsed, the transaction is aborted
  (`503`) rather than committing a graph another writer may have invalidated.
  Expiry is compared against the *database's* current clock at that final gate —
  SQL backends use `now()`, MongoDB uses `$$NOW` — so neither a long transaction
  nor a retried one can commit against a stale timestamp.

The guarantee covers only the resources in the request. It does not roll back
audit events (written after the commit) or unrelated resources that already
existed in the namespace.

### Backend support

| Backend | Guarantee | Notes |
|---------|-----------|-------|
| PostgreSQL | Always | One `BEGIN`/`COMMIT` for the whole graph |
| MySQL | Always | One `BEGIN`/`COMMIT` for the whole graph |
| SQLite | Always | One transaction; the single-writer lock serializes batches |
| MongoDB (replica set) | Always | One `ClientSession` transaction for the whole graph |
| MongoDB (standalone) | **Not supported** | `POST /batch` returns `501` before any mutation |

MongoDB multi-document transactions require a replica set (or a sharded cluster);
`startTransaction` is rejected on a standalone `mongod`, and a config graph has
no single-document representation to swap atomically instead. Rather than fall
back to per-family writes that can strand half a graph, standalone deployments
are refused up front:

```json
{
  "error": "Atomic batch configuration is not supported by the configured database deployment",
  "detail": "MongoDB multi-document transactions require a replica set; set FERRUM_MONGO_REPLICA_SET (or a ?replicaSet= URL option) so POST /batch can persist the whole graph in one transaction"
}
```

Set `FERRUM_MONGO_REPLICA_SET` (or a `?replicaSet=` option on `FERRUM_DB_URL`) to
enable the endpoint. Individual resource endpoints (`POST /proxies`,
`POST /consumers`, …) are unaffected and continue to work on standalone MongoDB.

Because a MongoDB transaction is bounded by the server's oplog entry size (16 MB
by default) and `transactionLifetimeLimitSeconds`, very large single requests can
exceed those limits. That failure is still atomic — nothing is applied — but
split such imports into several smaller `POST /batch` requests.

## Endpoint

```
POST /batch
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

## Request Body

The request body is a JSON object with optional arrays for each resource type.
Unknown top-level keys are rejected with `400` — there is no `updates`,
`deletes`, or `dry_run`. `GET /backup` metadata (`version`, `ferrum_version`,
`exported_at`, `source`, `counts`) and the backup-only `api_specs` /
`gateway_trust_bundles` sections are accepted and ignored so a backup file
remains a valid additive import. Batch does not persist those backup-only
sections; use `POST /restore` or the dedicated endpoints.

```json
{
  "consumers": [ ... ],
  "upstreams": [ ... ],
  "proxies": [ ... ],
  "plugin_configs": [ ... ]
}
```

All fields are optional. Include only the resource types you need to create. Resources are processed in dependency order:

1. **consumers** and **upstreams** first (no dependencies)
2. **proxies** second (may reference `upstream_id`)
3. **plugin_configs** last (reference `proxy_id` via the proxy_plugins junction)

### Resource Schemas

Each resource in the arrays uses the same schema as the individual `POST` endpoint for that resource type. The `id`, `created_at`, and `updated_at` fields are auto-generated if omitted. Plugin configs use `plugin_name` (not `name`). A proxy that sets `upstream_id` may omit `backend_host` and `backend_port`; the upstream's targets supply the dial address.

Consumer `credentials` map each built-in type (`keyauth`, `basicauth`, `jwt`, `hmac_auth`, `mtls_auth`) to a **non-empty array of credential objects** — for example `keyauth: [{ "key": "..." }]`, `basicauth: [{ "password": "..." }]`, and `hmac_auth: [{ "secret": "..." }]` (32+ characters). Plain strings are rejected with `400`.

Plaintext Basic-auth passwords are hashed during batch preparation. This requires `FERRUM_BASIC_AUTH_HMAC_SECRET` to be configured with at least 32 bytes; a missing or weak operator secret returns `500 Internal Server Error` before any batch resource is persisted. Invalid Basic credential shapes remain request errors and return `400`.

#### Consumers

```json
{
  "consumers": [
    {
      "username": "user-1",
      "custom_id": "tenant-1",
      "credentials": {
        "keyauth": [{ "key": "api-key-abc123" }]
      }
    },
    {
      "username": "user-2",
      "custom_id": "tenant-2",
      "credentials": {
        "keyauth": [{ "key": "api-key-def456" }]
      }
    }
  ]
}
```

#### Proxies

```json
{
  "proxies": [
    {
      "name": "service-a",
      "listen_path": "/api/service-a",
      "backend_scheme": "http",
      "backend_host": "svc-a.internal",
      "backend_port": 8080
    }
  ]
}
```

#### Plugin Configs

```json
{
  "plugin_configs": [
    {
      "plugin_name": "key_auth",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "<proxy-id>",
      "config": {}
    },
    {
      "plugin_name": "access_control",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "<proxy-id>",
      "config": {
        "allowed_consumers": ["user-1"]
      }
    }
  ]
}
```

#### Upstreams

```json
{
  "upstreams": [
    {
      "name": "backend-pool",
      "algorithm": "round_robin",
      "targets": [
        {"host": "10.0.1.1", "port": 8080, "weight": 100},
        {"host": "10.0.1.2", "port": 8080, "weight": 100}
      ]
    }
  ]
}
```

### Full Example

Create consumers, proxies, and plugin configs in a single request:

```json
{
  "consumers": [
    {
      "username": "tenant-1",
      "credentials": {"keyauth": [{ "key": "key-001" }]}
    },
    {
      "username": "tenant-2",
      "credentials": {"keyauth": [{ "key": "key-002" }]}
    }
  ],
  "proxies": [
    {
      "id": "proxy-1",
      "name": "svc-1",
      "listen_path": "/svc/1",
      "backend_scheme": "http",
      "backend_host": "localhost",
      "backend_port": 9090
    },
    {
      "id": "proxy-2",
      "name": "svc-2",
      "listen_path": "/svc/2",
      "backend_scheme": "http",
      "backend_host": "localhost",
      "backend_port": 9090
    }
  ],
  "plugin_configs": [
    {
      "plugin_name": "key_auth",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "proxy-1",
      "config": {}
    },
    {
      "plugin_name": "access_control",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "proxy-1",
      "config": {"allowed_consumers": ["tenant-1"]}
    },
    {
      "plugin_name": "key_auth",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "proxy-2",
      "config": {}
    },
    {
      "plugin_name": "access_control",
      "enabled": true,
      "scope": "proxy",
      "proxy_id": "proxy-2",
      "config": {"allowed_consumers": ["tenant-2"]}
    }
  ]
}
```

## Usage Examples

### curl: Create consumers with API keys

```bash
curl -X POST http://localhost:9000/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "consumers": [
      {"username": "alice", "credentials": {"keyauth": [{ "key": "alice-api-key-2024" }]}},
      {"username": "bob", "credentials": {"keyauth": [{ "key": "bob-api-key-2024" }]}},
      {"username": "charlie", "credentials": {"keyauth": [{ "key": "charlie-api-key-2024" }]}}
    ]
  }'
```

**Response:**
```json
{"created":{"proxies":0,"consumers":3,"plugin_configs":0,"upstreams":0}}
```

### curl: Provision a complete service with auth in one call

This creates a consumer, a proxy route, and attaches key_auth + access_control plugins -- all in a single request:

```bash
curl -X POST http://localhost:9000/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "consumers": [
      {
        "username": "mobile-app",
        "custom_id": "mobile-team",
        "credentials": {"keyauth": [{ "key": "mobile-secret-key" }]}
      }
    ],
    "proxies": [
      {
        "id": "payments-proxy",
        "name": "payments-api",
        "listen_path": "/api/payments",
        "backend_scheme": "http",
        "backend_host": "payments-service.internal",
        "backend_port": 8080
      }
    ],
    "plugin_configs": [
      {
        "plugin_name": "key_auth",
        "enabled": true,
        "scope": "proxy",
        "proxy_id": "payments-proxy",
        "config": {}
      },
      {
        "plugin_name": "access_control",
        "enabled": true,
        "scope": "proxy",
        "proxy_id": "payments-proxy",
        "config": {"allowed_consumers": ["mobile-app"]}
      },
      {
        "plugin_name": "rate_limiting",
        "enabled": true,
        "scope": "proxy",
        "proxy_id": "payments-proxy",
        "config": {"limits": [{"scope": "default", "requests_per_second": 100}]}
      }
    ]
  }'
```

Once the DB poller picks up the new config (default 30s, or set `FERRUM_DB_POLL_INTERVAL=5` for faster feedback), the route is live:

```bash
curl http://localhost:8000/api/payments/checkout \
  -H "X-API-Key: mobile-secret-key"
```

### curl: Create a load-balanced upstream with proxies

```bash
curl -X POST http://localhost:9000/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "upstreams": [
      {
        "id": "user-svc-upstream",
        "name": "user-service-pool",
        "algorithm": "round_robin",
        "targets": [
          {"host": "10.0.1.10", "port": 3000, "weight": 100},
          {"host": "10.0.1.11", "port": 3000, "weight": 100},
          {"host": "10.0.1.12", "port": 3000, "weight": 50}
        ],
        "health_checks": {
          "active": {
            "http_path": "/health",
            "interval": 10,
            "healthy_threshold": 2,
            "unhealthy_threshold": 3
          }
        }
      }
    ],
    "proxies": [
      {
        "name": "user-service",
        "listen_path": "/api/users",
        "backend_scheme": "http",
        "upstream_id": "user-svc-upstream"
      }
    ]
  }'
```

### Python: Bulk-provision tenants from a CSV

```python
import csv
import json
import requests

ADMIN_URL = "http://localhost:9000"
TOKEN = "your-jwt-token"
CHUNK_SIZE = 100

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

# Read tenants from CSV (columns: tenant_name, api_key, backend_host, backend_port)
with open("tenants.csv") as f:
    tenants = list(csv.DictReader(f))

# Process in chunks of 100
for i in range(0, len(tenants), CHUNK_SIZE):
    chunk = tenants[i : i + CHUNK_SIZE]

    consumers = []
    proxies = []
    plugin_configs = []

    for t in chunk:
        consumer_name = t["tenant_name"]
        proxy_id = f"proxy-{consumer_name}"

        consumers.append({
            "username": consumer_name,
            "credentials": {"keyauth": [{"key": t["api_key"]}]},
        })
        proxies.append({
            "id": proxy_id,
            "name": consumer_name,
            "listen_path": f"/tenant/{consumer_name}",
            "backend_scheme": "http",
            "backend_host": t["backend_host"],
            "backend_port": int(t["backend_port"]),
        })
        plugin_configs.append({
            "plugin_name": "key_auth",
            "enabled": True,
            "scope": "proxy",
            "proxy_id": proxy_id,
            "config": {},
        })
        plugin_configs.append({
            "plugin_name": "access_control",
            "enabled": True,
            "scope": "proxy",
            "proxy_id": proxy_id,
            "config": {"allowed_consumers": [consumer_name]},
        })

    resp = requests.post(
        f"{ADMIN_URL}/batch",
        headers=headers,
        json={
            "consumers": consumers,
            "proxies": proxies,
            "plugin_configs": plugin_configs,
        },
    )
    result = resp.json()
    print(f"Chunk {i // CHUNK_SIZE + 1}: {result['created']}")
```

### Verifying batch results

After creating resources, list them with pagination to confirm:

```bash
# Check total consumer count
curl -s "http://localhost:9000/consumers?limit=1" \
  -H "Authorization: Bearer $TOKEN" | jq '.pagination.total'

# List first 10 proxies
curl -s "http://localhost:9000/proxies?limit=10" \
  -H "Authorization: Bearer $TOKEN" | jq '.data[].listen_path'
```

## Response

### Success (201 Created)

All resources created successfully:

```json
{
  "created": {
    "proxies": 2,
    "consumers": 2,
    "plugin_configs": 4,
    "upstreams": 0
  }
}
```

### Failure (nothing applied)

A batch that does not commit returns an error object with no `created` counts.
Every resource in the request is absent, so the identical payload can be retried
once the reported cause is addressed:

```json
{
  "error": "Resource identity conflicts with an existing resource in the namespace",
  "rollback": "not_needed"
}
```

### Validation

Each resource in the batch is validated before any database writes. If validation fails, the entire batch for that resource type is skipped and errors are returned. Validation includes:

- **All resources**: ID format (alphanumeric + `.`, `_`, `-`, max 254 chars), no duplicate IDs within the batch
- **Consumers**: Non-empty username, no duplicate usernames or custom_ids within the batch, custom_id normalization (empty string → null)
- **Proxies**: listen_path format (`/` prefix, `=/` exact path, or `~` regex with compilation check), host entry format validation and lowercase normalization, no duplicate proxy IDs within the batch
- **Upstreams**: At least one target or service_discovery config, no duplicate names within the batch
- **Plugin configs**: Known plugin name (`plugin_name`, same field as `POST /plugins/config`), scope/proxy_id consistency (proxy scope requires proxy_id, global and proxy_group scopes reject proxy_id), no duplicate plugin config IDs within the batch

**Note**: Within-batch uniqueness is checked, but cross-batch uniqueness (against existing DB records) is enforced by database constraints. Database constraint violations are returned as errors in the response.

### Error Responses

| Status | Condition | Applied? |
|--------|-----------|----------|
| 201 | Whole graph committed | Yes, in full |
| 400 | Invalid JSON body, unknown top-level envelope key, or graph validation failed — payload problems only, never a database failure | No |
| 403 | Admin API is in read-only mode | No |
| 409 | A resource conflicts with an existing resource or with another resource in the same request (duplicate ID, name, listen path, or consumer identity) | No |
| 500 | Server-side resource preparation failed, including a missing or weak `FERRUM_BASIC_AUTH_HMAC_SECRET` for plaintext Basic credentials | No |
| 501 | The configured database deployment cannot provide the all-or-nothing guarantee (standalone MongoDB) — refused before any mutation | No |
| 503 | No database available, a reference-check lookup or candidate-validation load failed, the datastore write failed, or the namespace config-admission lease lapsed before commit | No |

Every non-`201` status leaves the namespace as it was, so retrying the same
payload is safe. `409`, `501`, and the datastore/lease `503`s are raised by the
persistence attempt and carry `"rollback": "not_needed"`. Statuses raised
before persistence keep their shared shapes: `400` returns `error` +
`validation_errors`; a namespace-admission `503` returns the shared
admission-unavailable body; a database error while validating references
returns `503` with the redacted `db_error_response` body. No failure body
ever carries `created` counts.

A database failure anywhere in the validation phase is a retryable `503`, never
a `400`. This covers the reference lookups and, since issue #4527, the four
candidate-validation loads that run before them — transaction-log schema,
consumer credentials, mTLS compatibility, and the plugin graph. The plugin-graph
load is the first database call for any batch carrying `plugin_configs`, so a
Terraform/GitOps caller that previously read `400 "Batch validation failed"`
during a pool exhaustion and abandoned the work now sees the retryable status.
`400` is reserved for payload problems, which are the only failures a retry of
the identical body cannot fix.

**One residual case the server cannot decide.** If the database acknowledges the
commit but the acknowledgement is lost in transit, the transaction is durable
while Ferrum reports `503`. A retry of the identical payload then answers `409`
instead of `201` — that is the signal to re-read the namespace (`GET /backup`)
before retrying again, rather than evidence of a second failure.

## Chunking Strategy

The atomicity guarantee is per request: one request is one transaction. Splitting
a provisioning run across several requests therefore splits it across several
transactions — each request is individually all-or-nothing, but an earlier
request that already committed stays committed if a later one fails. Keep
resources that must be installed together (a proxy, its upstream, and its
plugins) in the same request.

For large-scale provisioning, send resources in chunks rather than one massive request. A chunk size of 100 resources per request provides a good balance between throughput and memory usage:

```bash
# Example: create 3,000 consumers in 30 batch requests
for chunk in $(seq 0 100 2900); do
  curl -s -X POST http://localhost:9000/batch \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"consumers\": $(generate_chunk $chunk 100)}"
done
```

## Pagination on List Endpoints

All list endpoints (`GET /proxies`, `GET /consumers`, `GET /plugins/config`, `GET /upstreams`) support pagination via query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `limit`   | 100     | Maximum number of items to return (max: 1000; `0` means the default) |
| `offset`  | 0       | Number of items to skip (max: 2^63 - 1) |

An omitted `limit` applies the default of 100 — list endpoints never return an
unbounded collection. Use `GET /backup` when you need a full export. Malformed,
negative, or out-of-range `limit`/`offset` values are rejected with `400` rather
than coerced to a default, and validation runs after authentication, so an
unauthenticated caller still receives `401`.

### Paginated Request

```bash
# Get the first 50 proxies
curl http://localhost:9000/proxies?limit=50

# Get the next 50
curl http://localhost:9000/proxies?limit=50&offset=50
```

### Response Format

List responses always use the pagination envelope, whether or not `limit` and
`offset` are supplied:

```json
{
  "data": [ ... ],
  "pagination": {
    "offset": 50,
    "limit": 50,
    "total": 3000
  }
}
```

`pagination.limit` reports the page size the server applied — 100 when the
request omitted `limit` — not the number of items in `data`.

## Database Considerations

The batch API works with PostgreSQL, MySQL, SQLite, and replica-set MongoDB (see [Backend support](#backend-support)). Resources are written in bounded chunks of up to 1,000 records, but every chunk shares the request's single transaction — a chunk boundary commits nothing, so a failure after one leaves nothing durable:

- **PostgreSQL/MySQL**: Handles concurrent batch writes well. Recommended for production workloads with high write throughput.
- **SQLite**: Single-writer lock means batch writes are serialized. Still significantly faster than individual API calls due to reduced transaction overhead, but PostgreSQL is preferred for write-heavy workloads.
- **MongoDB**: Requires a replica set for `POST /batch`; a standalone `mongod` is refused with `501`.

Concurrency: the request holds the namespace config-admission lease from
validation through commit, and the backend re-verifies that lease inside the
persisting transaction. Another admin writer therefore cannot interleave with the
graph the request validated — it either commits before the batch's transaction
opens (and the batch re-validates against it) or after the batch commits.
