# Batch Admin API

## Overview

The `POST /batch` endpoint enables bulk creation of gateway resources in a single request. Each resource type is inserted within a database transaction, eliminating per-row transaction overhead and dramatically improving write throughput at scale.

**Performance**: ~3,400-5,500 resources/s with batch API vs ~5-116 resources/s with individual API calls (47x-687x improvement).

## Endpoint

```
POST /batch
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

## Request Body

The request body is a JSON object with optional arrays for each resource type:

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

Each resource in the arrays uses the same schema as the individual `POST` endpoint for that resource type. The `id`, `created_at`, and `updated_at` fields are auto-generated if omitted.

#### Consumers

```json
{
  "consumers": [
    {
      "username": "user-1",
      "custom_id": "tenant-1",
      "credentials": {
        "keyauth": "api-key-abc123"
      }
    },
    {
      "username": "user-2",
      "custom_id": "tenant-2",
      "credentials": {
        "keyauth": "api-key-def456"
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
      "backend_protocol": "http",
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
      "name": "key_auth",
      "enabled": true,
      "proxy_id": "<proxy-id>",
      "config": {}
    },
    {
      "name": "access_control",
      "enabled": true,
      "proxy_id": "<proxy-id>",
      "config": {
        "allow": ["user-1"]
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
      "credentials": {"keyauth": "key-001"}
    },
    {
      "username": "tenant-2",
      "credentials": {"keyauth": "key-002"}
    }
  ],
  "proxies": [
    {
      "id": "proxy-1",
      "name": "svc-1",
      "listen_path": "/svc/1",
      "backend_protocol": "http",
      "backend_host": "localhost",
      "backend_port": 9090
    },
    {
      "id": "proxy-2",
      "name": "svc-2",
      "listen_path": "/svc/2",
      "backend_protocol": "http",
      "backend_host": "localhost",
      "backend_port": 9090
    }
  ],
  "plugin_configs": [
    {
      "name": "key_auth",
      "enabled": true,
      "proxy_id": "proxy-1",
      "config": {}
    },
    {
      "name": "access_control",
      "enabled": true,
      "proxy_id": "proxy-1",
      "config": {"allow": ["tenant-1"]}
    },
    {
      "name": "key_auth",
      "enabled": true,
      "proxy_id": "proxy-2",
      "config": {}
    },
    {
      "name": "access_control",
      "enabled": true,
      "proxy_id": "proxy-2",
      "config": {"allow": ["tenant-2"]}
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
      {"username": "alice", "credentials": {"keyauth": "alice-api-key-2024"}},
      {"username": "bob", "credentials": {"keyauth": "bob-api-key-2024"}},
      {"username": "charlie", "credentials": {"keyauth": "charlie-api-key-2024"}}
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
        "credentials": {"keyauth": "mobile-secret-key"}
      }
    ],
    "proxies": [
      {
        "id": "payments-proxy",
        "name": "payments-api",
        "listen_path": "/api/payments",
        "backend_protocol": "http",
        "backend_host": "payments-service.internal",
        "backend_port": 8080
      }
    ],
    "plugin_configs": [
      {
        "name": "key_auth",
        "enabled": true,
        "proxy_id": "payments-proxy",
        "config": {}
      },
      {
        "name": "access_control",
        "enabled": true,
        "proxy_id": "payments-proxy",
        "config": {"allow": ["mobile-app"]}
      },
      {
        "name": "rate_limiting",
        "enabled": true,
        "proxy_id": "payments-proxy",
        "config": {"requests_per_second": 100}
      }
    ]
  }'
```

Once the DB poller picks up the new config (default 30s, or set `FERRUM_DB_POLL_INTERVAL_SECONDS=5` for faster feedback), the route is live:

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
        "backend_protocol": "http",
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
            "credentials": {"keyauth": t["api_key"]},
        })
        proxies.append({
            "id": proxy_id,
            "name": consumer_name,
            "listen_path": f"/tenant/{consumer_name}",
            "backend_protocol": "http",
            "backend_host": t["backend_host"],
            "backend_port": int(t["backend_port"]),
        })
        plugin_configs.append({
            "name": "key_auth",
            "enabled": True,
            "proxy_id": proxy_id,
            "config": {},
        })
        plugin_configs.append({
            "name": "access_control",
            "enabled": True,
            "proxy_id": proxy_id,
            "config": {"allow": [consumer_name]},
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

### Partial Success (207 Multi-Status)

Some resource types failed while others succeeded:

```json
{
  "created": {
    "proxies": 2,
    "consumers": 0,
    "plugin_configs": 4,
    "upstreams": 0
  },
  "errors": [
    "consumers: duplicate key value violates unique constraint"
  ]
}
```

### Validation

Each resource in the batch is validated before any database writes. If validation fails, the entire batch for that resource type is skipped and errors are returned. Validation includes:

- **All resources**: ID format (alphanumeric + `.`, `_`, `-`, max 254 chars), no duplicate IDs within the batch
- **Consumers**: Non-empty username, no duplicate usernames or custom_ids within the batch, custom_id normalization (empty string → null)
- **Proxies**: listen_path format (`/` prefix or `~` regex with compilation check), host entry format validation and lowercase normalization, no duplicate proxy IDs within the batch
- **Upstreams**: At least one target or service_discovery config, no duplicate names within the batch
- **Plugin configs**: Known plugin name, scope/proxy_id consistency (proxy scope requires proxy_id, global scope rejects proxy_id), no duplicate plugin config IDs within the batch

**Note**: Within-batch uniqueness is checked, but cross-batch uniqueness (against existing DB records) is enforced by database constraints. Database constraint violations are returned as errors in the response.

### Error Responses

| Status | Condition |
|--------|-----------|
| 400 | Invalid JSON body |
| 403 | Admin API is in read-only mode |
| 503 | No database available |

## Chunking Strategy

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

All list endpoints (`GET /proxies`, `GET /consumers`, `GET /plugin-configs`, `GET /upstreams`) support pagination via query parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `limit`   | 1000    | Maximum number of items to return (max: 10000) |
| `offset`  | 0       | Number of items to skip |

### Paginated Request

```bash
# Get the first 50 proxies
curl http://localhost:9000/proxies?limit=50

# Get the next 50
curl http://localhost:9000/proxies?limit=50&offset=50
```

### Response Format

When `limit` or `offset` is provided, the response wraps items in an envelope with pagination metadata:

```json
{
  "data": [ ... ],
  "pagination": {
    "offset": 50,
    "limit": 50,
    "count": 50,
    "total": 3000
  }
}
```

When no pagination parameters are provided, the response is a plain JSON array (backward-compatible with existing clients).

## Database Considerations

The batch API works with all supported databases (PostgreSQL, MySQL, SQLite). Each resource type's batch is wrapped in a single database transaction:

- **PostgreSQL/MySQL**: Handles concurrent batch writes well. Recommended for production workloads with high write throughput.
- **SQLite**: Single-writer lock means batch writes are serialized. Still significantly faster than individual API calls due to reduced transaction overhead, but PostgreSQL is preferred for write-heavy workloads.
