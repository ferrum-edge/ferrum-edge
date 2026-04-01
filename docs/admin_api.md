# Admin API Reference

The Admin API provides full CRUD operations for managing Ferrum Edge configuration at runtime. It is available in **Database** and **Control Plane** modes (read/write) and **Data Plane** mode (read-only).

See also:
- [admin_read_only_mode.md](admin_read_only_mode.md) — Read-only mode configuration
- [admin_backup_restore.md](admin_backup_restore.md) — Backup and restore details
- [admin_batch_api.md](admin_batch_api.md) — Batch operations
- [admin_metrics.md](admin_metrics.md) — Metrics endpoint details
- [OpenAPI specification](../openapi.yaml) — Full API schema

## Authentication

All endpoints (except `/health` and `/status`) require a valid HS256 JWT in the `Authorization: Bearer <token>` header, verified against `FERRUM_ADMIN_JWT_SECRET`.

Generate a token:
```bash
# Using any JWT library; payload can be minimal
# Example using Node.js jsonwebtoken:
node -e "console.log(require('jsonwebtoken').sign({sub:'admin'}, 'my-super-secret-jwt-key'))"
```

## Health Check (Unauthenticated)

```bash
curl http://localhost:9000/health
# or equivalently:
curl http://localhost:9000/status
# Returns: {"status": "ok", "timestamp": "...", "mode": "database"}
```

Both endpoints return the same response and do not require JWT authentication, making them suitable for load balancer health probes.

## Proxies

```bash
# List all proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "/new-api",
    "backend_protocol": "http",
    "backend_host": "backend",
    "backend_port": 3000,
    "strip_listen_path": true
  }' \
  http://localhost:9000/proxies

# Get a proxy
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}

# Update a proxy
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/new-api", "backend_host": "new-backend", "backend_port": 4000, "backend_protocol": "http"}' \
  http://localhost:9000/proxies/{proxy_id}

# Delete a proxy
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}
```

### Stream Proxy (TCP/UDP)

Stream proxies use `listen_port` instead of `listen_path`:

```bash
# Create a TCP stream proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "",
    "listen_port": 5432,
    "backend_protocol": "tcp",
    "backend_host": "db.internal",
    "backend_port": 5432
  }' \
  http://localhost:9000/proxies
```

The Admin API validates `listen_port` at creation and update time:
- **409 Conflict** if the port is already used by another stream proxy
- **409 Conflict** if the port conflicts with a gateway reserved port (proxy HTTP/HTTPS, admin HTTP/HTTPS, or CP gRPC)
- **409 Conflict** if the port is already bound by another process on the host (OS-level probe)

In **CP mode**, the gateway reserved port and OS-level checks are skipped since stream proxies run on remote Data Plane nodes.

## Consumers

```bash
# List consumers
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/consumers

# Create consumer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "credentials": {"keyauth": {"key": "my-key"}}}' \
  http://localhost:9000/consumers

# Update consumer credentials
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "new-api-key"}' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Delete a credential type
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth
```

## Plugin Configs

```bash
# List available plugin types
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins

# List all plugin configs
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins/config

# Create plugin config
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "rate_limiting",
    "config": {"limit_by": "ip", "requests_per_minute": 60},
    "scope": "global",
    "enabled": true
  }' \
  http://localhost:9000/plugins/config
```

## Upstreams

```bash
# List all upstreams
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams

# Create an upstream (load-balanced backend group)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend2.example.com", "port": 8080, "weight": 3}
    ],
    "algorithm": "weighted_round_robin",
    "health_checks": {
      "active": {
        "http_path": "/health",
        "interval_seconds": 10,
        "healthy_threshold": 3,
        "unhealthy_threshold": 3
      }
    }
  }' \
  http://localhost:9000/upstreams

# Get an upstream
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}

# Update an upstream
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-backend-pool",
    "targets": [
      {"host": "backend1.example.com", "port": 8080, "weight": 5},
      {"host": "backend3.example.com", "port": 8080, "weight": 2}
    ],
    "algorithm": "round_robin"
  }' \
  http://localhost:9000/upstreams/{upstream_id}

# Delete an upstream
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/upstreams/{upstream_id}
```

Supported algorithms: `round_robin`, `weighted_round_robin`, `least_connections`, `least_latency`, `consistent_hashing`, `random`.

To use an upstream with a proxy, set the proxy's `upstream_id` field. When set, the upstream's targets override the proxy's `backend_host`/`backend_port`. Each target may also specify an optional `path` field which overrides the proxy's `backend_path` when that target is selected.

## Backup & Restore

```bash
# Full backup — exports all proxies, consumers, plugins, upstreams (unredacted)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup > ferrum-backup.json

# Partial backup — only proxies and upstreams
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9000/backup?resources=proxies,upstreams" > partial-backup.json

# Restore from backup (destructive — replaces all existing config)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @ferrum-backup.json \
  "http://localhost:9000/restore?confirm=true"
```

The backup output is directly compatible with `POST /batch` (additive) and `POST /restore` (full replacement). Database inserts are chunked into 1,000-record transactions for large-scale imports.

See [admin_backup_restore.md](admin_backup_restore.md) for details.

## Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/admin/metrics
```

Returns:
```json
{
  "mode": "database",
  "config_last_updated_at": "2025-01-15T10:30:00Z",
  "config_source_status": "online",
  "proxy_count": 5,
  "consumer_count": 10,
  "requests_per_second_current": 150,
  "status_codes_last_second": {"200": 145, "404": 3, "429": 2}
}
```

See [admin_metrics.md](admin_metrics.md) for the full metrics reference.
