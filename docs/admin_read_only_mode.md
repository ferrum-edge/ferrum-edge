# Admin Read-Only Mode

## Overview

Read-only mode blocks Admin API requests that persist configuration or write to the database, while reads and authenticated operational actions keep working. Use it in production to prevent accidental configuration changes without losing diagnostic and recovery controls.

## Behavior

### Read Operations (Always Allowed)
All GET endpoints continue to work normally in read-only mode:
- `GET /proxies` - List proxies (paginated)
- `GET /proxies/{id}` - Get specific proxy
- `GET /consumers` - List consumers (paginated)
- `GET /consumers/{id}` - Get specific consumer
- `GET /plugins/config` - List plugin configurations (paginated)
- `GET /plugins/config/{id}` - Get specific plugin configuration

List endpoints return one page at a time (default 100 items, maximum 1000); see
[admin_api.md](admin_api.md) for the full pagination contract.

### Configuration Mutations (Blocked in Read-Only Mode)
Configuration and database mutations are blocked and return `403 Forbidden`, for example:
- `POST /proxies` - Create new proxy
- `PUT /proxies/{id}` - Update existing proxy
- `DELETE /proxies/{id}` - Delete proxy
- `POST /consumers` - Create new consumer
- `PUT /consumers/{id}` - Update existing consumer
- `DELETE /consumers/{id}` - Delete consumer
- `POST /plugins/config` - Create new plugin configuration
- `PUT /plugins/config/{id}` - Update existing plugin configuration
- `DELETE /plugins/config/{id}` - Delete plugin configuration

The same applies to every other persisted-config write: upstreams, consumer
credentials, namespaces, API specs, `POST /batch`, and `POST /restore`
(in file and DP modes, which have no database, `POST /restore` returns
`503 Service Unavailable` instead).

Operational POST endpoints that do not persist configuration remain available
with their normal JWT and role checks. These include
`POST /mesh/egress-scope/test`, `POST /backend-capabilities/refresh`, and
`POST /admin/tls/rotate/{surface}`.

### Error Response

When write operations are attempted in read-only mode, the API returns:

```json
{
  "error": "Admin API is in read-only mode"
}
```

With HTTP status code `403 Forbidden`.

## Configuration

### Environment Variable

| Variable | Default | Description |
|---|---|---|
| `FERRUM_ADMIN_READ_ONLY` | `false` | Opt in to read-only mode for `database` and `cp`. `file`, `dp`, `mesh`, and the optional `node_agent` admin listener are always read-only regardless of this value. |

### Mode-Specific Behavior

#### Database and Control Plane (CP) Modes
- **Respects** the `FERRUM_ADMIN_READ_ONLY` environment variable
- **Default**: Read-write (unless explicitly set to read-only)
- **Use Case**: Configuration-management modes where operators may want to restrict changes

#### File, Data Plane (DP), and Mesh Modes
- **Always** read-only regardless of environment variable
- **Reasoning**: These modes consume configuration from a file or management plane rather than persisting Admin API mutations
- **Security**: Setting the variable to `false` cannot enable writes in these modes

#### Node Agent Mode
- **Always** read-only when its opt-in admin listener is enabled
- **Scope**: The listener exposes operational health and metrics surfaces, not configuration mutation APIs

## Use Cases

### Production Safety
```bash
# Enable read-only mode for production
FERRUM_ADMIN_READ_ONLY=true
```

Prevents accidental configuration changes that could cause service disruptions.

### Data Plane Security
File, data-plane, mesh, and node-agent admin surfaces automatically run in read-only mode, ensuring they cannot persist configuration mutations. This maintains the security boundary between configuration owners and consumers.

### Compliance and Maintenance
Freeze configuration to satisfy change-management policies or during maintenance
windows, while monitoring dashboards and health checks keep working.

## Examples

### Enable Read-Only Mode
```bash
# Control Plane with read-only Admin API
FERRUM_MODE=cp \
FERRUM_ADMIN_READ_ONLY=true \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="change-me-to-a-32-character-admin-secret" \
cargo run --release -- run
```

### Data Plane (Always Read-Only)
```bash
# Data Plane - Admin API is always read-only
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="http://control-plane:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-to-a-32-character-grpc-secret" \
cargo run --release -- run
```

### Database Mode with Read-Only
```bash
# Database mode with read-only Admin API
FERRUM_MODE=database \
FERRUM_ADMIN_READ_ONLY=true \
FERRUM_DB_URL="sqlite://ferrum.db" \
FERRUM_ADMIN_JWT_SECRET="change-me-to-a-32-character-admin-secret" \
cargo run --release -- run
```

## Implementation Details

`FERRUM_ADMIN_READ_ONLY` is parsed into `EnvConfig.admin_read_only` and copied to
`AdminState.read_only`. Every write handler passes through the admission gate
(`AdminState::admit_write` and related helpers in `src/admin/mod.rs`), which
returns the `403` above when `read_only` is set. The `file`, `dp`, `mesh`, and
`node_agent` modes hard-code `read_only: true`; `database` and `cp` use the
environment variable.

### Security Considerations
- **Authentication**: Management endpoints require an admin JWT. Observability endpoints retain their documented tiering: `/live` is minimal and unauthenticated; `/health`, `/status`, and `/overload` expose only coarse unauthenticated state; `/metrics` and detailed diagnostics require an accepted admin or metrics credential/policy.
- **Network Isolation**: Read-only mode is enforced at the application level
- **Blocked Write Observability**: Every blocked write increments the `ferrum_admin_read_only_rejected_mutations_total` Prometheus counter. A sampled structured `warn!` log (`admin mutation blocked by read-only mode`, with HTTP method, sanitized path, namespace, `outcome=forbidden`, and the running total; never request bodies, tokens, or credentials) is emitted for the first rejection and then at most once per 5 seconds on every 1,024th rejection. Observe-only surfaces such as `/health` do not increment the counter or emit these warnings, so health probes cannot inflate the signal.
- **Audit Events**: Blocked read-only mutations do **not** produce admin audit events; the durable audit pipeline runs only after read-only admission succeeds. Use the structured warning log and Prometheus counter for alerting and compliance evidence.
- **Sensitive Reads**: Read-only mode blocks mutations only; it does not make management-plane reads, diagnostics, or bearer tokens safe to expose on an untrusted network
- **Graceful Degradation**: Read operations continue to work during read-only enforcement

## Migration Guide

### Existing Deployments
No changes are required for existing deployments. `database` and `cp` default to read-write; `file`, `dp`, `mesh`, and the optional `node_agent` admin listener remain unconditionally read-only.

### Enabling Read-Only
1. Set `FERRUM_ADMIN_READ_ONLY=true` in your environment
2. Restart the gateway service
3. Verify write operations are blocked (should return 403)
4. Verify read operations still work (should return 200)

### Disabling Read-Only
1. In `database` or `cp` mode, set `FERRUM_ADMIN_READ_ONLY=false` in your environment
2. Restart the gateway service
3. Verify all operations work normally

This setting cannot enable mutations in `file`, `dp`, `mesh`, or `node_agent` mode.

## Troubleshooting

### Write Operations Still Work
- Confirm the gateway is running in `database` or `cp` mode; those are the only modes where the variable can enable or disable mutations
- Check if `FERRUM_ADMIN_READ_ONLY=false` is set
- Verify the gateway process was restarted after changing the variable

### Read Operations Blocked
- Verify JWT authentication is working
- Check if you're using a Data Plane deployment (always read-only)
- Review logs for authentication errors

### Unexpected 403 Errors
- Check environment variable spelling: `FERRUM_ADMIN_READ_ONLY`
- Verify the gateway is using the correct configuration mode
- Check `ferrum_admin_read_only_rejected_mutations_total` or the `admin mutation blocked by read-only mode` warning to confirm read-only mode is the cause

## Best Practices

1. **Production**: Enable read-only mode for production `database`/`cp` deployments that must not accept configuration mutations; the consuming modes enforce it automatically
2. **Development**: Keep read-write mode for development and testing
3. **File/Data Plane/Mesh/Node Agent**: Rely on the automatic read-only behavior; the variable cannot make these modes writable
4. **Monitoring**: Alert on `increase(ferrum_admin_read_only_rejected_mutations_total[15m]) > 0` and on the structured `admin mutation blocked by read-only mode` warning log
5. **Documentation**: Document your read-only mode configuration in runbooks
