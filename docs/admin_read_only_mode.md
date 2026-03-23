# Admin Read-Only Mode

The Ferrum Gateway Admin API supports a configurable read-only mode that provides an additional layer of security for production deployments.

## Overview

The Admin Read-Only Mode allows you to restrict write operations (POST, PUT, DELETE) on the Admin API while still allowing read operations (GET) for monitoring and health checks. This feature is particularly useful in production environments where you want to prevent accidental configuration changes.

## Behavior

### Read Operations (Always Allowed)
All GET endpoints continue to work normally in read-only mode:
- `GET /proxies` - List all proxies
- `GET /proxies/{id}` - Get specific proxy
- `GET /consumers` - List all consumers
- `GET /consumers/{id}` - Get specific consumer
- `GET /plugin-configs` - List all plugin configurations
- `GET /plugin-configs/{id}` - Get specific plugin configuration

### Write Operations (Blocked in Read-Only Mode)
All write operations are blocked and return `403 Forbidden`:
- `POST /proxies` - Create new proxy
- `PUT /proxies/{id}` - Update existing proxy
- `DELETE /proxies/{id}` - Delete proxy
- `POST /consumers` - Create new consumer
- `PUT /consumers/{id}` - Update existing consumer
- `DELETE /consumers/{id}` - Delete consumer
- `POST /plugin-configs` - Create new plugin configuration
- `PUT /plugin-configs/{id}` - Update existing plugin configuration
- `DELETE /plugin-configs/{id}` - Delete plugin configuration

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
| `FERRUM_ADMIN_READ_ONLY` | `false` | Set Admin API to read-only mode (DP mode defaults to `true`) |

### Mode-Specific Behavior

#### Control Plane (CP) Mode
- **Respects** the `FERRUM_ADMIN_READ_ONLY` environment variable
- **Default**: Read-write (unless explicitly set to read-only)
- **Use Case**: Central configuration management where you may want to restrict changes

#### Data Plane (DP) Mode
- **Always** read-only regardless of environment variable
- **Reasoning**: Data plane nodes should not modify configuration
- **Security**: Ensures configuration changes only happen through the control plane

#### Database/File Modes
- **Respect** the `FERRUM_ADMIN_READ_ONLY` environment variable
- **Default**: Read-write (unless explicitly set to read-only)
- **Use Case**: Single-node deployments where you may want to restrict changes

## Use Cases

### Production Safety
```bash
# Enable read-only mode for production
FERRUM_ADMIN_READ_ONLY=true
```

Prevents accidental configuration changes that could cause service disruptions.

### Data Plane Security
Data plane nodes automatically run in read-only mode, ensuring they cannot modify their own configuration. This maintains the security boundary between control and data planes.

### Compliance
Meet security and compliance requirements for immutable infrastructure:
- PCI DSS compliance requirements
- Change management policies
- Audit trail integrity

### Maintenance
Allow operations teams to monitor the system and perform health checks without risking accidental configuration changes:
- Read-only access during maintenance windows
- Monitoring dashboards remain functional
- Health check endpoints continue to work

## Examples

### Enable Read-Only Mode
```bash
# Control Plane with read-only Admin API
FERRUM_MODE=cp \
FERRUM_ADMIN_READ_ONLY=true \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="admin-secret" \
cargo run --release
```

### Data Plane (Always Read-Only)
```bash
# Data Plane - Admin API is always read-only
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL="http://control-plane:50051" \
FERRUM_DP_GRPC_AUTH_TOKEN="<signed-jwt-token>" \
cargo run --release
```

### Database Mode with Read-Only
```bash
# Database mode with read-only Admin API
FERRUM_MODE=database \
FERRUM_ADMIN_READ_ONLY=true \
FERRUM_DB_URL="sqlite://ferrum.db" \
FERRUM_ADMIN_JWT_SECRET="admin-secret" \
cargo run --release
```

## Input Validation

The Admin API validates proxy configurations on create (`POST /proxies`) and update (`PUT /proxies/{id}`) requests. Invalid input returns `400 Bad Request` with a descriptive error message.

**Validation rules:**

| Field | Rule | Example Error |
|-------|------|---------------|
| `listen_path` | Must be non-empty and start with `/` | `"listen_path must start with '/'"` |
| `backend_host` | Must be non-empty | `"backend_host must not be empty"` |
| `backend_port` | Must be greater than 0 | `"backend_port must be greater than 0"` |

These validations apply in all operating modes (database, file, CP) and are enforced regardless of read-only mode.

## Implementation Details

### Code Changes
The read-only mode is implemented through:

1. **Configuration Layer**: `FERRUM_ADMIN_READ_ONLY` environment variable parsed into `EnvConfig`
2. **State Management**: `read_only` field added to `AdminState` struct
3. **Handler Protection**: All write handlers check `state.read_only` before processing
4. **Mode Integration**: DP mode always sets `read_only: true`, CP mode uses environment variable

### Security Considerations
- **JWT Authentication**: Required for all Admin API access
- **Network Isolation**: Read-only mode is enforced at the application level
- **Audit Logging**: All blocked write attempts are logged
- **Graceful Degradation**: Read operations continue to work during read-only enforcement

## Testing

The feature includes comprehensive tests:
- Unit tests for `AdminState` configuration
- Integration tests for read-only behavior
- Mode-specific behavior validation
- Error response format verification

## Migration Guide

### Existing Deployments
No changes required for existing deployments. The feature defaults to read-write mode for all modes except Data Plane.

### Enabling Read-Only
1. Set `FERRUM_ADMIN_READ_ONLY=true` in your environment
2. Restart the gateway service
3. Verify write operations are blocked (should return 403)
4. Verify read operations still work (should return 200)

### Disabling Read-Only
1. Set `FERRUM_ADMIN_READ_ONLY=false` in your environment
2. Restart the gateway service
3. Verify all operations work normally

## Troubleshooting

### Write Operations Still Work
- Check if `FERRUM_ADMIN_READ_ONLY=false` is set
- Verify the gateway process was restarted after changing the variable
- Check logs for read-only mode activation

### Read Operations Blocked
- Verify JWT authentication is working
- Check if you're using a Data Plane deployment (always read-only)
- Review logs for authentication errors

### Unexpected 403 Errors
- Check environment variable spelling: `FERRUM_ADMIN_READ_ONLY`
- Verify the gateway is using the correct configuration mode
- Review logs for read-only mode activation messages

## Best Practices

1. **Production**: Always enable read-only mode in production environments
2. **Development**: Keep read-write mode for development and testing
3. **Data Plane**: Rely on the automatic read-only behavior, don't set the variable
4. **Control Plane**: Use environment variables, not code changes, to control read-only mode
5. **Monitoring**: Set up monitoring to alert on write attempts in read-only mode
6. **Documentation**: Document your read-only mode configuration in runbooks
