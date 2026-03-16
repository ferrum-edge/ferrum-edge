# Ferrum Gateway Test Suite

This directory contains the comprehensive test suite for Ferrum Gateway, organized into modular test files for easy maintenance and scalability.

## 📁 Test Structure

```
tests/
├── README.md                      # This file - test documentation
├── plugin_utils.rs                # Shared test utilities and helpers
├── stdout_logging_tests.rs         # stdout_logging plugin tests
├── http_logging_tests.rs          # http_logging plugin tests
├── transaction_debugger_tests.rs  # transaction_debugger plugin tests
├── key_auth_tests.rs              # key_auth plugin tests
├── jwt_auth_plugin_tests.rs       # jwt_auth plugin tests
├── basic_auth_tests.rs            # basic_auth plugin tests
├── oauth2_auth_tests.rs           # oauth2_auth plugin tests
├── access_control_tests.rs        # access_control plugin tests (IP/CIDR + consumer)
├── request_transformer_tests.rs   # request_transformer plugin tests
├── response_transformer_tests.rs  # response_transformer plugin tests
├── rate_limiting_tests.rs         # rate_limiting plugin tests
├── plugin_integration_tests.rs    # Cross-plugin integration tests
├── dns_tests.rs                   # DNS cache and resolution tests
├── env_config_tests.rs            # Environment configuration tests
├── config_file_loader_tests.rs    # Configuration file loading tests
├── config_types_tests.rs          # Configuration type validation tests
├── proxy_tests.rs                 # Proxy routing and matching tests
├── admin_tests.rs                 # Admin API JWT authentication tests
├── admin_enhanced_tls_tests.rs   # Admin API TLS/mTLS tests
├── admin_listeners_tests.rs       # Admin API separate listeners tests
├── admin_read_only_tests.rs       # Admin API read-only mode tests
├── backend_mtls_tests.rs         # Backend mTLS functionality tests
├── frontend_tls_tests.rs          # Frontend TLS tests
├── separate_listeners_tests.rs    # Separate HTTP/HTTPS listeners tests
├── websocket_auth_tests.rs        # WebSocket authentication tests
├── websocket_echo_server.rs       # WebSocket echo server for testing
├── secure_echo_server_simple.rs   # Secure echo server for TLS testing
├── websocket_gateway_test.rs       # Gateway WebSocket integration test
├── config.yaml                   # Test configuration with WebSocket settings
├── certs/                        # TLS certificates for testing
│   ├── server.crt
│   ├── server.key
│   └── client.crt
└── performance/                  # Performance testing directory
    ├── README.md
    └── [performance test files]
```

## 🚀 Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test Files
```bash
# Plugin tests
cargo test --test stdout_logging_tests
cargo test --test http_logging_tests
cargo test --test transaction_debugger_tests
cargo test --test key_auth_tests
cargo test --test jwt_auth_plugin_tests
cargo test --test basic_auth_tests
cargo test --test oauth2_auth_tests
cargo test --test access_control_tests
cargo test --test request_transformer_tests
cargo test --test response_transformer_tests
cargo test --test rate_limiting_tests
cargo test --test plugin_integration_tests

# Core module tests
cargo test --test dns_tests
cargo test --test env_config_tests

# Configuration tests
cargo test --test config_file_loader_tests
cargo test --test config_types_tests

# Proxy tests
cargo test --test proxy_tests

# Admin API tests
cargo test --test admin_tests
cargo test --test admin_enhanced_tls_tests
cargo test --test admin_listeners_tests
cargo test --test admin_read_only_tests

# TLS tests
cargo test --test backend_mtls_tests
cargo test --test frontend_tls_tests
cargo test --test separate_listeners_tests

# WebSocket tests
cargo test --test websocket_auth_tests

# Integration tests
cargo test --test websocket_gateway_test
```

### Run Tests by Pattern
```bash
# Run all plugin-related tests
cargo test plugin

# Run all configuration tests
cargo test config

# Run all admin API tests
cargo test admin

# Run specific test functions
cargo test test_stdout_logging_plugin_creation
cargo test test_key_auth_plugin_successful_auth
cargo test test_jwt_token_validation
cargo test test_admin_api_integration
```

### Run Tests with Output
```bash
# Verbose output
cargo test -- --nocapture

# Show test execution time
cargo test -- --ignored

# Run only ignored tests (if any)
cargo test -- --ignored
```

## 🧪 WebSocket Test Infrastructure

The test suite includes WebSocket test servers for comprehensive WebSocket functionality testing:

### Test Servers
```bash
# Run WebSocket echo server (port 8080)
cargo test --test websocket_echo_server -- --nocapture

# Run secure echo server (port 8443)  
cargo test --test secure_echo_server_simple -- --nocapture

# Run WebSocket gateway integration test
cargo test --test websocket_gateway_test -- --nocapture
```

### Manual Testing Setup
For manual WebSocket testing with the gateway:

1. **Start echo server:**
   ```bash
   cargo test --test websocket_echo_server -- --nocapture
   ```

2. **Start gateway with WebSocket config:**
   ```bash
   FERRUM_MODE=file FERRUM_FILE_CONFIG_PATH=tests/config.yaml cargo run --bin ferrum-gateway
   ```

3. **Test WebSocket connections:**
   - Regular WebSocket: `ws://localhost:8000/ws`
   - Secure WebSocket: `wss://localhost:8443/ws` (if TLS configured)

### Test Configuration
The `tests/config.yaml` file contains WebSocket proxy configurations:
- `/ws` → `ws://localhost:8080` (regular WebSocket)
- `/wss` → `wss://localhost:8443` (secure WebSocket)

### TLS Certificates
The `tests/certs/` directory contains self-signed certificates for testing:
- `server.crt` - Server certificate
- `server.key` - Server private key  
- `client.crt` - Client certificate (for mTLS testing)

## 📊 Test Results Summary

### ✅ Always Passing Tests

#### admin_tests.rs (6/6 tests)
- `test_jwt_token_validation` - ✅ JWT token generation and verification
- `test_admin_api_integration` - ✅ Admin API state initialization
- `test_jwt_configuration_validation` - ✅ Multiple JWT configurations
- `test_jwt_security_scenarios` - ✅ Token tampering and cross-issuer attacks
- `test_jwt_performance` - ✅ 100 token operations under 1 second
- `test_jwt_concurrent_access` - ✅ 50 simultaneous token operations

#### stdout_logging_tests.rs (4/4 tests)
- `test_stdout_logging_plugin_creation` - ✅ Plugin instantiation
- `test_stdout_logging_plugin_lifecycle` - ✅ All lifecycle phases
- `test_stdout_logging_plugin_logging` - ✅ Transaction logging
- `test_stdout_logging_plugin_with_config` - ✅ Configuration handling

#### plugin_integration_tests.rs (6/6 tests)
- `test_all_plugins_available` - ✅ All 11 plugins discoverable
- `test_plugin_creation_all_plugins` - ✅ Plugin instantiation
- `test_plugin_scope_configuration` - ✅ Global vs proxy scope
- `test_plugin_error_handling` - ✅ Invalid plugin names
- `test_plugin_configuration_validation` - ✅ Empty config handling
- `test_plugin_complex_configurations` - ✅ Advanced configurations

### ✅ All Plugin Tests Passing

#### key_auth_tests.rs (6/6 tests)
- All tests passing including successful auth and query parameter auth

#### access_control_tests.rs (18/18 tests)
- IP allowlist/blocklist, CIDR ranges (/8, /12, /16, /24, /32), consumer allow/disallow
- Blocked IP precedence over allowed ranges, no-consumer-identified (401)

#### rate_limiting_tests.rs (9/9 tests)
- Consumer and IP-based limiting, window expiry, zero limit, double-count prevention
- Rate limiting applied in `on_request_received` phase only (not `authorize`)

#### jwt_auth_plugin_tests.rs (13/13 tests)
- Bearer/query/custom header token lookup, claim field matching, wrong secret, malformed tokens

#### basic_auth_tests.rs (11/11 tests)
- Success/failure, scheme validation, base64 errors, missing headers, password with colons

#### oauth2_auth_tests.rs (13/13 tests)
- JWKS/introspection modes, issuer/audience validation, consumer matching

#### request_transformer_tests.rs (13/13 tests)
- Add/remove/update headers and query params, multiple rules, edge cases

#### response_transformer_tests.rs (10/10 tests)
- Add/remove/update response headers, multiple rules, various status codes

#### http_logging_tests.rs (6/6 tests)
- Creation, empty URL no-op, unreachable endpoint graceful handling, lifecycle

#### transaction_debugger_tests.rs (9/9 tests)
- Creation, request/response logging, full lifecycle, body logging flags

#### dns_tests.rs (13/13 tests)
- Cache creation, IP resolution, per-proxy/global overrides, TTL, warmup

#### env_config_tests.rs (27/27 tests)
- All 4 operating modes, validation errors, default/custom ports, TLS flags, HTTP/3

## 🛠️ Test Utilities

### Shared Helpers (plugin_utils.rs)

```rust
// Test data creation
create_test_consumer()           // Consumer with all credential types
create_test_context()            // Request context with headers
create_test_proxy()              // Default proxy configuration
create_test_transaction_summary() // Logging test data

// Assertion helpers
assert_continue(result)          // Assert PluginResult::Continue
assert_reject(result, status)    // Assert PluginResult::Reject with status
```

### Admin API Test Helpers (admin_tests.rs)

```rust
// JWT and admin state creation
create_test_jwt_manager()        // JWT manager with test configuration
create_test_admin_state()        // Admin state with JWT manager
generate_test_token()           // Valid JWT token for testing
generate_invalid_token()        // Invalid JWT token (wrong secret)

// Test configuration
TestConfig {                    // Configurable test parameters
    jwt_secret: "test-secret",
    jwt_issuer: "test-issuer", 
    max_ttl: 3600,
    admin_addr: "127.0.0.1:0"
}
```

### Usage Example

#### Plugin Test Example
```rust
use ferrum_gateway::plugins::{MyPlugin, Plugin, PluginResult};
use serde_json::json;

mod plugin_utils;
use plugin_utils::{create_test_context, assert_continue};

#[tokio::test]
async fn test_my_plugin() {
    let config = json!({"setting": "value"});
    let plugin = MyPlugin::new(&config);
    assert_eq!(plugin.name(), "my_plugin");
    
    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert_continue(result);
}
```

#### Admin API Test Example
```rust
use ferrum_gateway::admin::{AdminState, jwt_auth::{JwtManager, JwtConfig}};
use serde_json::json;

#[tokio::test]
async fn test_jwt_authentication() {
    let config = TestConfig::default();
    let jwt_manager = create_test_jwt_manager(&config);
    
    // Test valid token
    let valid_token = generate_test_token(&config, "test-user");
    let result = jwt_manager.verify_token(&valid_token);
    assert!(result.is_ok());
    
    // Test invalid token
    let invalid_token = generate_invalid_token(&config, "test-user");
    let result = jwt_manager.verify_token(&invalid_token);
    assert!(result.is_err());
}
```

## 🧪 Test Categories

### 1. Plugin Tests
- **Creation Tests**: Verify plugins instantiate with various configurations
- **Lifecycle Tests**: Test all plugin phases (request, auth, proxy, response)
- **Configuration Tests**: Test valid, invalid, and edge case configurations
- **Integration Tests**: Cross-plugin functionality and error handling

### 2. Configuration Tests
- **File Loading**: YAML and JSON configuration file parsing
- **Type Validation**: Configuration structure and validation rules
- **Error Handling**: Invalid configuration detection and reporting

### 3. Proxy Tests
- **Route Matching**: Path-based proxy selection
- **URL Building**: Backend URL construction
- **Priority Handling**: Route priority and conflict resolution

### 4. Admin API Tests
- **JWT Authentication**: Token generation, validation, and security
- **Configuration Testing**: Multiple JWT configurations and scenarios
- **Security Validation**: Token tampering, cross-issuer attacks, and edge cases
- **Performance Testing**: Token operation benchmarks and concurrent access
- **Integration Testing**: Admin API state management and initialization

## 🔧 Debugging Failed Tests

### Enable Backtraces
```bash
RUST_BACKTRACE=1 cargo test --test failing_test_file
```

### Run Single Test
```bash
cargo test --test test_file_name test_function_name
```

### Verbose Output
```bash
cargo test --test test_file_name -- --nocapture
```

### Common Debugging Steps

1. **Check Test Data**: Ensure test consumers, contexts, and configurations are valid
2. **Verify Plugin Logic**: Review plugin implementation for expected behavior
3. **Check Assertions**: Make sure expected results match actual plugin behavior
4. **Enable Logging**: Use `--nocapture` to see println! output from tests

## 📈 Test Coverage

### Current Coverage
- **11 Plugins**: All plugins have comprehensive test suites with full lifecycle coverage
- **7 Core Areas**: Logging, Authentication, Authorization, Rate Limiting, DNS, Configuration, Integration
- **150+ Plugin Test Cases**: Comprehensive coverage including edge cases and error handling
- **6 Admin API Tests**: JWT authentication, security, and performance validation
- **27 Environment Config Tests**: All operating modes, validation, defaults
- **13 DNS Tests**: Caching, resolution, overrides, TTL
- **228 Total Test Cases**: Full coverage of gateway functionality (all passing)

### Adding New Tests

1. **Create Test File**: `tests/new_plugin_tests.rs`
2. **Use Standard Template**: Follow existing test patterns
3. **Add Utilities**: Extend `plugin_utils.rs` if needed
4. **Update Documentation**: Add test description to this README

### Test Naming Conventions

```rust
// Plugin tests
test_{plugin_name}_plugin_creation
test_{plugin_name}_plugin_lifecycle
test_{plugin_name}_plugin_with_config

// Admin API tests
test_jwt_token_validation
test_jwt_configuration_validation
test_jwt_security_scenarios
test_jwt_performance
test_jwt_concurrent_access
test_admin_api_integration

// Integration tests
test_all_plugins_available
test_plugin_error_handling
test_plugin_scope_configuration
```

## 🎯 Expected Behaviors

### Plugin Lifecycle
1. **on_request_received** - Called first, should return Continue
2. **authenticate** - Auth plugins validate credentials
3. **authorize** - Authz plugins check permissions
4. **before_proxy** - Transform request before backend call
5. **after_proxy** - Transform response after backend call

### Common Results
- **Continue**: Plugin allows request to proceed
- **Reject { status_code, body }**: Plugin blocks request with HTTP response

### Authentication Flow
- Valid credentials → Continue
- Invalid/missing credentials → Reject (401)
- Configuration errors → Continue (graceful fallback)

### Authorization Flow
- Allowed IP/consumer → Continue  
- Blocked IP/consumer → Reject (403)
- No rules → Continue (default allow)

### JWT Authentication Flow
- Valid token with correct ISS → Continue
- Invalid signature → Reject (401)
- Expired token → Reject (401)
- Wrong issuer → Reject (401)
- Malformed token → Reject (401)
- Missing token → Reject (401)

## 🚨 Troubleshooting

### Test Compilation Errors
- **Missing Imports**: Ensure `Plugin`, `PluginResult` are imported
- **Module Issues**: Check `mod plugin_utils;` declaration
- **Type Mismatches**: Verify plugin method signatures

### Test Runtime Failures
- **Mock Data**: Ensure test data matches plugin expectations
- **Async/Await**: All plugin tests must be `#[tokio::test]`
- **Configuration**: Check JSON config matches plugin schema
- **JWT Tokens**: Ensure test tokens use correct secret and issuer
- **Admin State**: Verify admin state initialization in tests

### Performance Issues
- **Test Isolation**: Each test should be independent
- **Cleanup**: Reset state between tests if needed
- **Timeouts**: Use appropriate test timeouts for async operations

---

## 📝 Contributing

When adding new tests:

1. **Follow Patterns**: Use existing test structure and naming
2. **Add Documentation**: Update this README with new test info
3. **Test Utilities**: Add reusable helpers to `plugin_utils.rs`
4. **Edge Cases**: Consider invalid inputs and error conditions
5. **Integration**: Add integration tests for cross-plugin functionality

This test suite ensures Ferrum Gateway maintains high quality and reliability as it evolves! 🚀
