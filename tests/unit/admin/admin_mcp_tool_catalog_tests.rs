//! `GET /proxies/{id}/mcp/tools` (issue #5926): read an `mcp_gateway` proxy's
//! cached tool catalog without speaking MCP.
//!
//! Each test runs a real admin listener over a data plane that serves the
//! `ferrum` namespace, while the Admin API's configuration also holds a
//! `staging` tenant the data plane does not route. Catalogs are filled the
//! way production fills them: an MCP client initializes a session and lists
//! tools through the running plugin instance.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager, ViewerNamespaceCeiling},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PRIMARY_SECRET: &str = "mcp-tool-catalog-primary-secret-0123456789";
const VIEWER_SECRET: &str = "mcp-tool-catalog-viewer-secret-0123456789a";
const ISSUER: &str = "ferrum-edge-mcp-tool-catalog-test";
const CEILING_REFUSAL: &str = "FERRUM_ADMIN_JWT_VIEWER_NAMESPACES";
/// Rides the upstream URL's path, like a hosted MCP server's ingest token.
const PATH_TOKEN: &str = "ingest-token-must-not-leak";
const AGG: &str = "/proxies/mcp-agg/mcp/tools";
const BRIDGE: &str = "/proxies/mcp-bridge/mcp/tools";
const STAGING: &str = "/proxies/mcp-staging/mcp/tools";
const PLAIN: &str = "/proxies/plain/mcp/tools";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: PRIMARY_SECRET.to_string(),
        issuer: ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    })
    .with_viewer_secret(VIEWER_SECRET.to_string())
    .expect("distinct viewer secret")
}

fn token(secret: &str, role: &str, ns: Option<Value>) -> String {
    let now = Utc::now();
    let mut claims = json!({
        "iss": ISSUER,
        "sub": "foundry",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(ns) = ns {
        claims["ns"] = ns;
    }
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn viewer() -> String {
    token(PRIMARY_SECRET, "viewer", None)
}

fn proxy(id: &str, namespace: &str, listen_path: &str, plugins: &[&str]) -> Value {
    json!({
        "id": id,
        "namespace": namespace,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "allowed_methods": if id == "mcp-bridge" {
            json!(["GET"])
        } else {
            Value::Null
        },
        "plugins": plugins
            .iter()
            .map(|plugin| json!({"plugin_config_id": plugin}))
            .collect::<Vec<_>>(),
    })
}

fn mcp_plugin(id: &str, namespace: &str, proxy_id: &str, config: Value) -> Value {
    json!({
        "id": id,
        "plugin_name": "mcp_gateway",
        "namespace": namespace,
        "scope": "proxy",
        "proxy_id": proxy_id,
        "config": config,
    })
}

/// Two upstream MCP servers: `github` answers `tools/list` behind a URL whose
/// path carries a token, `flaky` fails every list.
fn aggregate_config(github_url: &str, flaky_url: &str) -> Value {
    json!({
        "mode": "aggregate_router",
        "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
        "sessions": {"initialize_upstreams": "passthrough"},
        "discovery": {
            "aggregate_resources": true,
            "aggregate_prompts": false,
            "on_new_tool": "hide_until_configured"
        },
        "validation": {"validate_tool_results": true},
        "servers": {
            "github": {
                "upstream_url": github_url,
                "namespace": "github",
                "expose_resources": true
            },
            "flaky": {"upstream_url": flaky_url, "namespace": "flaky"}
        },
        "policy": {
            "default_action": "deny",
            "tools": {
                "github.create_pr": {
                    "action": "allow",
                    "allowed_groups": ["release-managers", "admins"],
                    "denied_groups": ["contractors"]
                },
                "github.merge_pr": {"action": "deny"}
            }
        }
    })
}

fn bridge_config() -> Value {
    json!({
        "mode": "aggregate_router",
        "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
        "discovery": {"on_new_tool": "allow", "on_schema_change": "allow"},
        "policy": {"default_action": "allow"},
        "servers": {
            "petstore": {
                "namespace": "pets",
                "openapi": {"operations": [
                    {
                        "name": "getPet",
                        "method": "GET",
                        "path": "/pets/{petId}",
                        "title": "Get a pet",
                        "description": "Fetch one pet by id",
                        "parameters": [{
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }]
                    },
                    {
                        "name": "createPet",
                        "method": "POST",
                        "path": "/pets",
                        "request_body": {
                            "required": true,
                            "schema": {
                                "type": "object",
                                "properties": {"name": {"type": "string"}},
                                "required": ["name"]
                            }
                        }
                    },
                    {
                        "name": "deletePet",
                        "method": "DELETE",
                        "path": "/pets/{petId}",
                        "parameters": [{
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }]
                    }
                ]}
            }
        }
    })
}

/// `(runtime config the data plane serves, admin config holding both tenants)`.
fn configs(github_url: &str, flaky_url: &str) -> (GatewayConfig, GatewayConfig) {
    let ferrum_proxies = vec![
        proxy("mcp-agg", "ferrum", "/agg", &["mcp-agg-plugin"]),
        proxy("mcp-bridge", "ferrum", "/bridge", &["mcp-bridge-plugin"]),
        proxy("plain", "ferrum", "/plain", &[]),
    ];
    let ferrum_plugins = vec![
        mcp_plugin(
            "mcp-agg-plugin",
            "ferrum",
            "mcp-agg",
            aggregate_config(github_url, flaky_url),
        ),
        mcp_plugin("mcp-bridge-plugin", "ferrum", "mcp-bridge", bridge_config()),
    ];
    let build = |proxies: Vec<Value>, plugins: Vec<Value>| -> GatewayConfig {
        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": proxies,
            "consumers": [],
            "plugin_configs": plugins,
            "upstreams": []
        }))
        .expect("fixture deserializes");
        config.normalize_fields();
        config
    };
    let runtime = build(ferrum_proxies.clone(), ferrum_plugins.clone());
    let mut all_proxies = ferrum_proxies;
    let staging_proxy = proxy("mcp-staging", "staging", "/agg", &["mcp-staging-plugin"]);
    all_proxies.push(staging_proxy);
    let mut all_plugins = ferrum_plugins;
    all_plugins.push(mcp_plugin(
        "mcp-staging-plugin",
        "staging",
        "mcp-staging",
        bridge_config(),
    ));
    (runtime, build(all_proxies, all_plugins))
}

struct Fixture {
    base: String,
    proxy_state: ProxyState,
    _github: MockServer,
    _flaky: MockServer,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

async fn start_mcp_servers() -> (MockServer, MockServer) {
    let github = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/mcp/{PATH_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": "upstream",
            "result": {"tools": [
                {
                    "name": "create_pr",
                    "description": "Create a pull request",
                    "annotations": {"destructiveHint": false},
                    "inputSchema": {
                        "type": "object",
                        "required": ["repo"],
                        "properties": {"repo": {"type": "string"}}
                    }
                },
                {
                    "name": "merge_pr",
                    "description": "Merge a pull request",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {
                        "type": "object",
                        "properties": {"merged": {"type": "boolean"}}
                    }
                },
                {
                    "name": "hidden_new",
                    "description": "Not configured yet",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {
                        "type": "object",
                        "properties": {"hidden": {"type": "boolean"}}
                    }
                }
            ], "resourceTemplates": [{
                "uriTemplate": "file:///repos/{repo}",
                "name": "repo-file"
            }]}
        })))
        .mount(&github)
        .await;
    let flaky = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&flaky)
        .await;
    (github, flaky)
}

fn admin_state(proxy_state: Option<ProxyState>, cached: GatewayConfig) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(cached)))),
        proxy_state,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

fn proxy_state_for(runtime: GatewayConfig) -> ProxyState {
    let env_config = ferrum_edge::config::EnvConfig {
        mode: OperatingMode::File,
        namespace: "ferrum".to_string(),
        ..Default::default()
    };
    let (state, _health_check_handles) = ProxyState::new(
        runtime,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("ProxyState::new");
    state
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

/// A data plane serving `ferrum`, behind an admin listener whose state is
/// shaped by `configure`.
async fn fixture_with(configure: impl FnOnce(&mut AdminState)) -> Fixture {
    let (github, flaky) = start_mcp_servers().await;
    let (runtime, cached) = configs(
        &format!("{}/mcp/{PATH_TOKEN}", github.uri()),
        &format!("{}/mcp", flaky.uri()),
    );
    let proxy_state = proxy_state_for(runtime);
    let mut state = admin_state(Some(proxy_state.clone()), cached);
    configure(&mut state);
    let (base, shutdown) = start_admin(state).await;
    Fixture {
        base,
        proxy_state,
        _github: github,
        _flaky: flaky,
        _shutdown: shutdown,
    }
}

async fn fixture() -> Fixture {
    fixture_with(|_| {}).await
}

struct Reply {
    status: u16,
    data_source: Option<String>,
    body: Value,
    text: String,
}

async fn get(base: &str, path: &str, bearer: Option<&str>, namespace: Option<&str>) -> Reply {
    let mut req = reqwest::Client::new().get(format!("{base}{path}"));
    if let Some(bearer) = bearer {
        req = req.bearer_auth(bearer);
    }
    if let Some(namespace) = namespace {
        req = req.header("X-Ferrum-Namespace", namespace);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let data_source = resp
        .headers()
        .get("x-data-source")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let text = resp.text().await.unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Reply {
        status,
        data_source,
        body,
        text,
    }
}

fn mcp_request(body: Value, session: Option<&str>) -> (RequestContext, HashMap<String, String>) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/mcp".to_string(),
    );
    let bytes = serde_json::to_vec(&body).unwrap();
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(bytes.clone()).unwrap(),
    );
    ctx.request_body_bytes = Some(bytes::Bytes::from(bytes));
    let mut headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    if let Some(session) = session {
        headers.insert("mcp-session-id".to_string(), session.to_string());
    }
    (ctx, headers)
}

/// Initialize an MCP session on the proxy's running `mcp_gateway` and list
/// tools once, which refreshes that session's catalog.
async fn refresh_catalog(proxy_state: &ProxyState, proxy_id: &str) -> String {
    let plugins = proxy_state
        .plugin_cache
        .request_view("ferrum", proxy_id, ProxyProtocol::Http)
        .plugins();
    let plugin: &Arc<dyn Plugin> = plugins
        .iter()
        .find(|plugin| plugin.name() == "mcp_gateway")
        .expect("the proxy runs an mcp_gateway");
    let (mut ctx, mut headers) = mcp_request(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "catalog-test", "version": "1"}
            }
        }),
        None,
    );
    let session = match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code: 200,
            headers,
            ..
        } => headers
            .get("mcp-session-id")
            .cloned()
            .expect("initialize mints a session"),
        other => panic!("initialize must be answered by the gateway: {other:?}"),
    };
    let (mut ctx, mut headers) = mcp_request(
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        Some(&session),
    );
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code: 200, ..
        } => {}
        other => panic!("tools/list must be answered by the gateway: {other:?}"),
    }
    session
}

async fn refresh_resource_templates(proxy_state: &ProxyState, proxy_id: &str, session: &str) {
    let plugins = proxy_state
        .plugin_cache
        .request_view("ferrum", proxy_id, ProxyProtocol::Http)
        .plugins();
    let plugin: &Arc<dyn Plugin> = plugins
        .iter()
        .find(|plugin| plugin.name() == "mcp_gateway")
        .expect("the proxy runs an mcp_gateway");
    let (mut ctx, mut headers) = mcp_request(
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/templates/list",
            "params": {}
        }),
        Some(session),
    );
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code: 200, ..
        } => {}
        other => panic!("resources/templates/list must be answered by the gateway: {other:?}"),
    }
}

fn tool<'a>(reply: &'a Reply, name: &str) -> &'a Value {
    reply.body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap_or_else(|| panic!("tool {name} is listed: {}", reply.text))
}

fn tool_names(reply: &Reply) -> Vec<String> {
    reply.body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect()
}

fn server<'a>(catalog: &'a Value, server_id: &str) -> &'a Value {
    catalog["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .find(|server| server["server_id"] == server_id)
        .unwrap_or_else(|| panic!("server {server_id} is reported: {catalog}"))
}

fn is_sha256_hex(value: &Value) -> bool {
    value.as_str().is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[tokio::test]
async fn catalog_not_yet_refreshed_is_empty_and_stale() {
    let fixture = fixture().await;
    let reply = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.body["proxy_id"], "mcp-agg");
    assert_eq!(reply.body["namespace"], "ferrum");
    assert_eq!(reply.body["data"], json!([]));
    assert_eq!(reply.body["pagination"]["total"], 0);
    assert_eq!(reply.body["refreshed_at"], Value::Null);
    assert_eq!(reply.body["stale"], true);
    let catalog = &reply.body["catalogs"][0];
    assert_eq!(catalog["plugin_config_id"], "mcp-agg-plugin");
    assert_eq!(catalog["catalog_state"], "not_refreshed");
    assert_eq!(catalog["refreshed_at"], Value::Null);
    assert_eq!(catalog["stale"], true);
    assert_eq!(catalog["cached_sessions"], 0);
    assert_eq!(catalog["discovery"]["on_new_tool"], "hide_until_configured");
    assert_eq!(server(catalog, "github")["tools_refresh"], "pending");
    assert_eq!(server(catalog, "flaky")["tools_refresh"], "pending");
}

#[tokio::test]
async fn aggregate_catalog_reports_upstream_sources_policy_grants_and_refresh_errors() {
    let fixture = fixture().await;
    refresh_catalog(&fixture.proxy_state, "mcp-agg").await;

    let reply = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.data_source.as_deref(), Some("cached"));
    assert_eq!(
        tool_names(&reply),
        vec!["github.create_pr", "github.hidden_new", "github.merge_pr"]
    );
    assert_eq!(reply.body["stale"], false);
    assert!(reply.body["refreshed_at"].is_string(), "{}", reply.text);

    let create = tool(&reply, "github.create_pr");
    assert_eq!(create["plugin_config_id"], "mcp-agg-plugin");
    assert_eq!(
        create["source"],
        json!({
            "type": "upstream",
            "server_id": "github",
            "namespace": "github",
            "upstream_name": "create_pr"
        })
    );
    assert_eq!(create["description"], "Create a pull request");
    assert_eq!(create["annotations"], json!({"destructiveHint": false}));
    assert_eq!(
        create["policy"],
        json!({
            "action": "allow",
            "configured": true,
            "effective": "allow",
            "listed": true,
            "callable": true
        })
    );
    assert_eq!(
        create["allowed_groups"],
        json!(["admins", "release-managers"])
    );
    assert_eq!(create["denied_groups"], json!(["contractors"]));
    assert!(is_sha256_hex(&create["schema_hash"]), "{create}");

    let merge = tool(&reply, "github.merge_pr");
    assert_eq!(merge["policy"]["action"], "deny");
    assert_eq!(merge["policy"]["effective"], "deny");
    assert_eq!(merge["policy"]["listed"], false);
    assert_eq!(merge["policy"]["callable"], false);
    assert_eq!(merge["allowed_groups"], Value::Null);
    assert_eq!(merge["denied_groups"], json!([]));

    // `on_new_tool: hide_until_configured` keeps an unconfigured tool hidden.
    let hidden = tool(&reply, "github.hidden_new");
    assert_eq!(hidden["policy"]["configured"], false);
    assert_eq!(hidden["policy"]["action"], "deny");
    assert_eq!(hidden["policy"]["effective"], "hidden_until_configured");
    assert_eq!(hidden["policy"]["listed"], false);

    // Result validation makes the stored hash cover both schemas, even though
    // these tools have identical input schemas.
    assert_ne!(merge["schema_hash"], hidden["schema_hash"]);
    assert_ne!(create["schema_hash"], merge["schema_hash"]);

    let catalog = &reply.body["catalogs"][0];
    assert_eq!(catalog["catalog_state"], "fresh");
    assert_eq!(catalog["mode"], "aggregate_router");
    assert_eq!(catalog["cached_sessions"], 1);
    assert_eq!(catalog["tool_count"], 3);
    assert_eq!(catalog["tools_unavailable"], false);
    assert_eq!(catalog["policy"]["default_action"], "deny");
    assert_eq!(catalog["limits"]["max_catalog_items_per_list"], 10_000);
    let github = server(catalog, "github");
    assert_eq!(github["kind"], "mcp");
    assert_eq!(github["tools_refresh"], "ok");
    assert_eq!(github["refresh_error"], Value::Null);
    let flaky = server(catalog, "flaky");
    assert_eq!(flaky["tools_refresh"], "failed");
    assert!(flaky["refresh_error"].is_string(), "{catalog}");
}

#[tokio::test]
async fn upstream_urls_are_structurally_redacted_for_every_role() {
    let fixture = fixture().await;
    refresh_catalog(&fixture.proxy_state, "mcp-agg").await;
    for role in ["viewer", "operator", "admin"] {
        let bearer = token(PRIMARY_SECRET, role, None);
        let reply = get(&fixture.base, AGG, Some(&bearer), None).await;
        assert_eq!(reply.status, 200, "{role}: {}", reply.text);
        assert!(
            !reply.text.contains(PATH_TOKEN),
            "{role} read disclosed the upstream path token: {}",
            reply.text
        );
        let url = server(&reply.body["catalogs"][0], "github")["upstream_url"]
            .as_str()
            .expect("an MCP server reports its projected URL")
            .to_string();
        assert!(url.starts_with("http://127.0.0.1:"), "{url}");
        assert!(url.ends_with("/[REDACTED_PATH]"), "{url}");
    }
}

#[test]
fn endpoint_url_projection_masks_userinfo_path_query_and_fragment() {
    // The catalog read uses the plugin-config endpoint projection. Admission
    // refuses userinfo in `upstream_url`, so the projection is pinned directly.
    let projected = ferrum_edge::admin::plugin_config_projection::redact_endpoint_url(
        "https://agent:hunter2@mcp.example.com:8443/v1/sk-live?key=abc#frag",
    );
    assert_eq!(
        projected,
        "https://redacted@mcp.example.com:8443/[REDACTED_PATH]?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    for secret in ["agent", "hunter2", "sk-live", "abc", "frag"] {
        assert!(!projected.contains(secret), "{projected}");
    }
}

#[tokio::test]
async fn bridge_catalog_reports_openapi_operations_and_paginates() {
    let fixture = fixture().await;
    refresh_catalog(&fixture.proxy_state, "mcp-bridge").await;

    let reply = get(&fixture.base, BRIDGE, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        tool_names(&reply),
        vec!["pets.createPet", "pets.deletePet", "pets.getPet"]
    );
    let get_pet = tool(&reply, "pets.getPet");
    assert_eq!(
        get_pet["source"],
        json!({
            "type": "openapi",
            "server_id": "petstore",
            "namespace": "pets",
            "operation_name": "getPet",
            "method": "GET",
            "path": "/pets/{petId}"
        })
    );
    assert_eq!(get_pet["title"], "Get a pet");
    assert_eq!(get_pet["annotations"]["readOnlyHint"], true);
    assert_eq!(get_pet["policy"]["effective"], "allow");
    assert_eq!(get_pet["policy"]["callable"], true);
    let create_pet = tool(&reply, "pets.createPet");
    assert_eq!(create_pet["policy"]["listed"], false);
    assert_eq!(create_pet["policy"]["callable"], false);
    assert_eq!(tool(&reply, "pets.createPet")["source"]["method"], "POST");
    assert_eq!(tool(&reply, "pets.createPet")["source"]["path"], "/pets");
    let catalog = &reply.body["catalogs"][0];
    let petstore = server(catalog, "petstore");
    assert_eq!(petstore["kind"], "openapi");
    assert_eq!(petstore["upstream_url"], Value::Null);
    assert_eq!(petstore["tools_refresh"], "ok");

    let first = get(
        &fixture.base,
        "/proxies/mcp-bridge/mcp/tools?limit=2",
        Some(&viewer()),
        None,
    )
    .await;
    assert_eq!(tool_names(&first), vec!["pets.createPet", "pets.deletePet"]);
    assert_eq!(
        first.body["pagination"],
        json!({"offset": 0, "limit": 2, "total": 3})
    );
    let second = get(
        &fixture.base,
        "/proxies/mcp-bridge/mcp/tools?limit=2&offset=2",
        Some(&viewer()),
        None,
    )
    .await;
    assert_eq!(tool_names(&second), vec!["pets.getPet"]);
    let malformed = get(
        &fixture.base,
        "/proxies/mcp-bridge/mcp/tools?limit=abc",
        Some(&viewer()),
        None,
    )
    .await;
    assert_eq!(malformed.status, 400, "{}", malformed.text);
}

#[tokio::test]
async fn resource_template_refresh_does_not_change_tool_catalog_refreshed_at() {
    let fixture = fixture().await;
    let session = refresh_catalog(&fixture.proxy_state, "mcp-agg").await;
    let before = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(before.status, 200, "{}", before.text);
    let refreshed_at = before.body["catalogs"][0]["refreshed_at"].clone();
    assert!(refreshed_at.is_string());

    refresh_resource_templates(&fixture.proxy_state, "mcp-agg", &session).await;

    let after = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(after.status, 200, "{}", after.text);
    assert_eq!(after.body["catalogs"][0]["refreshed_at"], refreshed_at);
    assert_eq!(after.body["catalogs"][0]["stale"], false);
    assert_eq!(after.body["stale"], false);
}

#[tokio::test]
async fn every_admin_role_reads_the_catalog_and_anonymous_callers_do_not() {
    let fixture = fixture().await;
    for role in ["viewer", "operator", "admin"] {
        let bearer = token(PRIMARY_SECRET, role, None);
        let reply = get(&fixture.base, BRIDGE, Some(&bearer), None).await;
        assert_eq!(reply.status, 200, "{role}: {}", reply.text);
    }
    // A viewer-secret token is capped at viewer, which is enough to read.
    let viewer_key = token(VIEWER_SECRET, "admin", None);
    let reply = get(&fixture.base, BRIDGE, Some(&viewer_key), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);

    let reply = get(&fixture.base, BRIDGE, None, None).await;
    assert_eq!(reply.status, 401, "{}", reply.text);
}

#[tokio::test]
async fn proxies_without_an_mcp_gateway_or_outside_the_namespace_are_not_found() {
    let fixture = fixture().await;
    let reply = get(&fixture.base, PLAIN, Some(&viewer()), None).await;
    assert_eq!(reply.status, 404, "{}", reply.text);
    assert_eq!(
        reply.body,
        json!({"error": "Proxy has no mcp_gateway plugin"})
    );

    let reply = get(
        &fixture.base,
        "/proxies/missing/mcp/tools",
        Some(&viewer()),
        None,
    )
    .await;
    assert_eq!(reply.status, 404, "{}", reply.text);
    assert_eq!(reply.body, json!({"error": "Proxy not found"}));

    // Another namespace's proxy is not found here, exactly as `GET /proxies/{id}`.
    let reply = get(&fixture.base, STAGING, Some(&viewer()), None).await;
    assert_eq!(reply.status, 404, "{}", reply.text);
    let plain_read = get(&fixture.base, "/proxies/mcp-staging", Some(&viewer()), None).await;
    assert_eq!(plain_read.status, 404, "{}", plain_read.text);
    let reply = get(&fixture.base, AGG, Some(&viewer()), Some("staging")).await;
    assert_eq!(reply.status, 404, "{}", reply.text);

    let reply = get(
        &fixture.base,
        "/proxies/bad%20id/mcp/tools",
        Some(&viewer()),
        None,
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.text);
}

#[tokio::test]
async fn cached_fallback_misses_after_a_store_failure_are_not_authoritative() {
    // Issue #6143: with the store failing, the cached snapshot may predate the
    // proxy or its gateway, so a miss is a stale 503, never the 404 answer.
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("closed.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let db = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("connect test store");
    db.pool().close().await;
    let fixture = fixture_with(|state| {
        state.db = Some(Arc::new(db));
        state.mode = "database".to_string();
    })
    .await;

    for path in ["/proxies/missing/mcp/tools", PLAIN] {
        let reply = get(&fixture.base, path, Some(&viewer()), None).await;
        assert_eq!(reply.status, 503, "{path}: {}", reply.text);
        assert_eq!(
            reply.body,
            json!({"error": ferrum_edge::admin::CACHED_FALLBACK_MISS_MESSAGE}),
            "{path}"
        );
        assert_eq!(reply.data_source.as_deref(), Some("cached"), "{path}");
    }

    // A cached hit is still served, marked stale.
    let reply = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.data_source.as_deref(), Some("cached"));
}

#[tokio::test]
async fn a_proxy_this_data_plane_does_not_serve_reports_not_served() {
    let fixture = fixture().await;
    let reply = get(&fixture.base, STAGING, Some(&viewer()), Some("staging")).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.body["data"], json!([]));
    assert_eq!(reply.body["refreshed_at"], Value::Null);
    assert_eq!(reply.body["stale"], true);
    assert_eq!(reply.body["catalogs"][0]["catalog_state"], "not_served");

    // No data plane at all (a control plane): every catalog is not served.
    let (github, flaky) = start_mcp_servers().await;
    let (_, cached) = configs(&github.uri(), &flaky.uri());
    let (base, _shutdown) = start_admin(admin_state(None, cached)).await;
    let reply = get(&base, BRIDGE, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.body["catalogs"][0]["catalog_state"], "not_served");
}

#[tokio::test]
async fn viewer_namespace_ceiling_bounds_the_catalog_read() {
    let fixture = fixture_with(|state| {
        let ceiling = ViewerNamespaceCeiling::parse("staging").expect("valid ceiling");
        state.jwt_manager = jwt_manager().with_viewer_namespace_ceiling(ceiling);
    })
    .await;
    refresh_catalog(&fixture.proxy_state, "mcp-agg").await;

    let capped = token(VIEWER_SECRET, "viewer", Some(json!(["ferrum", "staging"])));
    for namespace in [None, Some("ferrum")] {
        let reply = get(&fixture.base, AGG, Some(&capped), namespace).await;
        assert_eq!(reply.status, 403, "{namespace:?}: {}", reply.text);
        assert!(reply.text.contains(CEILING_REFUSAL), "{}", reply.text);
        assert!(!reply.text.contains("github"), "{}", reply.text);
    }
    let reply = get(&fixture.base, STAGING, Some(&capped), Some("staging")).await;
    assert_eq!(reply.status, 200, "{}", reply.text);

    // Primary-key tokens are never bound by the viewer-key ceiling.
    let reply = get(&fixture.base, AGG, Some(&viewer()), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
}

#[tokio::test]
async fn namespace_claim_enforcement_applies_to_the_catalog_read() {
    let fixture = fixture_with(|state| state.admin_require_namespace_claim = true).await;
    let staging_only = token(PRIMARY_SECRET, "viewer", Some(json!("staging")));
    let reply = get(&fixture.base, AGG, Some(&staging_only), Some("ferrum")).await;
    assert_eq!(reply.status, 403, "{}", reply.text);
    let ferrum = token(PRIMARY_SECRET, "viewer", Some(json!("ferrum")));
    let reply = get(&fixture.base, AGG, Some(&ferrum), None).await;
    assert_eq!(reply.status, 200, "{}", reply.text);
}
