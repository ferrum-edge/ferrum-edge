//! `x-ferrum-mcp` generation (issue #5906): an OpenAPI 3.x document's
//! operations become a proxy-scoped `mcp_gateway` OpenAPI bridge server.

use ferrum_edge::admin::api_specs::{ExtractError, SpecFormat, extract};
use ferrum_edge::config::types::{PluginConfig, PluginScope};
use ferrum_edge::plugins::create_plugin;
use serde_json::{Value, json};

fn spec(extension: Value, paths: Value) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": { "title": "Pets API", "version": "1.0.0" },
        "servers": [{ "url": "https://pets.example.com/v1" }],
        "x-ferrum-mcp": extension,
        "x-ferrum-proxy": {
            "id": "pets-proxy",
            "listen_path": "/pets-api",
            "backend_host": "pets.internal",
            "backend_port": 8080
        },
        "components": {
            "parameters": {
                "PetId": {
                    "name": "petId",
                    "in": "path",
                    "required": true,
                    "schema": { "$ref": "#/components/schemas/Id" }
                }
            },
            "schemas": {
                "Id": { "type": "string", "minLength": 1 },
                "Pet": {
                    "type": "object",
                    "required": ["name"],
                    "properties": { "name": { "type": "string" } }
                }
            }
        },
        "paths": paths
    })
}

fn pet_paths() -> Value {
    json!({
        "/pets/{petId}": {
            "parameters": [{ "$ref": "#/components/parameters/PetId" }],
            "get": {
                "operationId": "getPet",
                "summary": "Get a pet",
                "tags": ["read"],
                "parameters": [
                    { "name": "verbose", "in": "query", "schema": { "type": "boolean" } },
                    { "name": "X-Trace-Tag", "in": "header", "schema": { "type": "string" } }
                ],
                "responses": {
                    "200": {
                        "description": "the pet",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/Pet" }
                            }
                        }
                    }
                }
            },
            "delete": {
                "operationId": "deletePet",
                "tags": ["write"],
                "responses": { "204": { "description": "deleted" } }
            },
            "head": {
                "operationId": "headPet",
                "responses": { "200": { "description": "exists" } }
            }
        },
        "/pets": {
            "post": {
                "operationId": "create pet!",
                "tags": ["write"],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } }
                    }
                },
                "responses": { "201": { "description": "created" } }
            }
        }
    })
}

fn extract_value(document: &Value) -> Result<Vec<PluginConfig>, ExtractError> {
    let body = serde_json::to_vec(document).unwrap();
    extract(&body, Some(SpecFormat::Json), "prod").map(|(bundle, _)| bundle.plugins)
}

fn generated_gateway(document: &Value) -> Value {
    let plugins = extract_value(document).expect("spec extraction must succeed");
    let plugin = plugins
        .iter()
        .find(|plugin| plugin.plugin_name == "mcp_gateway")
        .expect("a generated mcp_gateway plugin");
    assert_eq!(plugin.scope, PluginScope::Proxy);
    assert_eq!(plugin.proxy_id.as_deref(), Some("pets-proxy"));
    let fields = plugin.validate_fields();
    assert!(fields.is_ok(), "{fields:?}");
    plugin.config.clone()
}

fn has_gateway(plugins: &[PluginConfig]) -> bool {
    plugins.iter().any(|p| p.plugin_name == "mcp_gateway")
}

fn extract_error(document: &Value) -> String {
    match extract_value(document) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("spec extraction must fail"),
    }
}

fn operation<'a>(config: &'a Value, name: &str) -> &'a Value {
    config["servers"]["openapi"]["openapi"]["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .find(|operation| operation["name"] == name)
        .unwrap_or_else(|| panic!("no generated operation {name}: {config}"))
}

fn operation_names(config: &Value) -> Vec<String> {
    let mut names: Vec<String> = config["servers"]["openapi"]["openapi"]["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .map(|operation| operation["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

#[test]
fn x_ferrum_mcp_generates_a_constructible_proxy_scoped_gateway() {
    let config = generated_gateway(&spec(json!({ "namespace": "pets" }), pet_paths()));
    assert_eq!(config["mode"], "aggregate_router");
    assert_eq!(config["endpoint"]["path"], "/pets-api/mcp");
    assert_eq!(config["servers"]["openapi"]["namespace"], "pets");
    assert!(config["servers"]["openapi"].get("upstream_url").is_none());
    // HEAD is not bridged; the invalid operationId is sanitized.
    assert_eq!(
        operation_names(&config),
        vec!["create_pet", "deletePet", "getPet"]
    );

    let get = operation(&config, "getPet");
    assert_eq!(get["method"], "GET");
    // Listen prefix + first server pathname + Paths key. The server URL's
    // scheme and host never enter the generated config.
    assert_eq!(get["path"], "/pets-api/v1/pets/{petId}");
    assert!(!config.to_string().contains("pets.example.com"));
    assert_eq!(get["title"], "Get a pet");
    let parameters = get["parameters"].as_array().unwrap();
    let path_parameter = parameters
        .iter()
        .find(|parameter| parameter["name"] == "petId")
        .expect("the Path Item parameter is inherited");
    assert_eq!(path_parameter["in"], "path");
    assert_eq!(path_parameter["required"], json!(true));
    let expected = json!({ "type": "string", "minLength": 1 });
    assert_eq!(path_parameter["schema"], expected);
    assert_eq!(get["output_schema"]["type"], "object");
    assert_eq!(get["output_schema"]["required"], json!(["name"]));

    let create = operation(&config, "create_pet");
    assert_eq!(create["method"], "POST");
    assert_eq!(create["request_body"]["required"], json!(true));
    let body_schema = &create["request_body"]["schema"];
    assert_eq!(body_schema["required"], json!(["name"]));
    assert!(create.get("output_schema").is_none());

    let plugin = create_plugin("mcp_gateway", &config).unwrap();
    assert!(plugin.is_some(), "the generated config must construct");
}

#[test]
fn x_ferrum_mcp_selection_honours_include_exclude_and_operation_overrides() {
    let extension = json!({
        "include": { "tags": ["write"] },
        "exclude": { "operations": ["deletePet"] }
    });
    let config = generated_gateway(&spec(extension, pet_paths()));
    assert_eq!(operation_names(&config), vec!["create_pet"]);

    let mut paths = pet_paths();
    paths["/pets/{petId}"]["get"]["x-ferrum-mcp"] = json!({
        "name": "fetch_pet",
        "description": "Fetch one pet",
        "annotations": { "openWorldHint": false }
    });
    paths["/pets/{petId}"]["delete"]["x-ferrum-mcp"] = json!(false);
    let config = generated_gateway(&spec(json!(true), paths));
    assert_eq!(operation_names(&config), vec!["create_pet", "fetch_pet"]);
    let fetch = operation(&config, "fetch_pet");
    assert_eq!(fetch["description"], "Fetch one pet");
    assert_eq!(fetch["annotations"], json!({ "openWorldHint": false }));

    // An explicit per-operation expose wins over document selection.
    let mut paths = pet_paths();
    paths["/pets/{petId}"]["delete"]["x-ferrum-mcp"] = json!({ "expose": true });
    let extension = json!({ "include": { "operations": ["getPet"] } });
    let config = generated_gateway(&spec(extension, paths));
    assert_eq!(operation_names(&config), vec!["deletePet", "getPet"]);
}

#[test]
fn x_ferrum_mcp_refuses_reserved_header_parameters_at_generation() {
    for name in [
        "Authorization",
        "cookie",
        "Host",
        "X-Forwarded-For",
        "x_consumer_role",
        "Mcp-Session-Id",
    ] {
        let mut paths = pet_paths();
        paths["/pets/{petId}"]["get"]["parameters"][1]["name"] = json!(name);
        let error = extract_error(&spec(json!(true), paths));
        assert!(error.contains("reserved request header"), "{name}: {error}");
        assert!(error.contains("x-ferrum-mcp"), "{name}: {error}");
    }
    // Excluding the operation is the documented way to proceed.
    let mut paths = pet_paths();
    paths["/pets/{petId}"]["get"]["parameters"][1]["name"] = json!("Authorization");
    paths["/pets/{petId}"]["get"]["x-ferrum-mcp"] = json!(false);
    let config = generated_gateway(&spec(json!(true), paths));
    assert_eq!(operation_names(&config), vec!["create_pet", "deletePet"]);
}

#[test]
fn x_ferrum_mcp_refuses_unserializable_operations_with_clear_errors() {
    let cases: Vec<(&str, Value)> = vec![
        (
            "serializes only path, query, and header",
            json!({ "name": "session", "in": "cookie", "schema": { "type": "string" } }),
        ),
        (
            "uses `content`",
            json!({ "name": "filter", "in": "query", "content": { "application/json": {} } }),
        ),
        (
            "non-default `style`",
            json!({
                "name": "ids",
                "in": "query",
                "style": "pipeDelimited",
                "schema": { "type": "array" }
            }),
        ),
        (
            "`explode: false`",
            json!({
                "name": "ids",
                "in": "query",
                "explode": false,
                "schema": { "type": "array" }
            }),
        ),
        ("has no `schema`", json!({ "name": "q", "in": "query" })),
    ];
    for (needle, parameter) in cases {
        let mut paths = pet_paths();
        paths["/pets/{petId}"]["get"]["parameters"][1] = parameter;
        let error = extract_error(&spec(json!(true), paths));
        assert!(error.contains(needle), "{needle}: {error}");
    }

    let mut paths = pet_paths();
    paths["/pets"]["post"]["requestBody"]["content"] =
        json!({ "application/xml": { "schema": { "type": "object" } } });
    let error = extract_error(&spec(json!(true), paths));
    assert!(error.contains("sends JSON bodies only"), "{error}");

    let mut paths = pet_paths();
    paths["/pets/{petId}"]["head"]["x-ferrum-mcp"] = json!(true);
    let error = extract_error(&spec(json!(true), paths));
    assert!(
        error.contains("only GET, POST, PUT, PATCH, and DELETE"),
        "{error}"
    );

    let mut paths = pet_paths();
    paths["/pets"]["post"]["x-ferrum-mcp"] = json!({ "name": "getPet" });
    let error = extract_error(&spec(json!(true), paths));
    assert!(error.contains("another operation already uses"), "{error}");
}

#[test]
fn x_ferrum_mcp_extension_is_closed_and_validated() {
    let error = extract_error(&spec(json!({ "namespcae": "pets" }), pet_paths()));
    assert!(error.contains("unknown configuration key"), "{error}");
    assert!(
        error.contains("namespace"),
        "a spelling suggestion: {error}"
    );

    let error = extract_error(&spec(json!({ "namespace": "pets.v1" }), pet_paths()));
    assert!(error.contains("`x-ferrum-mcp.namespace`"), "{error}");

    let error = extract_error(&spec(json!("yes"), pet_paths()));
    assert!(
        error.contains("expected true, false, or an object"),
        "{error}"
    );

    let extension = json!({ "endpoint": { "path": "/elsewhere/mcp" } });
    let error = extract_error(&spec(extension, pet_paths()));
    assert!(error.contains("under the proxy's `listen_path`"), "{error}");

    let extension = json!({ "include": { "operations": ["missing"] } });
    let error = extract_error(&spec(extension, pet_paths()));
    assert!(
        error.contains("selected no bridgeable operations"),
        "{error}"
    );
}

#[test]
fn x_ferrum_mcp_absent_or_disabled_generates_nothing() {
    for extension in [json!(false), Value::Null, json!({ "enabled": false })] {
        let plugins = extract_value(&spec(extension, pet_paths())).unwrap();
        assert!(!has_gateway(&plugins));
    }
}

#[test]
fn x_ferrum_mcp_refuses_swagger_2_and_x_ferrum_validate_composition() {
    let mut document = spec(json!(true), pet_paths());
    document["x-ferrum-validate"] = json!(true);
    let error = extract_error(&document);
    assert!(
        error.contains("cannot be combined with `x-ferrum-validate`"),
        "{error}"
    );

    let swagger = json!({
        "swagger": "2.0",
        "info": { "title": "Legacy", "version": "1" },
        "x-ferrum-mcp": true,
        "x-ferrum-proxy": {
            "id": "legacy",
            "listen_path": "/legacy",
            "backend_host": "legacy.internal",
            "backend_port": 8080
        },
        "paths": { "/items": { "get": { "responses": { "200": { "description": "ok" } } } } }
    });
    let error = extract_error(&swagger);
    assert!(error.contains("OpenAPI 3.x"), "{error}");
}

#[test]
fn x_ferrum_mcp_merges_into_an_embedded_mcp_gateway() {
    let mut document = spec(json!({ "namespace": "pets" }), pet_paths());
    document["x-ferrum-plugins"] = json!([{
        "id": "pets-mcp",
        "plugin_name": "mcp_gateway",
        "config": {
            "mode": "aggregate_router",
            "policy": {
                "default_action": "deny",
                "tools": {
                    "pets.getPet": { "action": "allow", "allowed_groups": ["pet-readers"] }
                }
            }
        }
    }]);
    let plugins = extract_value(&document).unwrap();
    let gateways: Vec<_> = plugins
        .iter()
        .filter(|plugin| plugin.plugin_name == "mcp_gateway")
        .collect();
    assert_eq!(gateways.len(), 1, "merged, not duplicated");
    let config = &gateways[0].config;
    assert_eq!(gateways[0].id, "pets-mcp");
    assert_eq!(config["policy"]["default_action"], "deny");
    assert_eq!(config["endpoint"]["path"], "/pets-api/mcp");
    assert!(config["servers"]["openapi"]["openapi"]["operations"].is_array());
    assert!(create_plugin("mcp_gateway", config).unwrap().is_some());

    document["x-ferrum-plugins"][0]["config"]["servers"] = json!({
        "openapi": { "upstream_url": "http://mcp.internal/mcp", "namespace": "other" }
    });
    let error = extract_error(&document);
    assert!(error.contains("reserved"), "{error}");

    document["x-ferrum-plugins"][0]["config"] = json!({ "mode": "transparent_proxy" });
    let error = extract_error(&document);
    assert!(error.contains("`aggregate_router`"), "{error}");
}
