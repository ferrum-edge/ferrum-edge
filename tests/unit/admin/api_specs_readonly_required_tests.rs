//! OpenAPI 3.0 / Swagger 2.0 readOnly and writeOnly required-direction tests.
//!
//! Covers issue #2582: the API-spec importer must apply direction-specific
//! `required` semantics when generating `openapi_validator` operations.

use ferrum_edge::admin::api_specs::{SpecFormat, extract};
use serde_json::{Value, json};

fn direction_proxy() -> &'static str {
    r#"{
    "id": "direction-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn first_operation(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    assert_eq!(bundle.plugins.len(), 1);
    assert_eq!(bundle.plugins[0].plugin_name, "openapi_validator");
    bundle.plugins[0].config["operations"][0].clone()
}

#[test]
fn openapi_30_drops_readonly_required_on_request_and_writeonly_on_response() {
    let spec = format!(
        r##"{{
  "openapi": "3.0.3",
  "info": {{"title": "Direction API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "Shared": {{
        "type": "object",
        "required": ["id", "secret", "name"],
        "properties": {{
          "id": {{"type": "string", "readOnly": true}},
          "secret": {{"type": "string", "writeOnly": true}},
          "name": {{"type": "string"}},
          "nested": {{
            "type": "object",
            "required": ["token", "label"],
            "properties": {{
              "token": {{"type": "string", "writeOnly": true}},
              "label": {{"type": "string"}}
            }}
          }},
          "items": {{
            "type": "array",
            "items": {{
              "type": "object",
              "required": ["code", "password"],
              "properties": {{
                "code": {{"type": "string", "readOnly": true}},
                "password": {{"type": "string", "writeOnly": true}}
              }}
            }}
          }}
        }},
        "allOf": [
          {{
            "type": "object",
            "required": ["auditId", "payload"],
            "properties": {{
              "auditId": {{"type": "string", "readOnly": true}},
              "payload": {{"type": "string", "writeOnly": true}}
            }}
          }}
        ],
        "oneOf": [
          {{
            "type": "object",
            "required": ["kind", "password"],
            "properties": {{
              "kind": {{"type": "string"}},
              "password": {{"type": "string", "writeOnly": true}}
            }}
          }}
        ],
        "anyOf": [
          {{
            "type": "object",
            "required": ["marker", "etag"],
            "properties": {{
              "marker": {{"type": "string"}},
              "etag": {{"type": "string", "readOnly": true}}
            }}
          }}
        ]
      }}
    }}
  }},
  "paths": {{
    "/items": {{
      "post": {{
        "requestBody": {{
          "required": true,
          "content": {{
            "application/json": {{
              "schema": {{"$ref": "#/components/schemas/Shared"}}
            }}
          }}
        }},
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{"$ref": "#/components/schemas/Shared"}}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"##,
        proxy = direction_proxy()
    );

    let operation = first_operation(&spec);
    let request = &operation["request_body"]["content"]["application/json"];
    let response = &operation["responses"]["200"]["application/json"];

    assert_eq!(request["required"], json!(["secret", "name"]));
    assert_eq!(response["required"], json!(["id", "name"]));
    assert_eq!(
        request["properties"]["nested"]["required"],
        json!(["token", "label"])
    );
    assert_eq!(response["properties"]["nested"]["required"], json!(["label"]));
    assert_eq!(
        request["properties"]["items"]["items"]["required"],
        json!(["password"])
    );
    assert_eq!(
        response["properties"]["items"]["items"]["required"],
        json!(["code"])
    );
    assert_eq!(request["allOf"][0]["required"], json!(["payload"]));
    assert_eq!(response["allOf"][0]["required"], json!(["auditId"]));
    assert_eq!(request["oneOf"][0]["required"], json!(["kind", "password"]));
    assert_eq!(response["oneOf"][0]["required"], json!(["kind"]));
    assert_eq!(request["anyOf"][0]["required"], json!(["marker"]));
    assert_eq!(
        response["anyOf"][0]["required"],
        json!(["marker", "etag"])
    );
    assert_eq!(request["properties"]["id"]["readOnly"], json!(true));
    assert_eq!(response["properties"]["secret"]["writeOnly"], json!(true));
}

#[test]
fn openapi_31_keeps_authored_required_for_readonly_writeonly() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Direction API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "post": {{
        "requestBody": {{
          "required": true,
          "content": {{
            "application/json": {{
              "schema": {{
                "type": "object",
                "required": ["id", "name"],
                "properties": {{
                  "id": {{"type": "string", "readOnly": true}},
                  "name": {{"type": "string"}}
                }}
              }}
            }}
          }}
        }},
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "type": "object",
                  "required": ["secret", "name"],
                  "properties": {{
                    "secret": {{"type": "string", "writeOnly": true}},
                    "name": {{"type": "string"}}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"##,
        proxy = direction_proxy()
    );

    let operation = first_operation(&spec);
    assert_eq!(
        operation["request_body"]["content"]["application/json"]["required"],
        json!(["id", "name"]),
        "OpenAPI 3.1 must not inherit OAS 3.0 readOnly required rewriting"
    );
    assert_eq!(
        operation["responses"]["200"]["application/json"]["required"],
        json!(["secret", "name"]),
        "OpenAPI 3.1 must not inherit OAS 3.0 writeOnly required rewriting"
    );
}

#[test]
fn swagger_20_drops_readonly_required_on_request_only() {
    let spec = format!(
        r##"{{
  "swagger": "2.0",
  "info": {{"title": "Direction API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/items": {{
      "post": {{
        "parameters": [
          {{
            "in": "body",
            "name": "body",
            "required": true,
            "schema": {{
              "type": "object",
              "required": ["id", "name"],
              "properties": {{
                "id": {{"type": "string", "readOnly": true}},
                "name": {{"type": "string"}}
              }}
            }}
          }}
        ],
        "responses": {{
          "200": {{
            "description": "ok",
            "schema": {{
              "type": "object",
              "required": ["id", "name"],
              "properties": {{
                "id": {{"type": "string", "readOnly": true}},
                "name": {{"type": "string"}}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"##,
        proxy = direction_proxy()
    );

    let operation = first_operation(&spec);
    assert_eq!(
        operation["request_body"]["content"]["application/json"]["required"],
        json!(["name"])
    );
    assert_eq!(
        operation["responses"]["200"]["application/json"]["required"],
        json!(["id", "name"]),
        "Swagger 2.0 response side must keep required readOnly properties"
    );
}
