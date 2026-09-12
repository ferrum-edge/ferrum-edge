//! Contract tests: importer-generated `openapi_validator` configs must validate
//! against the published Admin OpenAPI schema (`OpenapiValidatorConfig`).
//!
//! Covers issue #2337: top-level-only `schema_draft`, and JSON Schema values that
//! may be objects (Draft 7 / OAS 3.0) or boolean schemas (Draft 2020-12 / OAS 3.1).

use ferrum_edge::admin::api_specs::{SpecFormat, extract};
use ferrum_edge::plugins::openapi_validator::OpenapiValidator;
use serde_json::{Value, json};

fn openapi_validator_config_validator() -> jsonschema::Validator {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/OpenapiValidatorConfig",
        "components": spec["components"].clone()
    });
    jsonschema::draft202012::options()
        .build(&schema)
        .expect("OpenapiValidatorConfig schema compiles")
}

fn assert_valid_against_admin_schema(config: &Value, label: &str) {
    let validator = openapi_validator_config_validator();
    if let Err(error) = validator.validate(config) {
        panic!("{label} must validate against OpenapiValidatorConfig: {error}; config={config}");
    }
}

fn admission_contract_config() -> Value {
    json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST", "path_template": "/contract", "path_regex": "/contract",
            "request_body": {"content": {"application/json": {"type": "object"}}}
        }]
    })
}

fn assert_admission(validator: &jsonschema::Validator, config: &Value, accepted: bool) {
    assert_eq!(validator.is_valid(config), accepted, "schema: {config}");
    assert_eq!(
        OpenapiValidator::new(config).is_ok(),
        accepted,
        "runtime: {config}"
    );
}

#[test]
fn published_openapi_validator_fields_match_constructor_bounds_and_syntax() {
    let validator = openapi_validator_config_validator();
    for (patch, accepted) in [
        (json!({"max_body_bytes": 1}), true),
        (json!({"max_body_bytes": u64::MAX}), true),
        (json!({"max_body_bytes": 0}), false),
        (json!({"max_body_bytes": -1}), false),
        (json!({"error_truncate_chars": 0}), true),
        (json!({"error_truncate_chars": u64::MAX}), true),
        (json!({"error_truncate_chars": -1}), false),
        (
            json!({"error_response": {"content_type": "application/problem+json; charset=\"utf-8\""}}),
            true,
        ),
        (
            json!({"error_response": {"content_type": "application/problem+json;bad"}}),
            false,
        ),
        (
            json!({"error_response": {"content_type": "application/*"}}),
            false,
        ),
        (
            json!({"error_response": {"content_type": "application/{json}"}}),
            false,
        ),
        (
            json!({"error_response": {"content_type": " application/json"}}),
            false,
        ),
        (
            json!({"error_response": {"content_type": "application/json\n"}}),
            false,
        ),
        (
            json!({"error_response": {"request_status_code": 399}}),
            false,
        ),
        (
            json!({"error_response": {"response_status_code": 600}}),
            false,
        ),
        (json!({"bypass": {"paths": [""]}}), false),
        (json!({"bypass": {"methods": [""]}}), false),
        (json!({"bypass": {"consumers": [""]}}), false),
    ] {
        let mut config = admission_contract_config();
        config
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert_admission(&validator, &config, accepted);
    }
    for field in ["max_body_bytes", "error_truncate_chars"] {
        let mut config = admission_contract_config();
        config[field] = serde_json::from_str("18446744073709551616").unwrap();
        assert!(!validator.is_valid(&config));
        assert!(OpenapiValidator::new(&config).is_err());
    }
    for field in ["method", "path_template", "path_regex", "operation_label"] {
        let mut config = admission_contract_config();
        config["operations"][0][field] = json!("");
        assert!(!validator.is_valid(&config), "empty {field}");
        assert!(OpenapiValidator::new(&config).is_err(), "empty {field}");
    }
}

#[test]
fn published_media_selectors_match_constructor_normalization() {
    let validator = openapi_validator_config_validator();
    for (media, accepted) in [
        (" application/json ", true),
        ("\u{2003}Application/JSON\u{2003};ignored", true),
        ("application/x{sample}", true),
        ("application/*", true),
        ("*/*", true),
        ("*/json", false),
        ("application/json\n", false),
        ("application/json;\u{0085}", false),
    ] {
        let mut config = admission_contract_config();
        config["request_content_types"] = json!([media]);
        config["response_content_types"] = json!([media]);
        config["operations"][0]["request_body"]["content"] = json!({(media): true});
        config["operations"][0]["responses"] = json!({"200": {(media): true}});
        assert_admission(&validator, &config, accepted);
    }
}

#[test]
fn published_encoding_conditions_match_constructor_admission() {
    let validator = openapi_validator_config_validator();
    for inline in [false, true] {
        for (media, encoding, accepted) in [
            (
                "application/x-www-form-urlencoded",
                json!({"style": "spaceDelimited"}),
                true,
            ),
            (
                "application/x-www-form-urlencoded",
                json!({"style": "spaceDelimited", "explode": true}),
                false,
            ),
            (
                "multipart/form-data",
                json!({"style": "pipeDelimited", "explode": true}),
                false,
            ),
            ("multipart/form-data", json!({"style": "deepObject"}), false),
            (
                "multipart/form-data",
                json!({"style": "deepObject", "explode": true}),
                true,
            ),
            (
                "application/x-www-form-urlencoded",
                json!({"headers": {}}),
                false,
            ),
            (
                "application/x-www-form-urlencoded",
                json!({"contentType": "text/plain"}),
                false,
            ),
            ("multipart/form-data", json!({"contentType": "   "}), false),
            (
                "multipart/form-data",
                json!({"contentType": " text/plain "}),
                true,
            ),
            ("application/json", json!({}), false),
        ] {
            let schema = json!({
                "type": "object",
                "properties": {"data": {"type": "object", "additionalProperties": false}}
            });
            let mut config = admission_contract_config();
            let encoding = json!({"data": encoding});
            config["operations"][0]["request_body"] = if inline {
                json!({"content_type": media, "schema": schema, "encoding": encoding})
            } else {
                json!({"content": {(media): {"schema": schema, "encoding": encoding}}})
            };
            assert_admission(&validator, &config, accepted);
        }
    }
}

#[test]
fn response_content_metadata_uses_the_published_response_shape() {
    let validator = openapi_validator_config_validator();
    for (response, accepted) in [
        (
            json!({"description": "ok", "content": {"application/json": true}}),
            true,
        ),
        (json!({"description": "ok", "application/json": true}), true),
        (
            json!({"content": {"application/json": true, "description": "ok"}}),
            false,
        ),
        (
            json!({"application/json": {"schema": true, "encoding": {}}}),
            false,
        ),
    ] {
        let mut config = admission_contract_config();
        config["operations"][0]["responses"] = json!({"200": response});
        assert_admission(&validator, &config, accepted);
    }
}

#[test]
fn schema_dependent_admission_rules_remain_constructor_checks() {
    let validator = openapi_validator_config_validator();
    let mut duplicates = admission_contract_config();
    duplicates["request_content_types"] = json!(["application/json", " Application/JSON "]);
    assert!(validator.is_valid(&duplicates));
    assert!(OpenapiValidator::new(&duplicates).is_err());

    let mut unknown_property = admission_contract_config();
    unknown_property["operations"][0]["request_body"] = json!({"content": {
        "multipart/form-data": {
            "schema": {"type": "object", "properties": {"data": {"type": "string"}}},
            "encoding": {"other": {}}
        }
    }});
    assert!(validator.is_valid(&unknown_property));
    assert!(OpenapiValidator::new(&unknown_property).is_err());

    unknown_property["operations"][0]["request_body"]["content"]["multipart/form-data"]["encoding"] =
        json!({"data": {"style": "deepObject", "explode": true}});
    assert!(validator.is_valid(&unknown_property));
    assert!(OpenapiValidator::new(&unknown_property).is_err());
}

fn extract_validator_config(spec: &str) -> Value {
    let (bundle, _meta) = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect("spec extraction must succeed");
    assert_eq!(bundle.plugins.len(), 1, "expected one generated plugin");
    assert_eq!(bundle.plugins[0].plugin_name, "openapi_validator");
    bundle.plugins[0].config.clone()
}

#[test]
fn importer_draft7_object_schemas_match_published_admin_schema() {
    let spec = r##"{
  "openapi": "3.0.3",
  "info": {"title": "Orders API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "orders-api",
    "backend_host": "orders.internal",
    "backend_port": 8080
  },
  "paths": {
    "/orders": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                  "id": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["accepted"],
                  "properties": {
                    "accepted": {"type": "boolean"}
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    assert_eq!(config["schema_draft"], "draft7");
    assert!(
        config["operations"][0].get("schema_draft").is_none(),
        "operations must not emit a redundant schema_draft field"
    );
    assert!(config["operations"][0]["request_body"]["content"]["application/json"].is_object());
    assert!(config["operations"][0]["responses"]["200"]["application/json"].is_object());
    assert_valid_against_admin_schema(&config, "Draft 7 importer-generated config");
}

#[test]
fn importer_draft202012_boolean_schemas_match_published_admin_schema() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Boolean Schema API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "bool-api",
    "backend_host": "bool.internal",
    "backend_port": 8080
  },
  "paths": {
    "/any": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": true
            }
          }
        },
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": false
              }
            }
          },
          "default": {
            "description": "fallback",
            "content": {
              "application/json": {
                "schema": true
              }
            }
          }
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    assert_eq!(config["schema_draft"], "draft2020-12");
    assert!(
        config["operations"][0].get("schema_draft").is_none(),
        "operations must not emit a redundant schema_draft field"
    );
    assert_eq!(
        config["operations"][0]["request_body"]["content"]["application/json"],
        true
    );
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"],
        false
    );
    assert_eq!(
        config["operations"][0]["responses"]["default"]["application/json"],
        true
    );
    assert_valid_against_admin_schema(&config, "Draft 2020-12 boolean-schema importer config");
}

#[test]
fn published_schema_accepts_alternate_single_schema_boolean_form() {
    // Importer emits the content-map form; the alternate content_type/schema
    // shape is operator-facing and must accept boolean schemas consistently.
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "PUT",
            "path_template": "/items/{id}",
            "path_regex": "^/items/[^/]+$",
            "request_required": true,
            "request_body": {
                "content_type": "application/json",
                "schema": true
            },
            "responses": {
                "204": {
                    "application/json": false
                }
            }
        }]
    });
    assert_valid_against_admin_schema(&config, "alternate single-schema boolean form");
}

#[test]
fn published_schema_rejects_per_operation_schema_draft() {
    let validator = openapi_validator_config_validator();
    let config = json!({
        "schema_draft": "draft7",
        "operations": [{
            "method": "GET",
            "path_template": "/health",
            "path_regex": "^/health$",
            "schema_draft": "draft7"
        }]
    });
    assert!(
        validator.validate(&config).is_err(),
        "OpenapiValidatorOperation must reject undeclared schema_draft"
    );
}

#[test]
fn importer_preserves_form_encoding_objects_in_generated_config() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Form API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "form-api",
    "backend_host": "form.internal",
    "backend_port": 8080
  },
  "paths": {
    "/tags": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["tags"],
                "properties": {
                  "tags": {
                    "type": "array",
                    "minItems": 2,
                    "items": {"type": "string"}
                  }
                }
              },
              "encoding": {
                "tags": {"style": "form", "explode": false}
              }
            }
          }
        },
        "responses": {
          "204": {"description": "ok"}
        }
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    let media =
        &config["operations"][0]["request_body"]["content"]["application/x-www-form-urlencoded"];
    assert_eq!(media["encoding"]["tags"]["style"], "form");
    assert_eq!(media["encoding"]["tags"]["explode"], false);
    assert!(media["schema"]["properties"]["tags"].is_object());
    assert_valid_against_admin_schema(&config, "form encoding importer config");
}

#[test]
fn importer_resolves_multipart_encoding_header_and_schema_refs() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Upload API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "upload-api",
    "backend_host": "upload.internal",
    "backend_port": 8080
  },
  "components": {
    "schemas": {
      "PartTokenValue": {
        "type": "string",
        "pattern": "^[A-Z]{8}$"
      }
    },
    "headers": {
      "PartToken": {
        "required": true,
        "schema": {"$ref": "#/components/schemas/PartTokenValue"}
      }
    }
  },
  "paths": {
    "/upload": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "required": ["file"],
                "properties": {
                  "file": {"type": "string", "format": "binary"}
                }
              },
              "encoding": {
                "file": {
                  "headers": {
                    "X-Part-Token": {"$ref": "#/components/headers/PartToken"}
                  }
                }
              }
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}"##;

    let config = extract_validator_config(spec);
    let header = &config["operations"][0]["request_body"]["content"]["multipart/form-data"]["encoding"]
        ["file"]["headers"]["X-Part-Token"];
    assert!(header.get("$ref").is_none());
    assert!(header["schema"].get("$ref").is_none());
    assert_eq!(header["required"], true);
    assert_eq!(header["schema"]["type"], "string");
    assert_eq!(header["schema"]["pattern"], "^[A-Z]{8}$");
    assert_valid_against_admin_schema(&config, "resolved multipart header refs");

    let invalid_spec = spec.replacen(
        "\"required\": true,\n        \"schema\": {\"$ref\": \"#/components/schemas/PartTokenValue\"}",
        "\"requred\": true,\n        \"schema\": {\"$ref\": \"#/components/schemas/PartTokenValue\"}",
        1,
    );
    let error = extract(invalid_spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect_err("an unknown Header Object field must fail import");
    assert!(
        error.to_string().contains("requred"),
        "unexpected error: {error}"
    );
}

#[test]
fn importer_rejects_case_equivalent_duplicate_multipart_encoding_headers() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Upload API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "upload-api",
    "backend_host": "upload.internal",
    "backend_port": 8080
  },
  "paths": {
    "/upload": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "required": ["file"],
                "properties": {
                  "file": {"type": "string", "format": "binary"}
                }
              },
              "encoding": {
                "file": {
                  "headers": {
                    "X-Part-Token": {
                      "required": true,
                      "schema": {"type": "string", "minLength": 8}
                    },
                    "x-part-token": {
                      "schema": {"type": "string"}
                    }
                  }
                }
              }
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}"##;

    let error = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect_err("case-equivalent multipart encoding headers must fail import");
    let message = error.to_string();
    assert!(
        message.contains("duplicate header name"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("encoding") && message.contains("headers"),
        "error must be path-qualified: {message}"
    );
}

fn multipart_encoding_header_content_spec(header_object: &str) -> String {
    format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Upload API", "version": "1.0.0"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {{
    "id": "upload-api",
    "backend_host": "upload.internal",
    "backend_port": 8080
  }},
  "components": {{
    "schemas": {{
      "PartMeta": {{
        "type": "object",
        "required": ["kind"],
        "properties": {{
          "kind": {{"type": "string", "minLength": 3}}
        }},
        "additionalProperties": false
      }}
    }}
  }},
  "paths": {{
    "/upload": {{
      "post": {{
        "requestBody": {{
          "required": true,
          "content": {{
            "multipart/form-data": {{
              "schema": {{
                "type": "object",
                "required": ["file"],
                "properties": {{
                  "file": {{"type": "string", "format": "binary"}}
                }}
              }},
              "encoding": {{
                "file": {{
                  "headers": {{
                    "X-Part-Meta": {header_object}
                  }}
                }}
              }}
            }}
          }}
        }},
        "responses": {{"204": {{"description": "ok"}}}}
      }}
    }}
  }}
}}"##
    )
}

#[test]
fn importer_preserves_multipart_encoding_header_content_form() {
    let spec = multipart_encoding_header_content_spec(
        r##"{
          "required": true,
          "content": {
            "application/json": {
              "schema": {"$ref": "#/components/schemas/PartMeta"}
            }
          }
        }"##,
    );
    let config = extract_validator_config(&spec);
    let header = &config["operations"][0]["request_body"]["content"]["multipart/form-data"]["encoding"]
        ["file"]["headers"]["X-Part-Meta"];
    assert!(header.get("schema").is_none());
    assert_eq!(header["required"], true);
    assert!(
        header["content"]["application/json"]["schema"]
            .get("$ref")
            .is_none()
    );
    assert_eq!(
        header["content"]["application/json"]["schema"]["type"],
        "object"
    );
    assert_eq!(
        header["content"]["application/json"]["schema"]["required"],
        json!(["kind"])
    );
    assert_valid_against_admin_schema(&config, "multipart header content form");
}

#[test]
fn importer_rejects_multipart_encoding_header_schema_content_exclusivity() {
    let spec = multipart_encoding_header_content_spec(
        r#"{
          "schema": {"type": "string"},
          "content": {
            "application/json": {
              "schema": {"type": "object"}
            }
          }
        }"#,
    );
    let error = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect_err("schema+content must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("schema") && message.contains("content"),
        "unexpected error: {message}"
    );
}

#[test]
fn importer_rejects_multipart_encoding_header_content_without_exactly_one_media_type() {
    for header_object in [
        r#"{ "content": {} }"#,
        r#"{
          "content": {
            "application/json": {"schema": {"type": "object"}},
            "text/plain": {"schema": {"type": "string"}}
          }
        }"#,
    ] {
        let spec = multipart_encoding_header_content_spec(header_object);
        let error = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
            .expect_err("content must require exactly one media type");
        let message = error.to_string();
        assert!(
            message.contains("exactly one media type") || message.contains("content"),
            "unexpected error: {message}"
        );
    }
}

#[test]
fn importer_rejects_multipart_encoding_header_content_media_encoding_field() {
    let spec = multipart_encoding_header_content_spec(
        r#"{
          "content": {
            "application/json": {
              "schema": {"type": "object"},
              "encoding": {"nested": {"style": "form"}}
            }
          }
        }"#,
    );
    let error = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
        .expect_err("header content Media Type Object must reject encoding");
    let message = error.to_string();
    assert!(
        message.contains("encoding") || message.contains("unsupported field"),
        "unexpected error: {message}"
    );
}

#[test]
fn importer_rejects_malformed_multipart_encoding_header_content() {
    for (header_object, expected) in [
        (
            r#"{ "content": { "application/*": { "schema": { "type": "string" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "*/*": { "schema": { "type": "string" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/{json}": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "text/pl{ain}": { "schema": { "type": "string" } } } }"#,
            "concrete media type",
        ),
        (
            "{ \"content\": { \"application/json;\\u0001charset=utf-8\": { \"schema\": { \"type\": \"object\" } } } }",
            "valid HTTP header value",
        ),
        (
            r#"{ "content": { "application/json; charset": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json; charset=": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json;": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json;; charset=utf-8": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json; charset =utf-8": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json; charset= utf-8": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{ "content": { "application/json; charset=\"unterminated": { "schema": { "type": "object" } } } }"#,
            "concrete media type",
        ),
        (
            r#"{
              "content": {
                "application/json": {
                  "schema": {"type": "object"},
                  "example": {"kind": "one"},
                  "examples": {"two": {"value": {"kind": "two"}}}
                }
              }
            }"#,
            "mutually exclusive",
        ),
        (
            r#"{
              "style": "simple",
              "content": { "application/json": { "schema": { "type": "object" } } }
            }"#,
            "schema-form Header Object field",
        ),
        (
            r#"{
              "allowEmptyValue": true,
              "content": { "application/json": { "schema": { "type": "object" } } }
            }"#,
            "not valid for Header Objects",
        ),
        (
            r#"{
              "allowReserved": false,
              "schema": { "type": "string" }
            }"#,
            "not valid for Header Objects",
        ),
    ] {
        let spec = multipart_encoding_header_content_spec(header_object);
        let error = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod")
            .expect_err("header content must fail closed for wildcards and inert fields");
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "expected '{expected}' in error: {message}"
        );
    }
}

#[test]
fn importer_preserves_multipart_encoding_header_content_with_valid_parameters() {
    let media_type = r#"application/json; charset="utf-8"; profile="v1;beta""#;
    let spec = multipart_encoding_header_content_spec(
        r##"{
          "required": true,
          "content": {
            "application/json; charset=\"utf-8\"; profile=\"v1;beta\"": {
              "schema": {"$ref": "#/components/schemas/PartMeta"}
            }
          }
        }"##,
    );
    let config = extract_validator_config(&spec);
    let header = &config["operations"][0]["request_body"]["content"]["multipart/form-data"]["encoding"]
        ["file"]["headers"]["X-Part-Meta"];
    assert!(header["content"][media_type]["schema"].is_object());
    assert_valid_against_admin_schema(&config, "multipart header content with parameters");
}

#[test]
fn importer_header_content_replacement_drops_prior_content_contract() {
    let with_content = multipart_encoding_header_content_spec(
        r#"{
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["kind"],
                "properties": {"kind": {"type": "string"}}
              }
            }
          }
        }"#,
    );
    let with_schema = multipart_encoding_header_content_spec(
        r#"{
          "required": true,
          "schema": {"type": "string", "minLength": 4}
        }"#,
    );
    let content_config = extract_validator_config(&with_content);
    let schema_config = extract_validator_config(&with_schema);
    let content_header = &content_config["operations"][0]["request_body"]["content"]["multipart/form-data"]
        ["encoding"]["file"]["headers"]["X-Part-Meta"];
    let schema_header = &schema_config["operations"][0]["request_body"]["content"]["multipart/form-data"]
        ["encoding"]["file"]["headers"]["X-Part-Meta"];
    assert!(content_header.get("content").is_some());
    assert!(schema_header.get("content").is_none());
    assert_eq!(schema_header["schema"]["type"], "string");
    assert_valid_against_admin_schema(&schema_config, "replacement schema header form");
}

#[test]
fn published_schema_accepts_encoding_header_content_form() {
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "properties": {"file": {"type": "string"}}
                        },
                        "encoding": {
                            "file": {
                                "headers": {
                                    "X-Part-Meta": {
                                        "required": true,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "required": ["kind"],
                                                    "properties": {"kind": {"type": "string"}}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    });
    assert_valid_against_admin_schema(&config, "published encoding header content form");
}

#[test]
fn published_schema_rejects_encoding_header_schema_and_content_together() {
    let validator = openapi_validator_config_validator();
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/upload",
            "path_regex": "^/upload$",
            "request_body": {
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "properties": {"file": {"type": "string"}}
                        },
                        "encoding": {
                            "file": {
                                "headers": {
                                    "X-Part-Meta": {
                                        "schema": {"type": "string"},
                                        "content": {
                                            "application/json": {
                                                "schema": {"type": "object"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    });
    assert!(
        validator.validate(&config).is_err(),
        "schema+content Header Object must fail the published schema: {config}"
    );
}

#[test]
fn published_schema_rejects_encoding_header_content_wildcards_and_inert_fields() {
    let validator = openapi_validator_config_validator();
    for header in [
        json!({
            "content": {
                "application/*": {"schema": {"type": "string"}}
            }
        }),
        json!({
            "content": {
                "*/*": {"schema": {"type": "string"}}
            }
        }),
        json!({
            "content": {
                "application/{json}": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "content": {
                "text/pl{ain}": {"schema": {"type": "string"}}
            }
        }),
        json!({
            "content": {
                "application/json; charset": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "content": {
                "application/json;": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "content": {
                "application/json;; charset=utf-8": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "content": {
                "application/json; charset=\"unterminated": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "content": {
                "application/json": {
                    "schema": {"type": "object"},
                    "example": {"kind": "one"},
                    "examples": {"two": {"value": {"kind": "two"}}}
                }
            }
        }),
        json!({
            "style": "simple",
            "content": {
                "application/json": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "allowEmptyValue": true,
            "content": {
                "application/json": {"schema": {"type": "object"}}
            }
        }),
        json!({
            "allowReserved": true,
            "schema": {"type": "string"}
        }),
    ] {
        let config = json!({
            "schema_draft": "draft2020-12",
            "operations": [{
                "method": "POST",
                "path_template": "/upload",
                "path_regex": "^/upload$",
                "request_body": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "properties": {"file": {"type": "string"}}
                            },
                            "encoding": {
                                "file": {
                                    "headers": {
                                        "X-Part-Meta": header
                                    }
                                }
                            }
                        }
                    }
                }
            }]
        });
        assert!(
            validator.validate(&config).is_err(),
            "published schema must reject wildcards, brace-bearing media types, and inert Header Object fields: {config}"
        );
    }
}

#[test]
fn importer_rejects_unsupported_encoding_style_at_admission() {
    let spec = r##"{
  "openapi": "3.1.0",
  "info": {"title": "Bad Form API", "version": "1.0.0"},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {
    "id": "bad-form-api",
    "backend_host": "form.internal",
    "backend_port": 8080
  },
  "paths": {
    "/tags": {
      "post": {
        "requestBody": {
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": {
                  "tags": {"type": "array", "items": {"type": "string"}}
                }
              },
              "encoding": {
                "tags": {"style": "matrix"}
              }
            }
          }
        },
        "responses": {"204": {"description": "ok"}}
      }
    }
  }
}"##;

    let err = extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("unsupported") || message.contains("matrix"),
        "unsupported encoding must fail closed, got {message}"
    );
}

#[test]
fn published_schema_accepts_media_type_object_with_encoding() {
    let config = json!({
        "schema_draft": "draft2020-12",
        "operations": [{
            "method": "POST",
            "path_template": "/tags",
            "path_regex": "^/tags$",
            "request_body": {
                "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "tags": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "encoding": {
                            "tags": {
                                "style": "form",
                                "explode": false,
                                "allowReserved": true
                            }
                        }
                    }
                }
            }
        }]
    });
    assert_valid_against_admin_schema(&config, "media type object with encoding");
}

#[test]
fn published_schema_rejects_ambiguous_media_type_objects() {
    let validator = openapi_validator_config_validator();
    for invalid_entry in [
        json!({"encoding": {}}),
        json!({"schema": true, "encoding": null}),
        json!({"schema": true, "encoding": {}, "example": "ambiguous"}),
    ] {
        let config = json!({
            "schema_draft": "draft2020-12",
            "operations": [{
                "method": "POST",
                "path_template": "/strict",
                "path_regex": "^/strict$",
                "request_body": {
                    "content": {
                        "application/x-www-form-urlencoded": invalid_entry
                    }
                }
            }]
        });
        assert!(
            validator.validate(&config).is_err(),
            "ambiguous media type object must fail the published schema: {config}"
        );
    }
}

#[test]
fn published_schema_enforces_request_body_shape_and_response_keys() {
    let validator = openapi_validator_config_validator();
    for request_body in [
        json!({}),
        json!({"content": {}}),
        json!({"content_type": "application/json"}),
        json!({
            "content": {"application/json": {"type": "object"}},
            "content_type": "application/json",
            "schema": {"type": "object"}
        }),
    ] {
        let config = json!({
            "operations": [{
                "method": "POST",
                "path_template": "/strict",
                "path_regex": "^/strict$",
                "request_body": request_body
            }]
        });
        assert!(
            validator.validate(&config).is_err(),
            "invalid request_body shape must fail: {config}"
        );
    }

    let response_object_config = json!({
        "operations": [{
            "method": "GET",
            "path_template": "/strict",
            "path_regex": "^/strict$",
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {"application/json": {"type": "object"}}
                }
            }
        }]
    });
    assert!(
        validator.validate(&response_object_config).is_ok(),
        "the documented Response Object form must validate"
    );

    let invalid_status_config = json!({
        "operations": [{
            "method": "GET",
            "path_template": "/strict",
            "path_regex": "^/strict$",
            "responses": {
                "0200": {"application/json": {"type": "object"}}
            }
        }]
    });
    assert!(
        validator.validate(&invalid_status_config).is_err(),
        "non-canonical status keys must fail the published schema"
    );
}
