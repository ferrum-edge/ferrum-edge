//! External and cross-document OpenAPI `$ref` resolution (issue #3306).
//!
//! Covers opt-in policy, file/map loaders, Path Item and schema chains,
//! fragments, cycles/budgets, traversal rejection, SSRF URI gates, and
//! immutable snapshot digests. Network success paths use an in-memory map
//! loader (no live Internet). Absent policy stays fail-closed.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ferrum_edge::admin::api_specs::external_refs::{
    ExternalDocumentLoader, ExternalRefEnvBudgets, ExternalRefEnvOrigins, ExternalRefEnvTimeouts,
    LoadedExternalDocument, contain_path, redact_reference, resource_uri_key,
    validate_external_ref_snapshot_pair,
};
use ferrum_edge::admin::api_specs::{
    DefaultExternalDocumentLoader, EffectiveExternalRefPolicy, ExternalRefProcessPolicy,
    ExternalRefSnapshot, ExternalRefSpecExtension, ExtractError, MapExternalDocumentLoader,
    SpecFormat, extract, extract_with_external_refs,
};
use serde_json::{Value, json};
use url::Url;

fn proxy_block() -> &'static str {
    r#"{
    "id": "ext-ref-proxy",
    "backend_host": "backend.internal",
    "backend_port": 443
  }"#
}

fn process_enabled(file_root: Option<PathBuf>) -> ExternalRefProcessPolicy {
    ExternalRefProcessPolicy {
        enabled: true,
        file_root,
        allowed_origins: vec!["https://schemas.example.com:443".to_string()],
        allow_http_origins: vec!["http://127.0.0.1:9".to_string()],
        max_documents: 8,
        max_document_bytes: 64 * 1024,
        max_aggregate_bytes: 256 * 1024,
        max_refs: 64,
        max_uri_length: 2048,
        max_redirects: 2,
        max_nesting: 8,
        // Success-path budgets. Every fixture here answers within microseconds
        // on an idle machine, but a loaded coverage runner has reported both
        // request timeouts and truncated body reads under a 200 ms request
        // budget. Tests that assert on a deadline set their own tight values.
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(10),
    }
}

fn extract_err(spec: &str) -> ExtractError {
    extract(spec.as_bytes(), Some(SpecFormat::Json), "prod").expect_err("must fail")
}

fn extract_validator_ops(
    spec: &str,
    process: &ExternalRefProcessPolicy,
    loader: &dyn ExternalDocumentLoader,
) -> Value {
    let (bundle, meta) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        process,
        loader,
    )
    .expect("extraction must succeed");
    assert!(
        meta.external_ref_snapshot.is_some(),
        "enabled external refs must produce a snapshot"
    );
    bundle
        .plugins
        .iter()
        .find(|p| p.plugin_name == "openapi_validator")
        .expect("openapi_validator")
        .config
        .clone()
}

async fn load_production_http(
    uri: String,
    process: ExternalRefProcessPolicy,
) -> Result<ferrum_edge::admin::api_specs::external_refs::LoadedExternalDocument, ExtractError> {
    let extension = ExternalRefSpecExtension {
        enabled: true,
        document_base: None,
        allowed_origins: Vec::new(),
    };
    let policy = EffectiveExternalRefPolicy::compose(&process, Some(&extension))?;
    let total_timeout = process.total_timeout;
    let loader = DefaultExternalDocumentLoader {
        egress: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        dns_cache: None,
        fixtures: Default::default(),
    };
    // Arm the total deadline at the blocking load boundary. Computing it before
    // `spawn_blocking` schedules lets coverage-induced worker delay burn the
    // budget before dial, so the client times out without ever reaching the
    // live non-responding peer the fixture is meant to prove.
    tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + total_timeout;
        let uri = Url::parse(&uri)
            .map_err(|_| ExtractError::SchemaReference("invalid test URI".to_string()))?;
        loader.load(&uri, &policy, deadline)
    })
    .await
    .map_err(|_| ExtractError::SchemaReference("blocking test worker failed".to_string()))?
}

fn spawn_raw_http_response(response: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
    let port = listener.local_addr().expect("HTTP fixture address").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept HTTP fixture request");
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        stream
            .write_all(&response)
            .expect("write HTTP fixture response");
    });
    (port, server)
}

/// Accept one request, return response headers plus a partial body, then stall.
///
/// Does not return until the fixture thread reaches the `accept` boundary. The
/// accepted stream is handed back through `stalled` only after headers and an
/// incomplete `Content-Length` body are written, so receiving it proves the
/// production client is blocked in response-body I/O. The fixture thread must
/// not block on peer FIN: a cancelled reqwest fetch can leave the TCP session
/// open long enough for an unbounded second `read` + `join` to hang under
/// coverage instrumentation.
fn spawn_stalled_http_peer() -> (
    u16,
    std::sync::mpsc::Receiver<std::net::TcpStream>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled HTTP fixture");
    let port = listener
        .local_addr()
        .expect("stalled HTTP fixture address")
        .port();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stalled_tx, stalled_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let _ = ready_tx.send(());
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let partial_body = b"{\"type\":\"string\"";
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            partial_body.len() + 64
        );
        let _ = stream.write_all(headers.as_bytes());
        let _ = stream.write_all(partial_body);
        let _ = stalled_tx.send(stream);
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stalled HTTP fixture must reach accept boundary");
    (port, stalled_rx, server)
}

#[test]
fn absent_policy_keeps_external_refs_unsupported() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_err(&spec);
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "{err}"
    );
}

#[test]
fn process_gate_alone_is_insufficient() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );
    let process = process_enabled(None);
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &MapExternalDocumentLoader::default(),
    )
    .expect_err("per-spec opt-in required");
    assert!(
        matches!(err, ExtractError::UnsupportedExternalRef { .. }),
        "{err}"
    );
}

#[test]
fn map_loader_resolves_external_path_item_and_schema_chain() {
    let paths_doc = br#"{
  "paths": {
    "/pets": {
      "get": {
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": { "$ref": "https://schemas.example.com/schemas/pet.json" }
              }
            }
          }
        }
      }
    }
  }
}"#;
    let schema_doc = br#"{
  "type": "object",
  "required": ["id"],
  "properties": { "id": { "type": "integer" } }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/paths.json".to_string(),
        paths_doc.to_vec(),
    );
    loader.docs.insert(
        "https://schemas.example.com/schemas/pet.json".to_string(),
        schema_doc.to_vec(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{
    "enabled": true,
    "allowed_origins": ["https://schemas.example.com"]
  }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/pets": {{"$ref": "https://schemas.example.com/paths.json#/paths/~1pets"}}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(config["operations"][0]["method"], "GET");
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["id"])
    );
}

struct RedirectAliasLoader;

impl ExternalDocumentLoader for RedirectAliasLoader {
    fn load(
        &self,
        uri: &Url,
        _policy: &EffectiveExternalRefPolicy,
        _deadline: Instant,
    ) -> Result<LoadedExternalDocument, ExtractError> {
        assert_eq!(uri.as_str(), "https://schemas.example.com/start.json");
        let root = json!({
            "$anchor": "redirected",
            "type": "object",
            "required": ["through_redirect"],
            "properties": {"through_redirect": {"type": "boolean"}}
        });
        Ok(LoadedExternalDocument {
            canonical_uri: Url::parse("https://schemas.example.com/final.json").unwrap(),
            content_digest: "redirected-document".to_string(),
            format: "json",
            raw_bytes: serde_json::to_vec(&root).unwrap(),
            root,
        })
    }
}

#[test]
fn redirected_request_uri_remains_a_resolver_alias() {
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/redirected": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/start.json#redirected"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &RedirectAliasLoader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["through_redirect"])
    );
}

#[test]
fn query_bearing_and_queryless_schema_resources_remain_distinct() {
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/resource.json".to_string(),
        br#"{
  "type": "object",
  "required": ["from_queryless_resource"],
  "properties": {"from_queryless_resource": {"type": "boolean"}}
}"#
        .to_vec(),
    );
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "Query identity", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "components": {{
    "schemas": {{
      "QueryResource": {{
        "$id": "https://schemas.example.com/resource.json?view=local",
        "type": "object",
        "required": ["from_query_resource"],
        "properties": {{"from_query_resource": {{"type": "string"}}}}
      }}
    }}
  }},
  "paths": {{
    "/plain": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{"$ref": "https://schemas.example.com/resource.json"}}
              }}
            }}
          }}
        }}
      }}
    }},
    "/query": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/resource.json?view=local"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    let operations = config["operations"].as_array().expect("operations array");
    let plain = operations
        .iter()
        .find(|operation| operation["path_template"] == "/plain")
        .expect("queryless operation");
    let query = operations
        .iter()
        .find(|operation| operation["path_template"] == "/query")
        .expect("query-bearing operation");
    assert_eq!(
        plain["responses"]["200"]["application/json"]["required"],
        json!(["from_queryless_resource"])
    );
    assert_eq!(
        query["responses"]["200"]["application/json"]["required"],
        json!(["from_query_resource"])
    );
}

#[test]
fn nested_relative_bases_resolve_against_containing_document() {
    // Parent is retrieved from a deeper path than the Wrapper `$id`. The
    // sibling `$ref` must join against that `$id` (…/nest/wrapper.json), not
    // the retrieval URI (…/deep/nest/parent.json); otherwise `../leaf.json`
    // would miss the loaded leaf document.
    let parent = br#"{
  "components": {
    "schemas": {
      "Wrapper": {
        "$id": "https://schemas.example.com/nest/wrapper.json",
        "$ref": "../leaf.json#/definitions/Leaf"
      }
    }
  }
}"#;
    let leaf = br#"{
  "definitions": {
    "Leaf": {
      "type": "object",
      "required": ["ok"],
      "properties": { "ok": { "type": "boolean" } }
    }
  }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/deep/nest/parent.json".to_string(),
        parent.to_vec(),
    );
    loader.docs.insert(
        "https://schemas.example.com/leaf.json".to_string(),
        leaf.to_vec(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{ "enabled": true }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/x": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/deep/nest/parent.json#/components/schemas/Wrapper"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );

    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["ok"])
    );
}

#[test]
fn escaped_json_pointer_fragment_across_documents() {
    let remote = br#"{
  "components": {
    "schemas": {
      "Order Id": {
        "type": "object",
        "required": ["n"],
        "properties": { "n": { "type": "string" } }
      }
    }
  }
}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/remote.json".to_string(),
        remote.to_vec(),
    );
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/o": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{
                  "$ref": "https://schemas.example.com/remote.json#/components/schemas/Order%20Id"
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let config = extract_validator_ops(&spec, &process_enabled(None), &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["n"])
    );
}

#[test]
fn cross_document_cycle_fails_closed() {
    let a = br#"{ "$ref": "https://schemas.example.com/b.json" }"#;
    let b = br#"{ "$ref": "https://schemas.example.com/a.json" }"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader
        .docs
        .insert("https://schemas.example.com/a.json".to_string(), a.to_vec());
    loader
        .docs
        .insert("https://schemas.example.com/b.json".to_string(), b.to_vec());
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/c": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/a.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process_enabled(None),
        &loader,
    )
    .expect_err("cycle");
    assert!(
        matches!(err, ExtractError::SchemaReferenceCycle { .. }),
        "{err}"
    );
}

#[test]
fn document_count_budget_fails_closed() {
    let mut loader = MapExternalDocumentLoader::default();
    for i in 0..5 {
        loader.docs.insert(
            format!("https://schemas.example.com/d{i}.json"),
            format!(
                r#"{{"$ref":"https://schemas.example.com/d{}.json"}}"#,
                i + 1
            )
            .into_bytes(),
        );
    }
    loader.docs.insert(
        "https://schemas.example.com/d5.json".to_string(),
        br#"{"type":"string"}"#.to_vec(),
    );
    let mut process = process_enabled(None);
    process.max_documents = 2;
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/c": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/d0.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let err = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .expect_err("budget");
    assert!(
        matches!(err, ExtractError::SchemaReference(_))
            || matches!(err, ExtractError::SchemaTooLarge { .. }),
        "{err}"
    );
}

#[test]
fn file_root_sibling_and_traversal_rejection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    fs::write(
        root.join("pet.json"),
        br#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}"#,
    )
    .unwrap();
    // Symlink escape target outside the jail.
    let outside = dir.path().parent().unwrap().join("outside-secret.json");
    fs::write(&outside, br#"{"type":"string"}"#).unwrap();
    let link = root.join("escape.json");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let process = process_enabled(Some(root.clone()));
    let mut loader = MapExternalDocumentLoader::default();
    // Use DefaultExternalDocumentLoader semantics via contain_path unit below;
    // for extract, feed file contents through map keyed by file URI.
    let pet_uri = Url::from_file_path(root.join("pet.json")).unwrap();
    loader.docs.insert(
        resource_uri_key(&pet_uri),
        fs::read(root.join("pet.json")).unwrap(),
    );

    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": {{
    "enabled": true,
    "document_base": "{base}"
  }},
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "pet.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        base = Url::from_file_path(root.join("root.json")).unwrap(),
        proxy = proxy_block()
    );
    // document_base file URI requires process file_root; compose validates it.
    let config = extract_validator_ops(&spec, &process, &loader);
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["name"])
    );

    #[cfg(unix)]
    {
        let err = contain_path(&root, &link).expect_err("symlink must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("symbolic link") || msg.contains("escapes"),
            "{msg}"
        );
        assert!(!msg.contains("outside-secret"));
    }

    let traversal = root
        .join("subdir")
        .join("..")
        .join("..")
        .join("etc")
        .join("passwd");
    let err = contain_path(&root, &traversal).expect_err("traversal");
    assert!(!err.to_string().contains("/etc/passwd"));
}

#[test]
fn scheme_userinfo_and_private_https_rejected() {
    let process = process_enabled(None);
    let cases = [
        "http://schemas.example.com/a.json",
        "https://user:pass@schemas.example.com/a.json",
        "https://169.254.169.254/latest",
        "https://127.0.0.1/a.json",
        "ftp://schemas.example.com/a.json",
    ];
    for uri in cases {
        let spec = format!(
            r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{ "schema": {{ "$ref": "{uri}" }} }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
            proxy = proxy_block(),
            uri = uri
        );
        let err = extract_with_external_refs(
            spec.as_bytes(),
            Some(SpecFormat::Json),
            "prod",
            &process,
            &MapExternalDocumentLoader::default(),
        )
        .expect_err(uri);
        let rendered = err.to_string();
        assert!(
            !rendered.contains("user:pass"),
            "must not echo credentials: {rendered}"
        );
        assert!(
            matches!(
                err,
                ExtractError::UnsupportedExternalRef { .. }
                    | ExtractError::SchemaReference(_)
                    | ExtractError::MalformedExtension { .. }
            ),
            "{uri}: {err}"
        );
    }
}

#[test]
fn snapshot_is_reproducible_and_digest_stable() {
    let remote = br#"{"type":"string","minLength":1}"#;
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/s.json".to_string(),
        remote.to_vec(),
    );
    let process = process_enabled(None);
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "https://schemas.example.com/s.json" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block()
    );
    let (_, meta1) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .unwrap();
    let (_, meta2) = extract_with_external_refs(
        spec.as_bytes(),
        Some(SpecFormat::Json),
        "prod",
        &process,
        &loader,
    )
    .unwrap();
    let s1 = meta1.external_ref_snapshot.unwrap();
    let s2 = meta2.external_ref_snapshot.unwrap();
    assert_eq!(s1.snapshot_digest, s2.snapshot_digest);
    assert_eq!(s1.compute_digest(), s1.snapshot_digest);
    let gzip = s1.gzip_bytes().unwrap();
    validate_external_ref_snapshot_pair(Some(&gzip), Some(s1.snapshot_digest.as_str())).unwrap();
    let restored = ExternalRefSnapshot::from_gzip_bytes(&gzip, 1024 * 1024).unwrap();
    assert_eq!(restored.snapshot_digest, s1.snapshot_digest);
}

#[test]
fn effective_policy_digest_tracks_narrowing_and_canonical_set_order() {
    let mut process = process_enabled(None);
    process.allowed_origins = vec![
        "https://schemas.example.com:443".to_string(),
        "https://alternate.example.com:443".to_string(),
    ];
    process.allow_http_origins = vec![
        "http://127.0.0.1:9".to_string(),
        "http://localhost:8080".to_string(),
    ];

    let narrowed_schemas = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: vec!["https://schemas.example.com".to_string()],
        }),
    )
    .unwrap();
    let narrowed_alternate = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: vec!["https://alternate.example.com".to_string()],
        }),
    )
    .unwrap();
    assert_ne!(
        narrowed_schemas.effective_policy_digest,
        narrowed_alternate.effective_policy_digest
    );
    let schemas_snapshot = ExternalRefSnapshot::empty(&narrowed_schemas);
    let alternate_snapshot = ExternalRefSnapshot::empty(&narrowed_alternate);
    assert_ne!(
        schemas_snapshot.policy_digest,
        alternate_snapshot.policy_digest
    );
    assert_ne!(
        schemas_snapshot.snapshot_digest,
        alternate_snapshot.snapshot_digest
    );

    let mut reordered_process = process.clone();
    reordered_process.allowed_origins.reverse();
    reordered_process.allow_http_origins.reverse();
    let all_origins = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: vec![
                "https://schemas.example.com".to_string(),
                "https://alternate.example.com".to_string(),
            ],
        }),
    )
    .unwrap();
    let reordered_all_origins = EffectiveExternalRefPolicy::compose(
        &reordered_process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: vec![
                "https://alternate.example.com".to_string(),
                "https://schemas.example.com".to_string(),
            ],
        }),
    )
    .unwrap();
    assert_eq!(process.policy_digest(), reordered_process.policy_digest());
    assert_eq!(
        all_origins.effective_policy_digest,
        reordered_all_origins.effective_policy_digest
    );
    let all_snapshot = ExternalRefSnapshot::empty(&all_origins);
    let reordered_snapshot = ExternalRefSnapshot::empty(&reordered_all_origins);
    assert_eq!(all_snapshot.policy_digest, reordered_snapshot.policy_digest);
    assert_eq!(
        all_snapshot.snapshot_digest,
        reordered_snapshot.snapshot_digest
    );

    let disabled = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: false,
            document_base: None,
            allowed_origins: vec![
                "https://schemas.example.com".to_string(),
                "https://alternate.example.com".to_string(),
            ],
        }),
    )
    .unwrap();
    assert_ne!(
        all_origins.effective_policy_digest,
        disabled.effective_policy_digest
    );
}

#[test]
fn effective_policy_cache_key_does_not_expose_file_base() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let process = process_enabled(Some(root.clone()));
    let document_base = Url::from_file_path(root.join("root.json"))
        .expect("file document base")
        .to_string();
    let policy = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: Some(document_base),
            allowed_origins: Vec::new(),
        }),
    )
    .unwrap();
    let cache_key = policy.effective_policy_digest.clone();
    let raw_root = root.to_string_lossy().to_string();
    assert!(!cache_key.contains(&raw_root));

    let empty_snapshot = ExternalRefSnapshot::empty(&policy);
    assert!(
        empty_snapshot
            .root_document_base
            .starts_with("file:sha256:")
    );
    assert!(!empty_snapshot.root_document_base.contains(&raw_root));

    let child_uri = Url::from_file_path(root.join("child.json")).expect("child file URI");
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        resource_uri_key(&child_uri),
        br#"{"type":"string"}"#.to_vec(),
    );
    let (_, snapshot) = ferrum_edge::admin::api_specs::load_external_documents(
        &json!({"$ref": "child.json"}),
        &policy,
        &loader,
    )
    .expect("file snapshot identity");
    assert_eq!(snapshot.documents.len(), 1);
    assert!(
        snapshot.documents[0]
            .canonical_uri
            .starts_with("file:sha256:")
    );
    assert!(!snapshot.documents[0].canonical_uri.contains(&raw_root));
}

#[tokio::test]
async fn http_fixture_listener_resolves_under_explicit_http_allowlist() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    let origin = format!("http://127.0.0.1:{}", addr.port());
    let body = br#"{"type":"object","required":["n"],"properties":{"n":{"type":"integer"}}}"#;
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });

    let mut process = process_enabled(None);
    process.allow_http_origins = vec![format!("http://127.0.0.1:{}", addr.port())];
    // Loopback must pass egress for the fixture; production HTTPS stays public-only.
    let loader = ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader {
        egress: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        dns_cache: None,
        fixtures: Default::default(),
    };

    let uri = format!("{origin}/schema.json");
    let spec = format!(
        r##"{{
  "openapi": "3.1.0",
  "info": {{"title": "t", "version": "1"}},
  "x-ferrum-validate": true,
  "x-ferrum-external-refs": true,
  "x-ferrum-proxy": {proxy},
  "paths": {{
    "/p": {{
      "get": {{
        "responses": {{
          "200": {{
            "description": "ok",
            "content": {{
              "application/json": {{
                "schema": {{ "$ref": "{uri}" }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}"##,
        proxy = proxy_block(),
        uri = uri
    );

    let (bundle, meta) = tokio::task::spawn_blocking(move || {
        extract_with_external_refs(
            spec.as_bytes(),
            Some(SpecFormat::Json),
            "prod",
            &process,
            &loader,
        )
    })
    .await
    .expect("blocking worker")
    .expect("HTTP fixture fetch must succeed under explicit allowlist");
    server.join().expect("HTTP fixture thread");
    assert!(meta.external_ref_snapshot.is_some());
    let config = bundle
        .plugins
        .iter()
        .find(|p| p.plugin_name == "openapi_validator")
        .unwrap()
        .config
        .clone();
    assert_eq!(
        config["operations"][0]["responses"]["200"]["application/json"]["required"],
        json!(["n"])
    );
}

#[test]
fn redaction_is_utf8_safe_and_hides_filesystem_paths() {
    let redacted = redact_reference("https://alice:s3cret@host.example/x?token=abc#/y");
    assert!(!redacted.contains("alice"));
    assert!(!redacted.contains("s3cret"));
    assert!(!redacted.contains("token"));
    let unicode = format!("relative/{}?secret=yes", "🦀".repeat(80));
    let unicode_redacted = redact_reference(&unicode);
    assert!(unicode_redacted.ends_with('…'));
    assert!(!unicode_redacted.contains("secret"));
    assert_eq!(
        redact_reference("/srv/private/specs/root.yaml"),
        "[filesystem path redacted]"
    );
    assert_eq!(
        redact_reference(r"C:\private\specs\root.yaml"),
        "[filesystem path redacted]"
    );
    assert_eq!(
        redact_reference("file:///srv/private/specs/root.yaml?token=secret"),
        "file:[redacted]"
    );
    let protocol_relative = redact_reference(
        "//protocol-user:protocol-secret@host.example/path?token=protocol-query#/schema",
    );
    assert!(protocol_relative.contains("host.example"));
    assert!(protocol_relative.contains("#/schema"));
    assert_eq!(
        redact_reference(
            "https://malformed-user:malformed-secret@ bad-host/path?token=malformed-query"
        ),
        "https:[redacted]"
    );

    let adversarial = [
        "//protocol-user:protocol-secret@host.example/path?token=protocol-query#/schema",
        "https://malformed-user:malformed-secret@ bad-host/path?token=malformed-query",
        "https:/absolute-ish-user:absolute-ish-secret@host.example/path?token=absolute-ish-query",
        "relative/relative-user:relative-secret@host.example/path?token=relative-query",
        r"\\server\private\credential.txt?token=windows-query",
        r"D:\private\credential.txt?token=drive-query",
    ];
    for reference in adversarial {
        let rendered = redact_reference(reference);
        for secret in [
            "protocol-user",
            "protocol-secret",
            "protocol-query",
            "malformed-user",
            "malformed-secret",
            "malformed-query",
            "absolute-ish-user",
            "absolute-ish-secret",
            "absolute-ish-query",
            "relative-user",
            "relative-secret",
            "relative-query",
            "windows-query",
            "drive-query",
        ] {
            assert!(
                !rendered.contains(secret),
                "redacted reference exposed '{secret}': {rendered}"
            );
        }
        assert!(rendered.len() <= 257, "diagnostic must remain bounded");
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
    }
}

#[test]
fn snapshot_rejects_document_tampering_even_with_recomputed_snapshot_digest() {
    let mut loader = MapExternalDocumentLoader::default();
    loader.docs.insert(
        "https://schemas.example.com/value.json".to_string(),
        br#"{"type":"string"}"#.to_vec(),
    );
    let process = process_enabled(None);
    let policy = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: Vec::new(),
        }),
    )
    .unwrap();
    let root = json!({"$ref": "https://schemas.example.com/value.json"});
    let (_, mut snapshot) =
        ferrum_edge::admin::api_specs::load_external_documents(&root, &policy, &loader).unwrap();
    snapshot.documents[0].document = json!({"type": "integer"});
    snapshot.snapshot_digest = snapshot.compute_digest();
    let gzip = snapshot.gzip_bytes().unwrap();
    let err =
        validate_external_ref_snapshot_pair(Some(&gzip), Some(snapshot.snapshot_digest.as_str()))
            .expect_err("retaining content_digest after document mutation must fail");
    assert!(err.contains("integrity") || err.contains("digest"));
}

#[test]
fn disabled_extension_still_validates_allowed_origins() {
    let process = process_enabled(None);
    for allowed_origins in [
        vec!["not a URI".to_string()],
        vec!["https://not-process-allowed.example".to_string()],
    ] {
        let extension = ExternalRefSpecExtension {
            enabled: false,
            document_base: None,
            allowed_origins,
        };
        let err = EffectiveExternalRefPolicy::compose(&process, Some(&extension))
            .expect_err("disabled malformed/disallowed fields must fail closed");
        assert!(matches!(err, ExtractError::MalformedExtension { .. }));
    }
}

#[test]
fn ipv6_origins_are_canonicalized_with_brackets() {
    let process = ExternalRefProcessPolicy::from_env_parts(
        true,
        ExternalRefEnvOrigins {
            file_root: "",
            allowed_origins: "https://[2001:4860:4860::8888]",
            allow_http_origins: "http://[::1]:8080",
        },
        ExternalRefEnvBudgets {
            max_documents: 4,
            max_document_bytes: 1024,
            max_aggregate_bytes: 4096,
            max_refs: 8,
            max_uri_length: 2048,
            max_redirects: 2,
            max_nesting: 4,
        },
        ExternalRefEnvTimeouts {
            connect_timeout_ms: 100,
            request_timeout_ms: 200,
            total_timeout_ms: 500,
        },
    )
    .unwrap();
    assert_eq!(
        process.allowed_origins,
        vec!["https://[2001:4860:4860::8888]:443"]
    );
    assert_eq!(process.allow_http_origins, vec!["http://[::1]:8080"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn private_https_is_denied_even_when_backend_egress_is_unrestricted() {
    let mut process = process_enabled(None);
    process.allowed_origins = vec!["https://10.0.0.1:443".to_string()];
    let error = load_production_http("https://10.0.0.1/schema.json".to_string(), process)
        .await
        .expect_err("HTTPS RFC1918 destination must be unconditionally denied");
    assert!(error.to_string().contains("public destination"));
}

#[cfg(unix)]
#[test]
fn contained_loader_rejects_intermediate_directory_symlink_swap() {
    let temp = tempfile::tempdir().unwrap();
    let jail = temp.path().join("jail");
    let outside = temp.path().join("outside");
    fs::create_dir_all(jail.join("schemas")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(jail.join("schemas/value.json"), br#"{"type":"string"}"#).unwrap();
    fs::write(outside.join("value.json"), br#"{"secret":true}"#).unwrap();
    let uri = Url::from_file_path(jail.join("schemas/value.json")).unwrap();
    let process = process_enabled(Some(jail.clone()));
    let policy = EffectiveExternalRefPolicy::compose(
        &process,
        Some(&ExternalRefSpecExtension {
            enabled: true,
            document_base: None,
            allowed_origins: Vec::new(),
        }),
    )
    .unwrap();
    let loader = DefaultExternalDocumentLoader::default();
    loader
        .load(&uri, &policy, Instant::now() + Duration::from_secs(1))
        .expect("ordinary contained file");

    fs::rename(jail.join("schemas"), jail.join("schemas-old")).unwrap();
    std::os::unix::fs::symlink(&outside, jail.join("schemas")).unwrap();
    let error = loader
        .load(&uri, &policy, Instant::now() + Duration::from_secs(1))
        .expect_err("swapped intermediate symlink must be refused");
    assert!(!error.to_string().contains("outside"));
    assert!(!error.to_string().contains("secret"));
}

#[tokio::test(flavor = "multi_thread")]
async fn hostname_redirect_hops_are_allowlisted_resolved_and_pinned() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = destination.accept() {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let body = br#"{"type":"string"}"#;
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_port = redirector.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = redirector.accept() {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://localhost:{destination_port}/value.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let mut process = process_enabled(None);
    // This is a success-path DNS/redirect/pinning test, not a timeout test.
    // The shared helper's 100/200 ms budgets intentionally make negative
    // fixtures fast, but coverage instrumentation can consume a complete hop
    // budget while the blocking loader or localhost resolver is merely waiting
    // to be scheduled. Keep the live path bounded while giving instrumented CI
    // enough headroom; the dedicated deadline tests below retain tight budgets.
    process.connect_timeout = Duration::from_secs(2);
    process.request_timeout = Duration::from_secs(5);
    process.total_timeout = Duration::from_secs(10);
    process.allow_http_origins = vec![
        format!("http://127.0.0.1:{redirect_port}"),
        format!("http://localhost:{destination_port}"),
    ];
    let loaded = load_production_http(format!("http://127.0.0.1:{redirect_port}/start"), process)
        .await
        .expect("every redirect hop should be revalidated and hostname-pinned");
    assert_eq!(loaded.root, json!({"type": "string"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_origin_outside_policy_is_rejected() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://localhost:9/denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let mut process = process_enabled(None);
    process.allow_http_origins = vec![format!("http://127.0.0.1:{port}")];
    let error = load_production_http(format!("http://127.0.0.1:{port}/start"), process)
        .await
        .expect_err("redirect outside the explicit origin policy must fail");
    server.join().expect("redirect fixture thread");
    assert!(matches!(error, ExtractError::UnsupportedExternalRef { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_chunked_response_aborts_at_document_cap() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n0\r\n\r\n",
            );
        }
    });
    let mut process = process_enabled(None);
    process.max_document_bytes = 16;
    process.allow_http_origins = vec![format!("http://127.0.0.1:{port}")];
    let error = load_production_http(format!("http://127.0.0.1:{port}/large"), process)
        .await
        .expect_err("chunked body beyond cap must abort");
    assert!(matches!(error, ExtractError::SchemaTooLarge { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn response_content_type_allowlist_rejects_invalid_and_unsupported_headers() {
    for content_type in [
        b"application/xml".as_slice(),
        b"application/json\xff".as_slice(),
    ] {
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: ".to_vec();
        response.extend_from_slice(content_type);
        response.extend_from_slice(b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        let (port, server) = spawn_raw_http_response(response);
        let mut process = process_enabled(None);
        // The assertion is on the Content-Type refusal, not on timing: keep a
        // loaded runner from reporting a timeout in its place.
        process.connect_timeout = Duration::from_secs(2);
        process.request_timeout = Duration::from_secs(5);
        process.total_timeout = Duration::from_secs(10);
        process.allow_http_origins = vec![format!("http://127.0.0.1:{port}")];
        let error = load_production_http(format!("http://127.0.0.1:{port}/content-type"), process)
            .await
            .expect_err("present invalid or unsupported Content-Type must fail closed");
        server.join().expect("HTTP fixture thread");
        let rendered = error.to_string();
        assert!(
            rendered.contains(
                "external $ref response Content-Type is not an allowed OpenAPI media type"
            )
        );
        assert!(!rendered.contains("application/xml"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn absent_response_content_type_uses_bounded_format_detection() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"type\":\"string\"}"
            .to_vec();
    let (port, server) = spawn_raw_http_response(response);
    let mut process = process_enabled(None);
    // A success-path fixture, not a timeout test: the tight defaults report a
    // spurious request timeout on a loaded coverage runner.
    process.connect_timeout = Duration::from_secs(2);
    process.request_timeout = Duration::from_secs(5);
    process.total_timeout = Duration::from_secs(10);
    process.allow_http_origins = vec![format!("http://127.0.0.1:{port}")];
    let loaded = load_production_http(format!("http://127.0.0.1:{port}/no-content-type"), process)
        .await
        .expect("absent Content-Type may use bounded JSON/YAML detection");
    server.join().expect("HTTP fixture thread");
    assert_eq!(loaded.root, json!({"type": "string"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn total_deadline_covers_response_io() {
    let (port, stalled_rx, server) = spawn_stalled_http_peer();
    let mut process = process_enabled(None);
    process.request_timeout = Duration::from_secs(10);
    process.total_timeout = Duration::from_secs(1);
    process.allow_http_origins = vec![format!("http://127.0.0.1:{port}")];
    let uri = format!("http://127.0.0.1:{port}/slow");
    let (load_result, stalled_result) = tokio::join!(
        load_production_http(uri, process),
        tokio::task::spawn_blocking(move || {
            stalled_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("stalled fixture must deliver response-body I/O stream")
        }),
    );
    let error = load_result.expect_err("total timeout must cover request and response I/O");
    // Reclaim the stalled peer only after the client has fail-closed so the
    // partial response body covered the total deadline. Dropping the stream
    // here also finishes the fixture thread without waiting on FIN.
    let _stalled = stalled_result.expect("stalled fixture worker");
    server.join().expect("deadline fixture thread");
    assert!(error.to_string().contains("timed out") || error.to_string().contains("timeout"));
}

#[test]
fn policy_compose_intersects_origins() {
    let process = process_enabled(None);
    let ext = ExternalRefSpecExtension {
        enabled: true,
        document_base: None,
        allowed_origins: vec!["https://other.example.com".to_string()],
    };
    let err = EffectiveExternalRefPolicy::compose(&process, Some(&ext)).unwrap_err();
    assert!(
        matches!(err, ExtractError::MalformedExtension { .. }),
        "{err}"
    );
}

/// Tiny tempfile shim without adding a dependency if tempfile is absent.
mod tempfile {
    use std::path::{Path, PathBuf};

    pub struct TempDir {
        path: PathBuf,
    }

    pub fn tempdir() -> std::io::Result<TempDir> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ferrum-extref-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    impl TempDir {
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
