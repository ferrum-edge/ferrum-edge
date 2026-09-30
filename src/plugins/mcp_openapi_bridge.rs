//! OpenAPI bridge for `mcp_gateway` aggregate routing (issue #5906).
//!
//! A `servers.<id>` entry that carries an `openapi` block instead of an
//! `upstream_url` publishes one MCP tool per configured OpenAPI operation and
//! runs each `tools/call` as an ordinary HTTP request to THIS proxy's own
//! configured backend. The tools enter the same per-session catalog as tools
//! listed by an upstream MCP server, so policy (allow / deny / hide),
//! discovery, per-consumer grants, `inputSchema` argument validation, result
//! validation, and `mcp.*` metadata apply to them unchanged.
//!
//! Security contract, each part load bearing:
//!
//! * Execution goes ONLY to the proxy's configured backend through ordinary
//!   backend dispatch (upstreams, retries, circuit breaker, TLS,
//!   observability). The plugin never selects a host, scheme, or port for a
//!   bridged call, and a document's `servers[]` URLs are never dialed: the
//!   operation path is the proxy's public path, mapped onto the backend
//!   exactly as a direct client request to that path would be.
//! * Tool arguments can only fill the parameters the operation declares. A
//!   header parameter may never name a hop-by-hop, `Host`, `Authorization`,
//!   `Cookie`, `Proxy-*`, `X-Forwarded-*`, MCP-transport, or Ferrum-internal
//!   field; that is refused when the configuration is loaded and again when a
//!   call is built.
//! * Path parameters are percent-encoded one segment at a time and the
//!   assembled path must be a canonical policy path
//!   ([`crate::policy_path::canonicalize_policy_path`]), so an argument can
//!   never add a `/`, a dot segment, a `?`, or a `#`. Query values are
//!   `application/x-www-form-urlencoded`.
//! * Every quantity is bounded: operation count, per-tool schema size and
//!   depth, request body, response body, error excerpt, and
//!   `structuredContent`.
//!
//! Nothing here logs an argument, a header value, or a response body.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};

use crate::plugins::{BackendDispatchState, RequestContext};
use crate::proxy::headers::X_GATEWAY_ERROR_HEADER;
use crate::util::unknown_keys::reject_unknown_keys;

/// Maximum operations one `openapi` server block may publish as tools.
pub const MAX_BRIDGE_OPERATIONS: usize = 256;
/// Maximum serialized bytes of one generated MCP tool definition (its
/// `inputSchema`, `outputSchema`, description, and annotations together).
pub const MAX_BRIDGE_TOOL_DEFINITION_BYTES: usize = 256 * 1024;
/// Maximum parameters one operation may declare.
pub const MAX_BRIDGE_OPERATION_PARAMETERS: usize = 64;
/// Maximum byte length of a tool name, a parameter name, and an operation path.
const MAX_BRIDGE_NAME_BYTES: usize = 128;
const MAX_BRIDGE_PARAMETER_NAME_BYTES: usize = 256;
const MAX_BRIDGE_PATH_BYTES: usize = 2048;
const MAX_BRIDGE_TEXT_BYTES: usize = 8 * 1024;
/// Maximum byte length of one header or path argument value.
const MAX_BRIDGE_SCALAR_ARGUMENT_BYTES: usize = 8 * 1024;
/// Maximum values one array-typed query or header argument may carry.
const MAX_BRIDGE_ARRAY_ARGUMENT_ITEMS: usize = 256;

pub const DEFAULT_BRIDGE_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_BRIDGE_MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_BRIDGE_MAX_ERROR_EXCERPT_BYTES: usize = 2048;
pub const DEFAULT_BRIDGE_MAX_STRUCTURED_CONTENT_BYTES: usize = 256 * 1024;
const MAX_BRIDGE_BODY_LIMIT: usize = 16 * 1024 * 1024;
const MAX_BRIDGE_ERROR_EXCERPT_LIMIT: usize = 64 * 1024;

/// The `tools/call` argument that carries an operation's JSON request body.
pub const BRIDGE_BODY_ARGUMENT: &str = "body";

const OPENAPI_BRIDGE_KEYS: &[&str] = &[
    "forward_request_headers",
    "max_error_excerpt_bytes",
    "max_request_body_bytes",
    "max_response_body_bytes",
    "max_structured_content_bytes",
    "operations",
];
const OPERATION_KEYS: &[&str] = &[
    "annotations",
    "description",
    "method",
    "name",
    "output_schema",
    "parameters",
    "path",
    "request_body",
    "title",
];
const PARAMETER_KEYS: &[&str] = &["description", "in", "name", "required", "schema"];
const REQUEST_BODY_KEYS: &[&str] = &["description", "required", "schema"];
const ANNOTATION_KEYS: &[&str] = &[
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "readOnlyHint",
    "title",
];

/// Every byte outside RFC 3986 `pchar` is escaped. `pchar` itself is never
/// escaped, so any `%` in an encoded segment names a byte the canonical policy
/// path cannot carry, and the assembled path is then refused.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// Request header names a bridged call may never set from a tool argument:
/// framing and hop-by-hop fields, credentials, client-address attribution,
/// method and URL override families a backend framework may honor, range
/// requests (a partial response cannot become a tool result), trace context,
/// and MCP transport fields.
const RESERVED_BRIDGE_HEADER_NAMES: &[&str] = &[
    "accept",
    "accept-encoding",
    "authorization",
    "baggage",
    "cf-connecting-ip",
    "connection",
    "content-encoding",
    "content-length",
    "content-type",
    "cookie",
    "cookie2",
    "early-data",
    "expect",
    "forwarded",
    "host",
    "http2-settings",
    "if-range",
    "keep-alive",
    "last-event-id",
    "max-forwards",
    "range",
    "set-cookie",
    "te",
    "traceparent",
    "tracestate",
    "trailer",
    "transfer-encoding",
    "true-client-ip",
    "upgrade",
    "via",
    "x-client-ip",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
    "x-original-uri",
    "x-original-url",
    "x-real-ip",
    "x-rewrite-url",
];
/// Reserved header-name families: proxy control, forwarding identity, MCP
/// transport, fetch metadata, service-mesh control, and every Ferrum /
/// gateway-owned namespace.
const RESERVED_BRIDGE_HEADER_PREFIXES: &[&str] = &[
    "proxy-",
    "x-forwarded-",
    "x-ferrum-",
    "ferrum-",
    "x-gateway-",
    "x-consumer-",
    "x-path-param-",
    "mcp-",
    "sec-",
    "x-envoy-",
    "x-istio-",
    "l5d-",
];

/// Client request headers a bridged call forwards to the REST backend by
/// default. Everything else the MCP client sent (credentials, cookies,
/// conditional and range fields, method and URL override families, any
/// application header) is dropped: the MCP request is a JSON-RPC exchange
/// with the gateway, and only the tool arguments describe the REST call. The
/// gateway still adds its own forwarding, identity, and correlation headers at
/// dispatch, and `openapi.forward_request_headers` opts further names in.
const DEFAULT_FORWARDED_CLIENT_HEADERS: &[&str] =
    &["accept-language", "traceparent", "tracestate", "user-agent"];
/// Maximum names `openapi.forward_request_headers` may list.
const MAX_FORWARDED_REQUEST_HEADERS: usize = 32;

/// One header-name byte lower-cased with `_` folded to `-`, the spelling
/// every reserved-name comparison uses.
fn fold_header_byte(byte: u8) -> u8 {
    match byte {
        b'_' => b'-',
        other => other.to_ascii_lowercase(),
    }
}

fn normalized_header_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for byte in name.bytes() {
        normalized.push(char::from(fold_header_byte(byte)));
    }
    normalized
}

/// Whether two header names are the same field once `_` is folded to `-`,
/// ASCII case-insensitively.
pub(crate) fn bridge_header_names_match(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .all(|(a, b)| fold_header_byte(a) == fold_header_byte(b))
}

/// Whether a tool argument may never set request header `name`.
///
/// ASCII case-insensitive, with `_` treated as `-` so a backend that folds
/// underscores (nginx, CGI) cannot be reached through an alternate spelling.
/// Shared by plugin load, the `/api-specs` `x-ferrum-mcp` generator, and the
/// call path. The deployment-specific names (the configured
/// `FERRUM_REAL_IP_HEADER`, the MCP session headers, and the request's
/// `correlation_id` headers) are checked on top of this list by the plugin.
pub fn bridge_header_name_is_reserved(name: &str) -> bool {
    let normalized = normalized_header_name(name);
    RESERVED_BRIDGE_HEADER_NAMES.contains(&normalized.as_str())
        || RESERVED_BRIDGE_HEADER_PREFIXES
            .iter()
            .any(|prefix| normalized.starts_with(prefix))
        || crate::proxy::headers::is_gateway_assertion_header(&normalized)
        || crate::proxy::headers::is_backend_request_strip_header(&normalized)
}

/// Whether an `mcp_gateway` config declares at least one OpenAPI bridge server
/// (`servers.*.openapi`), which alone admits the larger generated-config size
/// and depth budget. A shape check only; the plugin validates the block.
pub fn config_declares_openapi_server(config: &Value) -> bool {
    config
        .get("servers")
        .and_then(Value::as_object)
        .is_some_and(|servers| {
            servers
                .values()
                .any(|server| server.get("openapi").is_some_and(Value::is_object))
        })
}

/// HTTP methods a bridged operation may use.
///
/// `HEAD`, `OPTIONS`, `TRACE`, and `CONNECT` are deliberately absent: the MCP
/// request is a `POST`, and the client response framing of a bridged call must
/// never depend on a backend method with body-less response semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl BridgeMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }

    /// The static wire token, so a dispatch override never allocates.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// MCP tool annotations implied by the method; explicit configuration
    /// overrides each hint.
    fn default_annotations(self) -> Map<String, Value> {
        let mut annotations = Map::new();
        match self {
            Self::Get => {
                annotations.insert("readOnlyHint".to_string(), Value::Bool(true));
            }
            Self::Delete => {
                annotations.insert("readOnlyHint".to_string(), Value::Bool(false));
                annotations.insert("destructiveHint".to_string(), Value::Bool(true));
            }
            Self::Put => {
                annotations.insert("readOnlyHint".to_string(), Value::Bool(false));
                annotations.insert("idempotentHint".to_string(), Value::Bool(true));
            }
            Self::Post | Self::Patch => {
                annotations.insert("readOnlyHint".to_string(), Value::Bool(false));
            }
        }
        annotations
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParameterLocation {
    Path,
    Query,
    Header,
}

impl ParameterLocation {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "path" => Some(Self::Path),
            "query" => Some(Self::Query),
            "header" => Some(Self::Header),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct BridgeParameter {
    name: String,
    location: ParameterLocation,
    required: bool,
}

#[derive(Debug, Clone)]
enum PathPart {
    Literal(String),
    Parameter(String),
}

/// One configured operation, precomputed at plugin load.
#[derive(Debug)]
pub struct BridgeOperation {
    name: String,
    method: BridgeMethod,
    path_parts: Vec<PathPart>,
    parameters: Vec<BridgeParameter>,
    /// `Some(required)` when the operation accepts a JSON request body.
    request_body: Option<bool>,
    /// `METHOD /path/{template}`: the `mcp.bridge.operation` metadata value.
    label: String,
    /// The MCP tool definition this operation publishes.
    tool: Value,
}

/// Response-side bounds of one bridge server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeResponseLimits {
    pub max_response_body_bytes: usize,
    pub max_error_excerpt_bytes: usize,
    pub max_structured_content_bytes: usize,
}

/// A parsed `servers.<id>.openapi` block.
#[derive(Debug)]
pub struct McpOpenApiBridge {
    operations: HashMap<String, BridgeOperation>,
    max_request_body_bytes: usize,
    limits: BridgeResponseLimits,
    /// Serialized bytes of every published tool definition, for the catalog
    /// byte budget.
    tool_definition_bytes: usize,
    /// Lower-cased client request headers forwarded to the backend on top of
    /// [`DEFAULT_FORWARDED_CLIENT_HEADERS`].
    forward_request_headers: Vec<String>,
}

/// The HTTP request one bridged `tools/call` becomes.
#[derive(Debug)]
pub struct BridgeRequest {
    pub method: BridgeMethod,
    /// The public request path (the proxy route the operation is served on).
    pub public_path: String,
    /// Encoded outbound query, empty when the call carries none.
    pub query: String,
    /// Last-wins view of `query` for the plugin-visible query map.
    pub query_params: HashMap<String, String>,
    /// Header parameters, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// JSON request body, `None` when the call sends no body.
    pub body: Option<Vec<u8>>,
}

/// Why a `tools/call` could not be turned into a backend request. The message
/// is fixed text naming the schema position, never an argument value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeArgumentError(String);

impl BridgeArgumentError {
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl McpOpenApiBridge {
    /// Parse and precompute one `openapi` server block.
    pub fn parse(value: &Value, server_id: &str) -> Result<Self, String> {
        let object = value.as_object().ok_or_else(|| {
            format!("mcp_gateway: server {server_id:?} `openapi` must be an object")
        })?;
        reject_unknown_keys(
            object,
            "config.servers.*.openapi",
            OPENAPI_BRIDGE_KEYS,
            "mcp_gateway: `config.servers.*.openapi`: ",
        )?;
        let max_request_body_bytes = bounded_limit(
            object,
            "max_request_body_bytes",
            DEFAULT_BRIDGE_MAX_REQUEST_BODY_BYTES,
            MAX_BRIDGE_BODY_LIMIT,
        )?;
        let limits = BridgeResponseLimits {
            max_response_body_bytes: bounded_limit(
                object,
                "max_response_body_bytes",
                DEFAULT_BRIDGE_MAX_RESPONSE_BODY_BYTES,
                MAX_BRIDGE_BODY_LIMIT,
            )?,
            max_error_excerpt_bytes: bounded_limit(
                object,
                "max_error_excerpt_bytes",
                DEFAULT_BRIDGE_MAX_ERROR_EXCERPT_BYTES,
                MAX_BRIDGE_ERROR_EXCERPT_LIMIT,
            )?,
            max_structured_content_bytes: bounded_limit(
                object,
                "max_structured_content_bytes",
                DEFAULT_BRIDGE_MAX_STRUCTURED_CONTENT_BYTES,
                MAX_BRIDGE_BODY_LIMIT,
            )?,
        };
        let forward_request_headers = parse_forward_request_headers(object)?;
        let Some(operations) = object.get("operations").and_then(Value::as_array) else {
            return Err(format!(
                "mcp_gateway: server {server_id:?} `openapi.operations` must be a non-empty array"
            ));
        };
        if operations.is_empty() {
            return Err(format!(
                "mcp_gateway: server {server_id:?} `openapi.operations` must be a non-empty array"
            ));
        }
        if operations.len() > MAX_BRIDGE_OPERATIONS {
            return Err(format!(
                "mcp_gateway: server {server_id:?} `openapi.operations` must not have more than {MAX_BRIDGE_OPERATIONS} entries"
            ));
        }
        let mut parsed = HashMap::with_capacity(operations.len());
        let mut tool_definition_bytes = 0usize;
        for (index, operation) in operations.iter().enumerate() {
            let operation = parse_operation(operation, index)?;
            let Ok(serialized) = serde_json::to_vec(&operation.tool) else {
                return Err(format!(
                    "mcp_gateway: `openapi.operations[{index}]` tool definition could not be serialized"
                ));
            };
            let bytes = serialized.len();
            if bytes > MAX_BRIDGE_TOOL_DEFINITION_BYTES {
                return Err(format!(
                    "mcp_gateway: `openapi.operations[{index}]` tool definition must not exceed {MAX_BRIDGE_TOOL_DEFINITION_BYTES} bytes"
                ));
            }
            tool_definition_bytes = tool_definition_bytes.saturating_add(bytes);
            if parsed.contains_key(&operation.name) {
                return Err(format!(
                    "mcp_gateway: `openapi.operations[{index}].name` duplicates an earlier operation name {name:?}",
                    name = operation.name
                ));
            }
            parsed.insert(operation.name.clone(), operation);
        }
        Ok(Self {
            operations: parsed,
            max_request_body_bytes,
            limits,
            tool_definition_bytes,
            forward_request_headers,
        })
    }

    /// Every published operation name with its MCP tool definition, in the
    /// shape an upstream `tools/list` page carries, so catalog construction
    /// treats them exactly like discovered tools.
    pub fn tools(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.operations
            .iter()
            .map(|(name, operation)| (name.as_str(), &operation.tool))
    }

    /// Whether a client request header reaches the REST backend of a bridged
    /// call: the fixed default set, or a name the operator listed in
    /// `openapi.forward_request_headers`.
    pub fn forwards_client_header(&self, name: &str) -> bool {
        DEFAULT_FORWARDED_CLIENT_HEADERS
            .iter()
            .any(|forwarded| forwarded.eq_ignore_ascii_case(name))
            || self
                .forward_request_headers
                .iter()
                .any(|forwarded| bridge_header_names_match(forwarded, name))
    }

    /// Operator-listed forwarded client headers, for the configuration
    /// cross-check against the deployment's own reserved names.
    pub fn forwarded_header_names(&self) -> impl Iterator<Item = &str> {
        self.forward_request_headers.iter().map(String::as_str)
    }

    pub fn tool_count(&self) -> usize {
        self.operations.len()
    }

    pub fn tool_definition_bytes(&self) -> usize {
        self.tool_definition_bytes
    }

    pub fn operation(&self, name: &str) -> Option<&BridgeOperation> {
        self.operations.get(name)
    }

    pub fn limits(&self) -> BridgeResponseLimits {
        self.limits
    }

    /// Header parameter names across every operation, for the configuration
    /// cross-check against the gateway's own session header names.
    pub fn header_parameter_names(&self) -> impl Iterator<Item = &str> {
        self.operations.values().flat_map(|operation| {
            operation
                .parameters
                .iter()
                .filter(|parameter| parameter.location == ParameterLocation::Header)
                .map(|parameter| parameter.name.as_str())
        })
    }

    pub fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes
    }
}

impl BridgeOperation {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn method(&self) -> BridgeMethod {
        self.method
    }

    /// Build the backend request for validated `tools/call` arguments.
    ///
    /// Arguments outside the declared parameter set are refused whether or not
    /// `validation.validate_tool_arguments` ran, because they have no defined
    /// place on the wire. `deployment_reserved` names the header fields this
    /// deployment reserves on top of [`bridge_header_name_is_reserved`].
    pub fn build_request(
        &self,
        arguments: Option<&Value>,
        max_request_body_bytes: usize,
        deployment_reserved: impl Fn(&str) -> bool,
    ) -> Result<BridgeRequest, BridgeArgumentError> {
        let empty = Map::new();
        let arguments = match arguments {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return Err(argument_error("`arguments` must be an object")),
        };
        for key in arguments.keys() {
            let known = (key == BRIDGE_BODY_ARGUMENT && self.request_body.is_some())
                || self
                    .parameters
                    .iter()
                    .any(|parameter| parameter.name == *key);
            if !known {
                return Err(argument_error(
                    "`arguments` carries a property the operation does not declare",
                ));
            }
        }

        let mut public_path = String::new();
        for part in &self.path_parts {
            match part {
                PathPart::Literal(literal) => public_path.push_str(literal),
                PathPart::Parameter(name) => {
                    let value = arguments
                        .get(name)
                        .filter(|value| !value.is_null())
                        .ok_or_else(|| argument_error("a required path parameter is missing"))?;
                    let text = scalar_argument_text(value)
                        .ok_or_else(|| argument_error("a path parameter must be a scalar"))?;
                    if text.is_empty() || text.len() > MAX_BRIDGE_SCALAR_ARGUMENT_BYTES {
                        return Err(argument_error(
                            "a path parameter must be non-empty and within the byte bound",
                        ));
                    }
                    if text == "." || text == ".." {
                        return Err(argument_error("a path parameter must not be a dot segment"));
                    }
                    // `;` starts RFC 3986 path-segment parameters. Servlet
                    // containers (Tomcat, Jetty, Spring) strip them before
                    // resolving dot segments, so `..;` would climb a segment
                    // there while the gateway reads one opaque segment. The
                    // bridge does not serialize matrix-style parameters, so a
                    // `;` in a path argument has no legitimate meaning.
                    if text.contains(';') {
                        return Err(argument_error("a path parameter must not carry `;`"));
                    }
                    public_path.extend(utf8_percent_encode(&text, PATH_SEGMENT_ENCODE_SET));
                }
            }
        }
        // The assembled path must already be canonical: an escape means a
        // path argument carried a byte (`/`, `?`, `#`, `%`, whitespace, a
        // control, non-ASCII, ...) the gateway's single policy/backend path
        // coordinate cannot represent, and a dot segment would be resolved
        // differently by the backend URL parser.
        if !matches!(
            crate::policy_path::canonicalize_policy_path(&public_path),
            Ok(std::borrow::Cow::Borrowed(_))
        ) {
            return Err(argument_error(
                "a path parameter carries characters that cannot be forwarded in a path segment",
            ));
        }

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        let mut query_params = HashMap::new();
        let mut headers = Vec::new();
        for parameter in &self.parameters {
            let value = arguments
                .get(&parameter.name)
                .filter(|value| !value.is_null());
            let Some(value) = value else {
                if parameter.required && parameter.location != ParameterLocation::Path {
                    return Err(argument_error("a required parameter is missing"));
                }
                continue;
            };
            match parameter.location {
                ParameterLocation::Path => {}
                ParameterLocation::Query => {
                    for text in scalar_or_array_texts(value)? {
                        query.append_pair(&parameter.name, &text);
                        query_params.insert(parameter.name.clone(), text);
                    }
                }
                ParameterLocation::Header => {
                    // Refused at load too; re-checked here so a configuration
                    // path that skipped load validation can still never set a
                    // reserved field.
                    if bridge_header_name_is_reserved(&parameter.name)
                        || deployment_reserved(&parameter.name)
                    {
                        return Err(argument_error(
                            "a header parameter names a reserved request header",
                        ));
                    }
                    let joined = scalar_or_array_texts(value)?.join(",");
                    if joined.len() > MAX_BRIDGE_SCALAR_ARGUMENT_BYTES
                        || http::HeaderValue::from_str(&joined).is_err()
                    {
                        return Err(argument_error(
                            "a header parameter value is not a valid bounded header value",
                        ));
                    }
                    headers.push((parameter.name.to_ascii_lowercase(), joined));
                }
            }
        }
        let query = query.finish();

        let body = match (self.request_body, arguments.get(BRIDGE_BODY_ARGUMENT)) {
            (Some(_), Some(body)) if !body.is_null() => {
                let bytes = serde_json::to_vec(body)
                    .map_err(|_| argument_error("the request body could not be serialized"))?;
                if bytes.len() > max_request_body_bytes {
                    return Err(argument_error(
                        "the request body exceeds `openapi.max_request_body_bytes`",
                    ));
                }
                Some(bytes)
            }
            (Some(true), _) => return Err(argument_error("the required request body is missing")),
            _ => None,
        };

        Ok(BridgeRequest {
            method: self.method,
            public_path,
            query,
            query_params,
            headers,
            body,
        })
    }
}

fn argument_error(reason: &str) -> BridgeArgumentError {
    BridgeArgumentError(format!("Invalid MCP tool arguments: {reason}"))
}

/// Text of a scalar JSON argument, `None` for an array or object.
fn scalar_argument_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

const SCALAR_ARGUMENT_REASON: &str =
    "a query or header parameter must be a scalar or an array of scalars";

/// A scalar as one value, or an array of scalars as its members (OpenAPI
/// `form` / `simple` styles with the default `explode`).
fn scalar_or_array_texts(value: &Value) -> Result<Vec<String>, BridgeArgumentError> {
    if let Some(text) = scalar_argument_text(value) {
        return Ok(vec![text]);
    }
    let Some(items) = value.as_array() else {
        return Err(argument_error(SCALAR_ARGUMENT_REASON));
    };
    if items.len() > MAX_BRIDGE_ARRAY_ARGUMENT_ITEMS {
        return Err(argument_error("an array parameter exceeds the item bound"));
    }
    let mut texts = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = scalar_argument_text(item) else {
            return Err(argument_error(SCALAR_ARGUMENT_REASON));
        };
        texts.push(text);
    }
    Ok(texts)
}

/// `openapi.forward_request_headers`: valid header names, at most
/// [`MAX_FORWARDED_REQUEST_HEADERS`], none of them reserved.
fn parse_forward_request_headers(object: &Map<String, Value>) -> Result<Vec<String>, String> {
    let items = match object.get("forward_request_headers") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(
                "mcp_gateway: `openapi.forward_request_headers` must be an array of header names"
                    .to_string(),
            );
        }
    };
    if items.len() > MAX_FORWARDED_REQUEST_HEADERS {
        return Err(format!(
            "mcp_gateway: `openapi.forward_request_headers` must not list more than {MAX_FORWARDED_REQUEST_HEADERS} names"
        ));
    }
    let mut names = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let valid = item
            .as_str()
            .filter(|name| http::HeaderName::from_bytes(name.as_bytes()).is_ok());
        let Some(name) = valid else {
            return Err(format!(
                "mcp_gateway: `openapi.forward_request_headers[{index}]` must be a valid HTTP header name"
            ));
        };
        if bridge_header_name_is_reserved(name) {
            return Err(format!(
                "mcp_gateway: `openapi.forward_request_headers[{index}]` names a reserved request header (hop-by-hop, Host, Authorization, Cookie, Range, a method or URL override, trace context, MCP transport, or a Ferrum-internal field) that a bridged call never forwards"
            ));
        }
        names.push(name.to_ascii_lowercase());
    }
    Ok(names)
}

fn bounded_limit(
    object: &Map<String, Value>,
    key: &str,
    default: usize,
    ceiling: usize,
) -> Result<usize, String> {
    let Some(value) = object.get(key).filter(|value| !value.is_null()) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("mcp_gateway: `openapi.{key}` must be a positive integer"))?;
    if value == 0 || value > ceiling {
        return Err(format!(
            "mcp_gateway: `openapi.{key}` must be between 1 and {ceiling}"
        ));
    }
    Ok(value)
}

fn optional_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    position: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= MAX_BRIDGE_TEXT_BYTES => Ok(Some(text)),
        Some(Value::String(_)) => Err(format!(
            "mcp_gateway: `{position}.{key}` must not exceed {MAX_BRIDGE_TEXT_BYTES} bytes"
        )),
        Some(_) => Err(format!("mcp_gateway: `{position}.{key}` must be a string")),
    }
}

fn optional_flag(object: &Map<String, Value>, key: &str, position: &str) -> Result<bool, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(format!("mcp_gateway: `{position}.{key}` must be a boolean")),
    }
}

/// Whether a tool name is a valid MCP tool name (1-128 of `A-Za-z0-9_.-`).
pub fn is_valid_bridge_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_BRIDGE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Split a path template into literal runs and `{parameter}` segments. A
/// parameter must occupy a whole segment, so an argument can never merge
/// into a literal and change how the path splits.
fn parse_path_template(path: &str, position: &str) -> Result<Vec<PathPart>, String> {
    if path.is_empty() || !path.starts_with('/') || path.len() > MAX_BRIDGE_PATH_BYTES {
        return Err(format!(
            "mcp_gateway: `{position}.path` must be a non-empty path starting with `/` and at most {MAX_BRIDGE_PATH_BYTES} bytes"
        ));
    }
    if path.contains(['?', '#']) {
        return Err(format!(
            "mcp_gateway: `{position}.path` must not carry a query or fragment"
        ));
    }
    let mut parts = Vec::new();
    let mut literal = String::new();
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            literal.push('/');
        }
        if let Some(inner) = segment
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            if inner.is_empty() || inner.contains(['{', '}']) {
                return Err(format!(
                    "mcp_gateway: `{position}.path` has an empty or nested `{{}}` template expression"
                ));
            }
            if !literal.is_empty() {
                parts.push(PathPart::Literal(std::mem::take(&mut literal)));
            }
            parts.push(PathPart::Parameter(inner.to_string()));
            continue;
        }
        if segment.contains(['{', '}']) {
            return Err(format!(
                "mcp_gateway: `{position}.path` template expressions must occupy a whole path segment"
            ));
        }
        literal.push_str(segment);
    }
    if !literal.is_empty() {
        parts.push(PathPart::Literal(literal));
    }
    // The literal skeleton must itself be canonical: a stray escape, a dot
    // segment, or a backslash in the configured path is a configuration error,
    // not something a call can repair.
    let skeleton: String = parts
        .iter()
        .map(|part| match part {
            PathPart::Literal(literal) => literal.as_str(),
            PathPart::Parameter(_) => "p",
        })
        .collect();
    if let Some(reason) = crate::policy_path::non_canonical_policy_path_reason(&skeleton) {
        return Err(format!(
            "mcp_gateway: `{position}.path` is not canonical: {reason}"
        ));
    }
    Ok(parts)
}

fn parse_operation(value: &Value, index: usize) -> Result<BridgeOperation, String> {
    let position = format!("openapi.operations[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| format!("mcp_gateway: `{position}` must be an object"))?;
    reject_unknown_keys(
        object,
        "config.servers.*.openapi.operations[*]",
        OPERATION_KEYS,
        &format!("mcp_gateway: `{position}`: "),
    )?;
    let name = optional_text(object, "name", &position)?
        .ok_or_else(|| format!("mcp_gateway: `{position}.name` is required"))?;
    if !is_valid_bridge_tool_name(name) {
        return Err(format!(
            "mcp_gateway: `{position}.name` must be 1-{MAX_BRIDGE_NAME_BYTES} characters of `A-Za-z0-9_.-`"
        ));
    }
    let method_text = optional_text(object, "method", &position)?
        .ok_or_else(|| format!("mcp_gateway: `{position}.method` is required"))?;
    // The configured spelling is the wire token, so it must be upper case.
    let method = BridgeMethod::parse(method_text).filter(|method| method.as_str() == method_text);
    let Some(method) = method else {
        return Err(format!(
            "mcp_gateway: `{position}.method` must be `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`"
        ));
    };
    let path = optional_text(object, "path", &position)?
        .ok_or_else(|| format!("mcp_gateway: `{position}.path` is required"))?;
    let path_parts = parse_path_template(path, &position)?;
    let template_parameters: Vec<&str> = path_parts
        .iter()
        .filter_map(|part| match part {
            PathPart::Parameter(name) => Some(name.as_str()),
            PathPart::Literal(_) => None,
        })
        .collect();

    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut parameters = Vec::new();
    let mut seen_names = HashSet::new();
    let declared = match object.get("parameters") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) => items.as_slice(),
        Some(_) => {
            return Err(format!(
                "mcp_gateway: `{position}.parameters` must be an array"
            ));
        }
    };
    if declared.len() > MAX_BRIDGE_OPERATION_PARAMETERS {
        return Err(format!(
            "mcp_gateway: `{position}.parameters` must not have more than {MAX_BRIDGE_OPERATION_PARAMETERS} entries"
        ));
    }
    for (parameter_index, parameter) in declared.iter().enumerate() {
        let parameter_position = format!("{position}.parameters[{parameter_index}]");
        let parameter_object = parameter
            .as_object()
            .ok_or_else(|| format!("mcp_gateway: `{parameter_position}` must be an object"))?;
        reject_unknown_keys(
            parameter_object,
            "config.servers.*.openapi.operations[*].parameters[*]",
            PARAMETER_KEYS,
            &format!("mcp_gateway: `{parameter_position}`: "),
        )?;
        let parameter_name = optional_text(parameter_object, "name", &parameter_position)?
            .ok_or_else(|| format!("mcp_gateway: `{parameter_position}.name` is required"))?;
        if parameter_name.is_empty() || parameter_name.len() > MAX_BRIDGE_PARAMETER_NAME_BYTES {
            return Err(format!(
                "mcp_gateway: `{parameter_position}.name` must be 1-{MAX_BRIDGE_PARAMETER_NAME_BYTES} bytes"
            ));
        }
        let location = optional_text(parameter_object, "in", &parameter_position)?
            .and_then(ParameterLocation::parse);
        let Some(location) = location else {
            return Err(format!(
                "mcp_gateway: `{parameter_position}.in` must be `path`, `query`, or `header`"
            ));
        };
        if parameter_name == BRIDGE_BODY_ARGUMENT || !seen_names.insert(parameter_name) {
            return Err(format!(
                "mcp_gateway: `{parameter_position}.name` collides with another argument of this operation (parameter names share one argument object with `body`)"
            ));
        }
        let mut is_required = optional_flag(parameter_object, "required", &parameter_position)?;
        match location {
            ParameterLocation::Path => {
                if !template_parameters.contains(&parameter_name) {
                    return Err(format!(
                        "mcp_gateway: `{parameter_position}` is a path parameter that `{position}.path` does not template"
                    ));
                }
                is_required = true;
            }
            ParameterLocation::Header => {
                if http::HeaderName::from_bytes(parameter_name.as_bytes()).is_err() {
                    return Err(format!(
                        "mcp_gateway: `{parameter_position}.name` must be a valid HTTP header name"
                    ));
                }
                if bridge_header_name_is_reserved(parameter_name) {
                    return Err(format!(
                        "mcp_gateway: `{parameter_position}.name` names a reserved request header (hop-by-hop, Host, Authorization, Cookie, Proxy-*, X-Forwarded-*, MCP transport, or a Ferrum-internal field) that a tool argument may never set"
                    ));
                }
            }
            ParameterLocation::Query => {}
        }
        let mut schema = parameter_schema(parameter_object, &parameter_position, location)?;
        describe_schema(
            &mut schema,
            optional_text(parameter_object, "description", &parameter_position)?,
        );
        properties.insert(parameter_name.to_string(), schema);
        if is_required {
            required.push(Value::String(parameter_name.to_string()));
        }
        parameters.push(BridgeParameter {
            name: parameter_name.to_string(),
            location,
            required: is_required,
        });
    }
    for template_parameter in &template_parameters {
        let declared = parameters.iter().any(|parameter| {
            parameter.location == ParameterLocation::Path && parameter.name == *template_parameter
        });
        if !declared {
            return Err(format!(
                "mcp_gateway: `{position}.path` templates a parameter that `{position}.parameters` does not declare with `in: path`"
            ));
        }
    }

    let request_body = match object.get("request_body") {
        None | Some(Value::Null) => None,
        Some(Value::Object(body)) => {
            let body_position = format!("{position}.request_body");
            reject_unknown_keys(
                body,
                "config.servers.*.openapi.operations[*].request_body",
                REQUEST_BODY_KEYS,
                &format!("mcp_gateway: `{body_position}`: "),
            )?;
            let body_required = optional_flag(body, "required", &body_position)?;
            let mut schema = match body.get("schema") {
                Some(schema @ (Value::Object(_) | Value::Bool(_))) => schema.clone(),
                None | Some(Value::Null) => json!({}),
                Some(_) => {
                    return Err(format!(
                        "mcp_gateway: `{body_position}.schema` must be a JSON Schema object"
                    ));
                }
            };
            describe_schema(
                &mut schema,
                optional_text(body, "description", &body_position)?,
            );
            properties.insert(BRIDGE_BODY_ARGUMENT.to_string(), schema);
            if body_required {
                required.push(Value::String(BRIDGE_BODY_ARGUMENT.to_string()));
            }
            Some(body_required)
        }
        Some(_) => {
            return Err(format!(
                "mcp_gateway: `{position}.request_body` must be an object"
            ));
        }
    };

    let mut input_schema = Map::new();
    input_schema.insert("type".to_string(), Value::String("object".to_string()));
    input_schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        input_schema.insert("required".to_string(), Value::Array(required));
    }
    input_schema.insert("additionalProperties".to_string(), Value::Bool(false));
    let input_schema = Value::Object(input_schema);
    super::mcp_gateway::audit_bridge_tool_schema(&input_schema)
        .map_err(|reason| format!("mcp_gateway: `{position}` inputSchema: {reason}"))?;
    if jsonschema::validator_for(&input_schema).is_err() {
        return Err(format!(
            "mcp_gateway: `{position}` produces an inputSchema that is not a valid JSON Schema"
        ));
    }

    let output_schema = match object.get("output_schema") {
        None | Some(Value::Null) => None,
        Some(schema @ Value::Object(_)) => {
            super::mcp_gateway::compile_tool_output_schema(schema)
                .map_err(|reason| format!("mcp_gateway: `{position}.output_schema`: {reason}"))?;
            // MCP requires an object-typed outputSchema: structuredContent is
            // a JSON object.
            if schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(format!(
                    "mcp_gateway: `{position}.output_schema` must declare `type: object`"
                ));
            }
            Some(schema.clone())
        }
        Some(_) => {
            return Err(format!(
                "mcp_gateway: `{position}.output_schema` must be a JSON Schema object"
            ));
        }
    };

    let mut annotations = method.default_annotations();
    if let Some(configured) = object.get("annotations").filter(|value| !value.is_null()) {
        let configured = configured
            .as_object()
            .ok_or_else(|| format!("mcp_gateway: `{position}.annotations` must be an object"))?;
        reject_unknown_keys(
            configured,
            "config.servers.*.openapi.operations[*].annotations",
            ANNOTATION_KEYS,
            &format!("mcp_gateway: `{position}.annotations`: "),
        )?;
        for (key, value) in configured {
            let valid = if key == "title" {
                value
                    .as_str()
                    .is_some_and(|title| title.len() <= MAX_BRIDGE_TEXT_BYTES)
            } else {
                value.is_boolean()
            };
            if !valid {
                return Err(format!(
                    "mcp_gateway: `{position}.annotations.{key}` has the wrong type"
                ));
            }
            annotations.insert(key.clone(), value.clone());
        }
    }

    let mut tool = Map::new();
    tool.insert("name".to_string(), Value::String(name.to_string()));
    if let Some(title) = optional_text(object, "title", &position)? {
        tool.insert("title".to_string(), Value::String(title.to_string()));
    }
    if let Some(description) = optional_text(object, "description", &position)? {
        tool.insert(
            "description".to_string(),
            Value::String(description.to_string()),
        );
    }
    tool.insert("inputSchema".to_string(), input_schema);
    if let Some(output_schema) = output_schema {
        tool.insert("outputSchema".to_string(), output_schema);
    }
    tool.insert("annotations".to_string(), Value::Object(annotations));

    Ok(BridgeOperation {
        name: name.to_string(),
        method,
        path_parts,
        parameters,
        request_body,
        label: format!("{} {path}", method.as_str()),
        tool: Value::Object(tool),
    })
}

/// Fold an OpenAPI `description` into a schema that does not carry its own, so
/// the agent reading `inputSchema` sees it.
fn describe_schema(schema: &mut Value, description: Option<&str>) {
    if let (Some(description), Some(object)) = (description, schema.as_object_mut()) {
        object
            .entry("description")
            .or_insert_with(|| Value::String(description.to_string()));
    }
}

/// A parameter's JSON Schema, refusing shapes the bridge cannot serialize
/// onto the wire (an object anywhere, or an array in a path segment).
fn parameter_schema(
    object: &Map<String, Value>,
    position: &str,
    location: ParameterLocation,
) -> Result<Value, String> {
    let schema = match object.get("schema") {
        None | Some(Value::Null) => json!({"type": "string"}),
        Some(schema @ Value::Object(_)) => schema.clone(),
        Some(_) => {
            return Err(format!(
                "mcp_gateway: `{position}.schema` must be a JSON Schema object"
            ));
        }
    };
    let types: Vec<&str> = match schema.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if types.contains(&"object") {
        return Err(format!(
            "mcp_gateway: `{position}.schema` is an object; only scalar (and, outside the path, array-of-scalar) parameters can be serialized"
        ));
    }
    if location == ParameterLocation::Path && types.contains(&"array") {
        return Err(format!(
            "mcp_gateway: `{position}.schema` is an array; path parameters must be scalars"
        ));
    }
    let item_type = schema
        .get("items")
        .and_then(|items| items.get("type"))
        .and_then(Value::as_str);
    if item_type.is_some_and(|kind| matches!(kind, "object" | "array")) {
        return Err(format!(
            "mcp_gateway: `{position}.schema.items` must be a scalar schema"
        ));
    }
    Ok(schema)
}

// ---------------------------------------------------------------------------
// Request-scoped claim and response conversion
// ---------------------------------------------------------------------------

/// What one `mcp_gateway` instance committed a bridged `tools/call` to.
///
/// Private and typed: forgeable `mcp.*` metadata can neither create, change,
/// nor clear it. Re-checked over the FINAL backend-visible request so a later
/// transform cannot change the method, path, query, or body the bridge built.
/// `Debug` never renders the query, the header values, or the body.
pub struct McpBridgeClaim {
    pub(crate) owner: u64,
    pub(crate) method: BridgeMethod,
    /// The operation's public request path, before listen-path mapping.
    pub(crate) public_path: String,
    pub(crate) backend_path: String,
    pub(crate) query: String,
    /// Header parameters the call set, lower-cased names.
    pub(crate) headers: Vec<(String, String)>,
    /// The JSON body built from the admitted arguments, empty for none.
    pub(crate) body: Vec<u8>,
    pub(crate) limits: BridgeResponseLimits,
    /// SHA-256 of the JSON-RPC envelope the call was admitted from.
    pub(crate) envelope_digest: [u8; 32],
    /// What the request-body transform did to the admitted call, set at most
    /// once. Interior so the H1/H2 hook-context clone shares it through the
    /// `Arc`, exactly like the admission record's drift latch.
    pub(crate) transformed: OnceLock<BridgeTransformOutcome>,
    /// What a transformed envelope must still name, and what rebuilds the
    /// REST call from it.
    pub(crate) rebuild: BridgeRebuildContext,
}

/// The admitted identity a transformed envelope must still carry, plus the
/// operation and the pinned validator that rebuild the REST call from it.
pub(crate) struct BridgeRebuildContext {
    pub(crate) bridge: Arc<McpOpenApiBridge>,
    pub(crate) operation: String,
    pub(crate) public_tool_name: String,
    pub(crate) request_id: Option<Value>,
    /// The admitted tool's `inputSchema` validator, when
    /// `validation.validate_tool_arguments` is on.
    pub(crate) input_validator: Option<Arc<jsonschema::Validator>>,
}

/// What the request-body transform decided for a bridged call whose
/// JSON-RPC envelope an earlier transform changed.
#[derive(Debug)]
pub(crate) enum BridgeTransformOutcome {
    /// Only the tool's JSON body changed (for example a prompt-guard
    /// redaction): the REST body rebuilt from the transformed envelope, whose
    /// arguments were validated again.
    Rebuilt(Vec<u8>),
    /// The transformed envelope no longer describes the admitted call. The
    /// final request-body hook refuses the request with this reason.
    Refused(&'static str),
}

impl McpBridgeClaim {
    /// The REST body the backend must receive once request-body transforms
    /// ran, or the refusal reason a transform latched.
    pub(crate) fn expected_body(&self) -> Result<&[u8], &'static str> {
        match self.transformed.get() {
            None => Ok(&self.body),
            Some(BridgeTransformOutcome::Rebuilt(body)) => Ok(body),
            Some(BridgeTransformOutcome::Refused(reason)) => Err(reason),
        }
    }
}

impl std::fmt::Debug for McpBridgeClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpBridgeClaim")
            .field("owner", &self.owner)
            .field("method", &self.method.as_str())
            .field("operation", &self.rebuild.operation)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Where a bridged call's response came from, read from the typed
/// backend-dispatch record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeResponseOrigin {
    /// The backend answered: the status and body are its own.
    Backend,
    /// The gateway authored the response (a failed dispatch, an open circuit
    /// breaker, overload, a stale configuration): there is no backend body.
    Gateway,
}

/// The backend response a bridged call received, recorded in `after_proxy`.
#[derive(Debug, Clone)]
pub struct BridgeObservedResponse {
    pub(crate) status: u16,
    /// The backend's own `Content-Type`, before the gateway relabels the
    /// client-visible representation as JSON.
    pub(crate) content_type: Option<String>,
    /// Fixed low-cardinality gateway-error class for a gateway or backend
    /// failure, derived from the dispatch outcome, never a backend string.
    pub(crate) gateway_error: Option<&'static str>,
}

/// Request-scoped bridge state on [`crate::plugins::RequestContext`].
#[derive(Clone)]
pub struct McpBridgeState {
    pub(crate) claim: Arc<McpBridgeClaim>,
    pub(crate) response: Option<BridgeObservedResponse>,
    /// Set once the normalize phase produced the JSON-RPC representation.
    pub(crate) converted: bool,
}

impl std::fmt::Debug for McpBridgeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpBridgeState")
            .field("claim", &self.claim)
            .field("response_status", &self.response.as_ref().map(|r| r.status))
            .field("converted", &self.converted)
            .finish()
    }
}

impl McpBridgeState {
    pub(crate) fn new(claim: Arc<McpBridgeClaim>) -> Self {
        Self {
            claim,
            response: None,
            converted: false,
        }
    }
}

/// Gateway-error classes a gateway-authored rejection may carry; anything
/// else is ignored rather than reflected.
const KNOWN_GATEWAY_ERROR_CLASSES: &[&str] = &[
    crate::retry::OBS_CONNECTION_FAILURE,
    crate::retry::OBS_BACKEND_TIMEOUT,
    crate::retry::OBS_BACKEND_ERROR,
    crate::retry::OBS_CIRCUIT_BREAKER_OPEN,
    crate::retry::OBS_OVERLOAD,
    crate::retry::OBS_CONFIG_STALE,
    crate::retry::OBS_CONCURRENCY_LIMIT,
    crate::retry::OBS_REQUEST_TIMEOUT,
];

/// The class a gateway rejection stamped on its own response. Read only when
/// nothing was dispatched, so no backend can have supplied the header.
fn stamped_gateway_error_class(headers: &HashMap<String, String>) -> Option<&'static str> {
    let value = header_value(headers, X_GATEWAY_ERROR_HEADER)?.trim();
    KNOWN_GATEWAY_ERROR_CLASSES
        .iter()
        .copied()
        .find(|class| class.eq_ignore_ascii_case(value))
}

/// The gateway-error class and the origin of a bridged response, from the
/// typed backend-dispatch record rather than a response header: a backend can
/// send `X-Gateway-Error` itself, so its presence on a backend response
/// proves nothing and is never read.
pub(crate) fn bridge_response_provenance(
    ctx: &RequestContext,
    status: u16,
    headers: &HashMap<String, String>,
) -> (Option<&'static str>, BridgeResponseOrigin) {
    match ctx.backend_dispatch_state() {
        BackendDispatchState::BackendResponse => (
            crate::proxy::x_gateway_error_for_response(ctx, false, status),
            BridgeResponseOrigin::Backend,
        ),
        BackendDispatchState::PreWireFailure => (
            crate::proxy::x_gateway_error_for_response(ctx, true, status),
            BridgeResponseOrigin::Gateway,
        ),
        BackendDispatchState::AmbiguousFailure => (
            crate::proxy::x_gateway_error_for_response(ctx, false, status),
            BridgeResponseOrigin::Gateway,
        ),
        // Nothing was dispatched, so no backend authored this response: it is
        // a gateway rejection (open breaker, overload, a stale configuration,
        // a concurrency limit) and its own stamped class is authoritative.
        BackendDispatchState::NotDispatched => (
            stamped_gateway_error_class(headers),
            BridgeResponseOrigin::Gateway,
        ),
    }
}

fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type.map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or(value)
            .trim()
            .to_ascii_lowercase()
    })
}

fn media_type_is_json(media_type: &str) -> bool {
    media_type == "application/json"
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix == "json")
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    })
}

/// A result whose backend body is not returned, saying why. A 2xx stays
/// `isError: false`: the operation ran, and reporting its representation as
/// a failure would invite an agent to retry a call that may not be
/// idempotent.
fn omitted_body_result(line: &str, reason: &str, is_error: bool) -> Value {
    text_result(
        format!("{line}: {reason}; the response body was omitted"),
        is_error,
    )
}

fn status_line(status: u16, gateway_error: Option<&str>) -> String {
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("");
    let mut line = format!("HTTP {status}");
    if !reason.is_empty() {
        line.push(' ');
        line.push_str(reason);
    }
    if let Some(class) = gateway_error {
        line.push_str(" (gateway error: ");
        line.push_str(class);
        line.push(')');
    }
    line
}

/// A `CallToolResult` decidable from the response head alone, or `None` when
/// the body must be read.
///
/// Status codes that forbid a body, a gateway-authored failure, partial
/// responses (which the buffered normalization phase deliberately never
/// rewrites), a coded or streamed representation, and a declared length past
/// the response bound are all answered here, so the gateway never buffers a
/// representation it cannot convert.
pub(crate) fn head_only_result(
    status: u16,
    headers: &HashMap<String, String>,
    limits: BridgeResponseLimits,
    gateway_error: Option<&'static str>,
    origin: BridgeResponseOrigin,
) -> Option<Value> {
    let is_error = !(200..300).contains(&status);
    let line = status_line(status, gateway_error);
    if (100..200).contains(&status) || matches!(status, 204 | 205 | 304) {
        return Some(text_result(line, is_error));
    }
    // A failure the gateway authored itself (a failed dispatch, an open
    // breaker, overload, ...) carries no backend body worth an excerpt, and
    // on the rejection path no buffered body is converted at all: answer it
    // from the status line.
    if is_error && origin == BridgeResponseOrigin::Gateway {
        return Some(text_result(line, true));
    }
    let coded = header_value(headers, "content-encoding")
        .is_some_and(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"));
    let streamed =
        media_type(header_value(headers, "content-type")).as_deref() == Some("text/event-stream");
    let reason = if matches!(status, 206 | 226) {
        Some("a partial response cannot be returned by an OpenAPI bridge tool")
    } else if coded {
        Some("the bridge does not decode the backend content coding")
    } else if streamed {
        Some("an event-stream response cannot be returned by an OpenAPI bridge tool")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Some(omitted_body_result(&line, reason, is_error));
    }
    let declared = header_value(headers, "content-length")
        .and_then(|value| value.trim().parse::<usize>().ok());
    if declared.is_some_and(|length| length > limits.max_response_body_bytes) {
        let reason = format!(
            "the response body exceeds the {} byte bridge bound",
            limits.max_response_body_bytes
        );
        return Some(omitted_body_result(&line, &reason, is_error));
    }
    None
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The longest UTF-8 prefix of `bytes`, or `None` when the bytes are not text.
fn utf8_prefix(bytes: &[u8]) -> Option<&str> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text),
        // An incomplete sequence at the cut is a truncation artifact; an
        // invalid byte before it means the body is not text.
        Err(error) if error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).ok()
        }
        Err(_) => None,
    }
}

/// Convert a buffered backend response into a `CallToolResult`.
///
/// A 2xx becomes `isError: false` with the body as text content, plus
/// `structuredContent` when the body is a JSON object within the structured
/// bound; a 2xx body the bridge cannot return (past a bound, not text,
/// ambiguous JSON) is omitted with a note, still `isError: false`. Anything
/// else becomes `isError: true` with the status line and a bounded excerpt.
/// Every output is bounded; nothing is copied or parsed past the configured
/// limits.
pub(crate) fn body_result(
    observed: &BridgeObservedResponse,
    body: &[u8],
    limits: BridgeResponseLimits,
) -> Value {
    let status = observed.status;
    let line = status_line(status, observed.gateway_error);
    let media_type = media_type(observed.content_type.as_deref());
    if !(200..300).contains(&status) {
        let mut text = line;
        if !body.is_empty() {
            let cut = body.len().min(limits.max_error_excerpt_bytes);
            match utf8_prefix(&body[..cut]) {
                Some(excerpt) => {
                    text.push('\n');
                    text.push_str(excerpt);
                    if cut < body.len() {
                        text.push_str(&format!(
                            "\n[response body truncated to {} of {} bytes]",
                            excerpt.len(),
                            body.len()
                        ));
                    }
                }
                None => text.push_str(&format!("\n[binary body of {} bytes omitted]", body.len())),
            }
        }
        return text_result(text, true);
    }
    if body.is_empty() {
        return text_result(line, false);
    }
    if body.len() > limits.max_response_body_bytes {
        let reason = format!(
            "the response body exceeds the {} byte bridge bound",
            limits.max_response_body_bytes
        );
        return omitted_body_result(&line, &reason, false);
    }
    let Ok(text) = std::str::from_utf8(body) else {
        let reason = format!("the response body is {} bytes of non-text data", body.len());
        return omitted_body_result(&line, &reason, false);
    };
    let is_json = media_type.as_deref().is_some_and(media_type_is_json);
    if !is_json {
        return text_result(text.to_string(), false);
    }
    // Duplicate members make the document parser-dependent; the caller and
    // the gateway could read different `structuredContent`.
    if crate::util::json_dup_keys::slice_ambiguity(body).is_some() {
        let reason = "the JSON response body repeats a member name, so its reading is ambiguous";
        return omitted_body_result(&line, reason, false);
    }
    // Checked before parsing, so a document past the structured bound is
    // never materialized: it is returned as text only.
    if body.len() > limits.max_structured_content_bytes {
        let note = format!(
            "{line}: structuredContent omitted: the JSON response exceeds the {} byte structuredContent bound",
            limits.max_structured_content_bytes
        );
        return json!({
            "content": [
                {"type": "text", "text": text},
                {"type": "text", "text": note},
            ],
            "isError": false,
        });
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(object)) => json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": Value::Object(object),
            "isError": false,
        }),
        // Arrays, scalars, and malformed JSON stay text: structuredContent is
        // a JSON object by definition.
        _ => text_result(text.to_string(), false),
    }
}

/// The result for a backend response that reached the final response phase
/// without being converted (normalization skipped, or its replacement refused
/// by the retained-response budget). The raw REST body is never released; a
/// 2xx stays `isError: false`, because the operation ran.
pub(crate) fn unconverted_result(observed: Option<&BridgeObservedResponse>) -> Value {
    let Some(observed) = observed else {
        let text = "The backend response could not be converted into a tool result";
        return text_result(text.to_string(), true);
    };
    let line = status_line(observed.status, observed.gateway_error);
    let is_error = !(200..300).contains(&observed.status);
    let reason = "the response could not be converted into a tool result";
    omitted_body_result(&line, reason, is_error)
}

/// Serialize a JSON-RPC success envelope carrying `result` for the request id
/// token, bounded by `ceiling`.
pub(crate) fn json_rpc_result_bytes(
    raw_id: Option<&str>,
    result: &Value,
    ceiling: usize,
) -> Option<Vec<u8>> {
    let id = raw_id.and_then(|id| serde_json::value::RawValue::from_string(id.to_string()).ok());
    let envelope = JsonRpcResult {
        id: id.as_deref(),
        result,
    };
    crate::proxy::response_buffer_budget::bounded_json_vec(&envelope, ceiling)
}

struct JsonRpcResult<'a> {
    id: Option<&'a serde_json::value::RawValue>,
    result: &'a Value,
}

impl serde::Serialize for JsonRpcResult<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("jsonrpc", "2.0")?;
        match self.id {
            Some(id) => map.serialize_entry("id", id)?,
            None => map.serialize_entry("id", &Value::Null)?,
        }
        map.serialize_entry("result", self.result)?;
        map.end()
    }
}
