use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

/// How allowed origins are configured.
#[derive(Debug)]
enum AllowedOrigins {
    /// Any origin is allowed (`["*"]`).
    Wildcard,
    /// Only the listed origins are allowed (exact match, case-sensitive).
    List(Vec<String>),
}

/// CORS (Cross-Origin Resource Sharing) plugin.
///
/// Handles preflight OPTIONS requests at the gateway level and injects the
/// appropriate CORS response headers on actual cross-origin requests, so
/// backend services do not need to implement CORS themselves.
pub struct CorsPlugin {
    allowed_origins: AllowedOrigins,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    exposed_headers: Vec<String>,
    allow_credentials: bool,
    max_age: u64,
    preflight_continue: bool,
}

impl CorsPlugin {
    pub fn new(config: &Value) -> Self {
        let allowed_origins = Self::parse_origins(config);

        let allowed_methods = Self::parse_string_array(
            config,
            "allowed_methods",
            &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        );

        let allowed_headers = Self::parse_string_array(
            config,
            "allowed_headers",
            &[
                "Accept",
                "Authorization",
                "Content-Type",
                "Origin",
                "X-Requested-With",
            ],
        );

        let exposed_headers = Self::parse_string_array(config, "exposed_headers", &[]);

        let mut allow_credentials = config["allow_credentials"].as_bool().unwrap_or(false);
        let max_age = config["max_age"].as_u64().unwrap_or(86400);
        let preflight_continue = config["preflight_continue"].as_bool().unwrap_or(false);

        // Per CORS spec: Access-Control-Allow-Origin: * cannot be used with credentials.
        if allow_credentials && matches!(allowed_origins, AllowedOrigins::Wildcard) {
            warn!(
                "cors: allow_credentials=true is incompatible with wildcard origins; \
                 credentials will be disabled. Specify explicit origins to use credentials."
            );
            allow_credentials = false;
        }

        Self {
            allowed_origins,
            allowed_methods,
            allowed_headers,
            exposed_headers,
            allow_credentials,
            max_age,
            preflight_continue,
        }
    }

    /// Parse the `allowed_origins` config field.
    fn parse_origins(config: &Value) -> AllowedOrigins {
        match config["allowed_origins"].as_array() {
            Some(arr) => {
                let origins: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if origins.is_empty() || (origins.len() == 1 && origins[0] == "*") {
                    AllowedOrigins::Wildcard
                } else {
                    AllowedOrigins::List(origins)
                }
            }
            None => AllowedOrigins::Wildcard,
        }
    }

    /// Parse a JSON array of strings with a fallback default.
    fn parse_string_array(config: &Value, key: &str, defaults: &[&str]) -> Vec<String> {
        config[key]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| defaults.iter().map(|s| (*s).to_string()).collect())
    }

    /// Check whether a request origin is allowed.
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if origin.is_empty() {
            return false;
        }
        match &self.allowed_origins {
            AllowedOrigins::Wildcard => true,
            AllowedOrigins::List(origins) => origins.iter().any(|o| o == origin),
        }
    }

    /// Build the common CORS response headers (used for both preflight and actual).
    fn build_cors_headers(&self, origin: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        // Set Access-Control-Allow-Origin
        match &self.allowed_origins {
            AllowedOrigins::Wildcard if !self.allow_credentials => {
                headers.insert("access-control-allow-origin".to_string(), "*".to_string());
            }
            _ => {
                headers.insert(
                    "access-control-allow-origin".to_string(),
                    origin.to_string(),
                );
            }
        }

        // Always set Vary: Origin for caching correctness
        headers.insert("vary".to_string(), "Origin".to_string());

        if self.allow_credentials {
            headers.insert(
                "access-control-allow-credentials".to_string(),
                "true".to_string(),
            );
        }

        if !self.exposed_headers.is_empty() {
            headers.insert(
                "access-control-expose-headers".to_string(),
                self.exposed_headers.join(", "),
            );
        }

        headers
    }

    /// Build headers specific to preflight responses (superset of common headers).
    fn build_preflight_headers(&self, origin: &str) -> HashMap<String, String> {
        let mut headers = self.build_cors_headers(origin);

        headers.insert(
            "access-control-allow-methods".to_string(),
            self.allowed_methods.join(", "),
        );

        headers.insert(
            "access-control-allow-headers".to_string(),
            self.allowed_headers.join(", "),
        );

        headers.insert(
            "access-control-max-age".to_string(),
            self.max_age.to_string(),
        );

        headers
    }
}

#[async_trait]
impl Plugin for CorsPlugin {
    fn name(&self) -> &str {
        "cors"
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Only act on requests that include an Origin header
        let origin = match ctx.headers.get("origin") {
            Some(o) => o.clone(),
            None => return PluginResult::Continue,
        };

        // Detect preflight: OPTIONS with Access-Control-Request-Method header
        let is_preflight =
            ctx.method == "OPTIONS" && ctx.headers.contains_key("access-control-request-method");

        if !is_preflight {
            // Simple/actual CORS request — reject if origin is not allowed
            if !self.is_origin_allowed(&origin) {
                debug!("cors: request rejected for disallowed origin '{}'", origin);
                return PluginResult::Reject {
                    status_code: 403,
                    body: "CORS origin not allowed".to_string(),
                    headers: HashMap::new(),
                };
            }
            ctx.metadata
                .insert("cors_origin".to_string(), origin.clone());
            return PluginResult::Continue;
        }

        // --- Preflight handling ---

        // If preflight_continue is set, let the request pass through to backend
        if self.preflight_continue {
            if self.is_origin_allowed(&origin) {
                ctx.metadata
                    .insert("cors_origin".to_string(), origin.clone());
            }
            return PluginResult::Continue;
        }

        // Check origin
        if !self.is_origin_allowed(&origin) {
            debug!(
                "cors: preflight rejected for disallowed origin '{}'",
                origin
            );
            return PluginResult::Reject {
                status_code: 403,
                body: "CORS origin not allowed".to_string(),
                headers: HashMap::new(),
            };
        }

        // Check requested method
        if let Some(requested_method) = ctx.headers.get("access-control-request-method") {
            let method_allowed = self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(requested_method));
            if !method_allowed {
                debug!(
                    "cors: preflight rejected method '{}' for origin '{}'",
                    requested_method, origin
                );
                return PluginResult::Reject {
                    status_code: 403,
                    body: format!("CORS method not allowed: {}", requested_method),
                    headers: HashMap::new(),
                };
            }
        }

        // Preflight approved — return 204 with CORS headers
        let headers = self.build_preflight_headers(&origin);
        debug!("cors: preflight approved for origin '{}'", origin);
        PluginResult::Reject {
            status_code: 204,
            body: String::new(),
            headers,
        }
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Check if on_request_received marked this as a valid CORS request
        let origin = match ctx.metadata.get("cors_origin") {
            Some(o) => o.clone(),
            None => return PluginResult::Continue,
        };

        let cors_headers = self.build_cors_headers(&origin);
        for (k, v) in cors_headers {
            response_headers.insert(k, v);
        }

        PluginResult::Continue
    }
}
