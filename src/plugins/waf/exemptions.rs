use regex::{RegexSet, RegexSetBuilder};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::plugins::RequestContext;

use super::rules::IpCidr;

#[derive(Debug, Default)]
pub struct CompiledExemptions {
    path_set: Option<RegexSet>,
    methods: HashSet<String>,
    consumers: HashSet<String>,
    ips: Vec<IpCidr>,
    header_present: HashMap<String, Option<String>>,
    fp_capture_filters: Option<RegexSet>,
}

impl CompiledExemptions {
    pub fn from_config(config: Option<&Value>) -> Result<Self, String> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        if config.is_null() {
            return Ok(Self::default());
        }
        let object = config
            .as_object()
            .ok_or_else(|| "waf: global_exemptions must be an object".to_string())?;

        let paths = optional_string_vec(object, "paths")?.unwrap_or_default();
        let path_set = if paths.is_empty() {
            None
        } else {
            RegexSetBuilder::new(paths.into_iter().map(exemption_path_pattern))
                .build()
                .map(Some)
                .map_err(|e| format!("waf: failed to compile global_exemptions.paths: {e}"))?
        };

        let methods = optional_string_vec(object, "methods")?
            .unwrap_or_default()
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect();
        let consumers = optional_string_vec(object, "consumers")?
            .unwrap_or_default()
            .into_iter()
            .collect();
        let ips = optional_string_vec(object, "ips")?
            .unwrap_or_default()
            .into_iter()
            .map(|raw| {
                IpCidr::parse(&raw).ok_or_else(|| {
                    format!("waf: global_exemptions.ips contains invalid IP/CIDR '{raw}'")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let header_present = parse_header_present(object.get("header_present"))?;
        let fp_filters = optional_string_vec(object, "fp_capture_filters")?.unwrap_or_default();
        let fp_capture_filters = if fp_filters.is_empty() {
            None
        } else {
            RegexSet::new(fp_filters).map(Some).map_err(|e| {
                format!("waf: failed to compile global_exemptions.fp_capture_filters: {e}")
            })?
        };

        Ok(Self {
            path_set,
            methods,
            consumers,
            ips,
            header_present,
            fp_capture_filters,
        })
    }

    pub fn request_short_circuits(&self, ctx: &RequestContext) -> bool {
        if self
            .path_set
            .as_ref()
            .is_some_and(|paths| paths.is_match(&ctx.path))
        {
            return true;
        }
        if self.methods.contains(&ctx.method.to_ascii_uppercase()) {
            return true;
        }
        if let Ok(client_ip) = ctx.client_ip.parse()
            && self.ips.iter().any(|cidr| cidr.matches(client_ip))
        {
            return true;
        }
        if let Some(identity) = ctx.effective_identity()
            && self.consumers.contains(identity)
        {
            return true;
        }
        false
    }

    pub fn suppresses_rule_for_request(&self, ctx: &RequestContext) -> bool {
        self.header_present.iter().any(|(name, expected)| {
            let Some(actual) = ctx.headers.get(name) else {
                return false;
            };
            expected.as_ref().is_none_or(|expected| actual == expected)
        })
    }

    pub fn suppresses_value(&self, value: &str) -> bool {
        self.fp_capture_filters
            .as_ref()
            .is_some_and(|filters| filters.is_match(value))
    }
}

fn exemption_path_pattern(raw: String) -> String {
    if let Some(regex) = raw.strip_prefix('~') {
        regex.to_string()
    } else if let Some(prefix) = raw.strip_suffix('*') {
        format!("^{}", regex::escape(prefix))
    } else {
        // Non-wildcard entries are exact-path matches per docs. Anchor both
        // ends so e.g. `/health` does not also exempt `/healthz`,
        // `/health-admin`, etc. — over-matching here can disable WAF on
        // unintended routes.
        format!("^{}$", regex::escape(&raw))
    }
}

fn parse_header_present(value: Option<&Value>) -> Result<HashMap<String, Option<String>>, String> {
    match value {
        None | Some(Value::Null) => Ok(HashMap::new()),
        Some(Value::Object(map)) => {
            let mut parsed = HashMap::new();
            for (key, value) in map {
                let expected = if value.is_null() {
                    None
                } else {
                    Some(value.as_str().ok_or_else(|| {
                        "waf: global_exemptions.header_present values must be strings or null"
                            .to_string()
                    })?)
                };
                parsed.insert(key.to_ascii_lowercase(), expected.map(str::to_string));
            }
            Ok(parsed)
        }
        Some(other) => Err(format!(
            "waf: global_exemptions.header_present must be an object, got {other}"
        )),
    }
}

fn optional_string_vec(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Some(raw) = value.as_str() else {
                    return Err(format!(
                        "waf: global_exemptions.{key} entries must be strings"
                    ));
                };
                if raw.is_empty() {
                    return Err(format!(
                        "waf: global_exemptions.{key} entries must be non-empty"
                    ));
                }
                parsed.push(raw.to_string());
            }
            Ok(Some(parsed))
        }
        Some(other) => Err(format!(
            "waf: global_exemptions.{key} must be an array, got {other}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_exemption_prefix_matches() {
        let config = serde_json::json!({"paths":["/health*"]});
        let exemptions = CompiledExemptions::from_config(Some(&config)).unwrap();
        let ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/healthz".into());
        assert!(exemptions.request_short_circuits(&ctx));
    }

    #[test]
    fn non_wildcard_exemption_is_exact_match() {
        let config = serde_json::json!({"paths":["/health"]});
        let exemptions = CompiledExemptions::from_config(Some(&config)).unwrap();

        let exact = RequestContext::new("127.0.0.1".into(), "GET".into(), "/health".into());
        assert!(exemptions.request_short_circuits(&exact));

        // Non-wildcard entries must NOT exempt longer paths sharing the prefix
        // — otherwise `/health` would silently disable WAF on `/health-admin`,
        // `/healthz`, etc.
        let suffix = RequestContext::new("127.0.0.1".into(), "GET".into(), "/healthz".into());
        assert!(!exemptions.request_short_circuits(&suffix));

        let dashed = RequestContext::new("127.0.0.1".into(), "GET".into(), "/health-admin".into());
        assert!(!exemptions.request_short_circuits(&dashed));
    }
}
