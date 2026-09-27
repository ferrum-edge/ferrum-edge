use regex::{RegexSet, RegexSetBuilder};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::plugins::RequestContext;
use crate::util::unknown_keys::reject_unknown_keys;

use super::rules::IpCidr;

/// Fixed-shape global exemption object keys. `header_present` remains an
/// intentionally open map of operator-defined header names.
const GLOBAL_EXEMPTION_KEYS: &[&str] = &[
    "paths",
    "methods",
    "consumers",
    "ips",
    "header_present",
    "fp_capture_filters",
];

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
        reject_unknown_keys(
            object,
            "config.global_exemptions",
            GLOBAL_EXEMPTION_KEYS,
            "waf: `config.global_exemptions`: ",
        )?;

        let paths = optional_string_vec(object, "paths")?.unwrap_or_default();
        let path_set = if paths.is_empty() {
            None
        } else {
            RegexSetBuilder::new(paths.into_iter().map(exemption_path_pattern))
                .build()
                .map(Some)
                .map_err(|_| {
                    "waf: `global_exemptions.paths` pattern set is invalid or too complex"
                        .to_string()
                })?
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
                    format!("waf: `global_exemptions.ips` contains invalid IP/CIDR {raw:?}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let header_present = parse_header_present(object.get("header_present"))?;
        let fp_filters = optional_string_vec(object, "fp_capture_filters")?.unwrap_or_default();
        let fp_capture_filters = if fp_filters.is_empty() {
            None
        } else {
            RegexSet::new(fp_filters).map(Some).map_err(|_| {
                "waf: `global_exemptions.fp_capture_filters` pattern set is invalid or too complex"
                    .to_string()
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
        // This predicate runs several times per request (authorize, both body
        // buffering decisions, response phases), so each check is skipped
        // outright when its list is empty and none allocates: methods compare
        // case-insensitively in place instead of uppercasing the request
        // method, and the client IP is parsed only when an IP exemption exists.
        if !self.methods.is_empty()
            && self
                .methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(&ctx.method))
        {
            return true;
        }
        if !self.ips.is_empty()
            && let Ok(client_ip) = ctx.client_ip.parse()
            && self.ips.iter().any(|cidr| cidr.matches(client_ip))
        {
            return true;
        }
        if !self.consumers.is_empty()
            && let Some(identity) = ctx.effective_identity()
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

fn anchor_exemption_path_regex(regex: &str) -> String {
    // Wrap instead of prefixing a bare `^` so every top-level alternation
    // branch is anchored: `~a|b` becomes `^(?:a|b)`, not `^a|b`.
    format!("^(?:{regex})")
}

fn exemption_path_pattern(raw: String) -> String {
    if let Some(regex) = raw.strip_prefix('~') {
        // Start-anchor `~regex` exemptions so they match from the beginning of
        // the path, matching the `prefix*` branch's semantics. The compiled set
        // is evaluated with `is_match`, which is unanchored (substring) by
        // default, so an un-anchored entry like `~api` would otherwise exempt
        // ANY path merely containing `api` (e.g. `/v1/api-keys`,
        // `/secret/api/admin`) — short-circuiting the entire WAF on those
        // routes via the early return in `request_short_circuits`. Operators
        // who genuinely want a substring/floating match can still write
        // `~.*pattern`; an explicit leading `^` remains compatible inside the
        // wrapper.
        anchor_exemption_path_regex(regex)
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
            // Intentionally open: keys are operator-defined header names.
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
            "waf: global_exemptions.header_present must be an object, got {other:?}",
            other = other.to_string()
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
            "waf: global_exemptions.{key} must be an array, got {other:?}",
            other = other.to_string()
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

    #[test]
    fn regex_exemption_is_start_anchored_and_does_not_overmatch() {
        // A short `~regex` exemption must anchor at the start of the path. A
        // bare `~api` previously matched UNANCHORED, so it exempted (and thus
        // silently disabled the WAF on) any path merely containing "api" —
        // e.g. `/v1/api-keys`. After anchoring it only exempts paths that
        // BEGIN with "api".
        let config = serde_json::json!({"paths":["~api"]});
        let exemptions = CompiledExemptions::from_config(Some(&config)).unwrap();

        // Path beginning with the pattern is still exempt.
        let starts = RequestContext::new("127.0.0.1".into(), "GET".into(), "api/v1".into());
        assert!(exemptions.request_short_circuits(&starts));

        // Paths that merely CONTAIN the pattern must NOT be exempt — otherwise
        // a one-word regex disables the WAF on sensitive routes.
        let contains_mid =
            RequestContext::new("127.0.0.1".into(), "GET".into(), "/v1/api-keys".into());
        assert!(!exemptions.request_short_circuits(&contains_mid));
        let contains_deep =
            RequestContext::new("127.0.0.1".into(), "GET".into(), "/secret/api/admin".into());
        assert!(!exemptions.request_short_circuits(&contains_deep));
    }

    #[test]
    fn explicit_anchor_and_floating_patterns_still_work_after_wrap() {
        // An operator-anchored pattern keeps anchored matching after the
        // `^(?:...)` wrap (the resulting `^(?:^/internal/)` is a harmless
        // double-anchor on single-line paths), and a floating match is still
        // expressible via `~.*`.
        let anchored = serde_json::json!({"paths":["~^/internal/"]});
        let exemptions = CompiledExemptions::from_config(Some(&anchored)).unwrap();
        let internal =
            RequestContext::new("127.0.0.1".into(), "GET".into(), "/internal/metrics".into());
        assert!(exemptions.request_short_circuits(&internal));
        let other = RequestContext::new("127.0.0.1".into(), "GET".into(), "/public".into());
        assert!(!exemptions.request_short_circuits(&other));

        let floating = serde_json::json!({"paths":["~.*/admin"]});
        let exemptions = CompiledExemptions::from_config(Some(&floating)).unwrap();
        let nested = RequestContext::new("127.0.0.1".into(), "GET".into(), "/team/admin".into());
        assert!(exemptions.request_short_circuits(&nested));
    }
}
