use serde_json::Value;

use super::claim_resolver::extract_claim_values;
use super::json_escape::escape_json_string;

pub struct ScopeRoleRequirements<'a> {
    pub required_scopes: &'a [String],
    pub required_roles: &'a [String],
    pub scope_claim: &'a str,
    pub role_claim: &'a str,
    pub plugin_name: &'static str,
}

pub fn check(claims: &Value, req: &ScopeRoleRequirements<'_>) -> Result<(), (u16, String)> {
    if !req.required_scopes.is_empty() {
        let token_scopes = extract_claim_values(claims, req.scope_claim);
        for required in req.required_scopes {
            if !token_scopes.iter().any(|scope| scope == required) {
                tracing::debug!(
                    plugin = req.plugin_name,
                    required_scope = %required,
                    "token missing required scope"
                );
                // The required scope is operator-configured text embedded in a
                // JSON body, so it must be JSON-escaped, not merely
                // HTML-escaped: a configured value carrying a newline, tab, or
                // any other byte below 0x20 would otherwise emit a body no JSON
                // parser accepts. `escape_json_string` also keeps the `<`/`>`
                // `\u003c`/`\u003e` escaping the previous helper provided, so
                // the body stays safe in a browser context.
                return Err((
                    403,
                    format!(
                        r#"{{"error":"Insufficient scope","required":"{}"}}"#,
                        escape_json_string(required)
                    ),
                ));
            }
        }
    }

    if !req.required_roles.is_empty() {
        let token_roles = extract_claim_values(claims, req.role_claim);
        let has_match = req
            .required_roles
            .iter()
            .any(|role| token_roles.iter().any(|token_role| token_role == role));
        if !has_match {
            tracing::debug!(plugin = req.plugin_name, "token missing required role");
            return Err((403, r#"{"error":"Insufficient role"}"#.to_string()));
        }
    }

    Ok(())
}
