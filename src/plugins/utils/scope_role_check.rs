use serde_json::Value;

use super::claim_resolver::{extract_claim_values, html_escape};

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
                return Err((
                    403,
                    format!(
                        r#"{{"error":"Insufficient scope","required":"{}"}}"#,
                        html_escape(required)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_required_scope_and_role() {
        let claims = json!({"scope": "read write", "roles": ["admin"]});
        let scopes = vec!["read".to_string()];
        let roles = vec!["admin".to_string()];
        let req = ScopeRoleRequirements {
            required_scopes: &scopes,
            required_roles: &roles,
            scope_claim: "scope",
            role_claim: "roles",
            plugin_name: "test",
        };

        assert!(check(&claims, &req).is_ok());
    }

    #[test]
    fn rejects_missing_scope() {
        let claims = json!({"scope": "read"});
        let scopes = vec!["write".to_string()];
        let req = ScopeRoleRequirements {
            required_scopes: &scopes,
            required_roles: &[],
            scope_claim: "scope",
            role_claim: "roles",
            plugin_name: "test",
        };

        let (status, body) = check(&claims, &req).expect_err("missing scope should reject");
        assert_eq!(status, 403);
        assert!(body.contains("Insufficient scope"));
    }
}
