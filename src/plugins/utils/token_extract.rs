use crate::plugins::RequestContext;

use super::auth_flow::ExtractedCredential;

#[derive(Clone)]
pub struct TokenHeaderLocation {
    pub name: String,
    pub prefix: Option<String>,
}

#[derive(Clone)]
pub enum TokenLocation {
    Header(TokenHeaderLocation),
    QueryParam(String),
}

pub enum TokenLocationExtract {
    Missing,
    Credential(ExtractedCredential),
}

pub fn extract_authorization_bearer(ctx: &RequestContext) -> ExtractedCredential {
    match ctx.headers.get("authorization") {
        None => ExtractedCredential::Missing,
        Some(value) if value.starts_with("Bearer ") || value.starts_with("bearer ") => {
            ExtractedCredential::BearerToken(value[7..].to_string())
        }
        Some(_) => {
            ExtractedCredential::InvalidFormat(r#"{"error":"Missing Bearer token"}"#.to_string())
        }
    }
}

pub fn extract_from_location(
    location: &TokenLocation,
    ctx: &RequestContext,
) -> TokenLocationExtract {
    match location {
        TokenLocation::Header(header) => match ctx.headers.get(&header.name) {
            Some(value) => extract_location_value(value, header.prefix.as_deref()),
            None => TokenLocationExtract::Missing,
        },
        TokenLocation::QueryParam(name) => match ctx.query_params.get(name) {
            Some(value) => extract_location_value(value, None),
            None => TokenLocationExtract::Missing,
        },
    }
}

pub fn provider_locations_extract_token(
    token_locations: &[TokenLocation],
    ctx: &RequestContext,
    expected_token: &str,
) -> bool {
    token_locations
        .iter()
        .any(|location| match extract_from_location(location, ctx) {
            TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                token == expected_token
            }
            _ => false,
        })
}

pub fn mark_original_token_stripping_metadata(
    ctx: &mut RequestContext,
    token_locations: &[TokenLocation],
    strip_authorization_metadata_key: &str,
    strip_header_metadata_prefix: &str,
    strip_query_param_metadata_prefix: &str,
) {
    if token_locations.is_empty() {
        ctx.metadata.insert(
            strip_authorization_metadata_key.to_string(),
            "true".to_string(),
        );
        return;
    }

    for location in token_locations {
        match location {
            TokenLocation::Header(header) => {
                ctx.metadata.insert(
                    format!("{strip_header_metadata_prefix}{}", header.name),
                    "true".to_string(),
                );
            }
            TokenLocation::QueryParam(name) => {
                ctx.metadata.insert(
                    format!("{strip_query_param_metadata_prefix}{name}"),
                    "true".to_string(),
                );
                ctx.query_params.remove(name);
            }
        }
    }
}

fn extract_location_value(value: &str, prefix: Option<&str>) -> TokenLocationExtract {
    let token = match prefix {
        Some(prefix) => match value.strip_prefix(prefix) {
            Some(token) => token,
            None => return TokenLocationExtract::Missing,
        },
        None => value,
    };

    if token.is_empty() {
        return TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(
            r#"{"error":"Empty token"}"#.to_string(),
        ));
    }

    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_header(name: &str, value: &str) -> RequestContext {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        ctx.headers.insert(name.to_string(), value.to_string());
        ctx
    }

    #[test]
    fn extracts_bearer_token_from_authorization() {
        let ctx = ctx_with_header("authorization", "Bearer abc");
        assert!(matches!(
            extract_authorization_bearer(&ctx),
            ExtractedCredential::BearerToken(token) if token == "abc"
        ));
    }

    #[test]
    fn configured_header_prefix_mismatch_is_missing() {
        let ctx = ctx_with_header("x-token", "Token abc");
        let location = TokenLocation::Header(TokenHeaderLocation {
            name: "x-token".to_string(),
            prefix: Some("Bearer ".to_string()),
        });
        assert!(matches!(
            extract_from_location(&location, &ctx),
            TokenLocationExtract::Missing
        ));
    }
}
