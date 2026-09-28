//! Ory Hydra container fixture for live OIDC relying-party and OAuth2
//! introspection coverage.
//!
//! Hydra issues opaque access tokens by default and exposes a real OIDC
//! discovery document, authorization-code + PKCE endpoints, JWKS, UserInfo,
//! end-session, and RFC 7662 introspection — enough for both suites without a
//! managed IdP.
//!
//! Login/consent are completed by intercepting Hydra's redirects and accepting
//! challenges through the admin API (no separate consent container). Host ports
//! are allocated outside the kernel ephemeral range (#3999); readiness is
//! polled. Secrets and tokens are never written to diagnostics.
//!
//! Loopback facades used by the suites:
//! - introspection discovery facade (same-origin rewrite + upstream call counter)
//! - OIDC token facade (grant-type counters + optional short `expires_in`)

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ferrum_edge::fips::approved::Sha256;
use ferrum_edge::fips::backend::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use url::Url;

use super::containers::{BoxError, fixture_http_client_builder, start_within_deadline};
use super::host_ports::{allocate_host_ports, retry_on_host_port_collision};

/// Pinned Hydra image (public OSS). Bump deliberately with fixture review.
pub const HYDRA_IMAGE: &str = "oryd/hydra";
pub const HYDRA_TAG: &str = "v2.2.0";

const HYDRA_PUBLIC_PORT: u16 = 4444;
const HYDRA_ADMIN_PORT: u16 = 4445;

/// Hard caps for loopback HTTP request framing (fail closed past these).
const FACADE_MAX_HEADER_BYTES: usize = 16 * 1024;
const FACADE_MAX_BODY_BYTES: usize = 64 * 1024;
const FACADE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// System secret for the disposable fixture. Not a production credential;
/// never log this value.
const HYDRA_SYSTEM_SECRET: &str = "ferrum-hydra-si-system-secret";

/// Subject accepted by the login interceptor for every browser flow.
pub const FIXTURE_SUBJECT: &str = "alice";
pub const FIXTURE_EMAIL: &str = "alice@example.test";
pub const FIXTURE_ROLE: &str = "operator";

/// Running Hydra with host-routable public/admin URLs and an in-memory DSN.
pub struct HydraContainer {
    _container: ContainerAsync<GenericImage>,
    pub public_url: String,
    pub admin_url: String,
    pub issuer: String,
    login_url: String,
    consent_url: String,
    client: reqwest::Client,
    /// Unique suffix used in client IDs for this fixture instance.
    pub isolation: String,
}

/// Token-endpoint client authentication registered with Hydra for a fixture
/// client. Token helpers must shape requests to match this method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    fn as_hydra_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// OAuth2 client seeded into Hydra for Ferrum plugins.
#[derive(Clone)]
pub struct HydraClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub audience: String,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

/// Authorization-code callback parameters returned by Hydra after login+consent.
pub struct AuthCodeCallback {
    pub code: String,
    pub state: String,
}

/// Observable counters for the introspection discovery facade.
///
/// Counts only classifications / presence bits — never secrets, tokens, or bodies.
#[derive(Default)]
pub struct IntrospectionFacadeStats {
    pub upstream_introspect_calls: AtomicU64,
    pub basic_authorization_header: AtomicU64,
    pub post_client_secret_field: AtomicU64,
}

/// Observable counters for the OIDC token loopback facade.
#[derive(Default)]
pub struct TokenFacadeStats {
    pub authorization_code_ok: AtomicU64,
    pub refresh_token_ok: AtomicU64,
    pub other_grant_ok: AtomicU64,
}

/// Start Hydra (`serve all --dev`) with memory DSN and host-mapped ports.
///
/// `URLS_SELF_ISSUER` / login / consent use the pre-allocated host ports so
/// discovery documents advertise loopback URLs the test process can reach.
/// Login/consent URLs are intentional blackholes — the browser helper never
/// GETs them; it parses `Location` and accepts challenges via the admin API.
pub async fn start_hydra_container() -> Result<HydraContainer, BoxError> {
    let hydra = retry_on_host_port_collision(start_hydra_container_once).await?;
    hydra.wait_ready().await?;
    Ok(hydra)
}

async fn start_hydra_container_once() -> Result<HydraContainer, BoxError> {
    let [public_port, admin_port, login_port, consent_port] = allocate_host_ports()?;

    let issuer = format!("http://127.0.0.1:{public_port}/");
    let login_url = format!("http://127.0.0.1:{login_port}/login");
    let consent_url = format!("http://127.0.0.1:{consent_port}/consent");

    let isolation = format!(
        "si{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    let image = || {
        GenericImage::new(HYDRA_IMAGE, HYDRA_TAG)
            .with_exposed_port(HYDRA_PUBLIC_PORT.tcp())
            .with_exposed_port(HYDRA_ADMIN_PORT.tcp())
            .with_mapped_port(public_port, HYDRA_PUBLIC_PORT.tcp())
            .with_mapped_port(admin_port, HYDRA_ADMIN_PORT.tcp())
            .with_env_var("DSN", "memory")
            .with_env_var("SECRETS_SYSTEM", HYDRA_SYSTEM_SECRET)
            .with_env_var("URLS_SELF_ISSUER", &issuer)
            .with_env_var("URLS_LOGIN", &login_url)
            .with_env_var("URLS_CONSENT", &consent_url)
            .with_env_var(
                "URLS_LOGOUT",
                format!("http://127.0.0.1:{consent_port}/logout"),
            )
            .with_env_var("SERVE_PUBLIC_CORS_ENABLED", "true")
            .with_env_var("SERVE_ADMIN_CORS_ENABLED", "true")
            .with_env_var("OIDC_SUBJECT_IDENTIFIERS_SUPPORTED_TYPES", "public")
            .with_env_var("STRATEGIES_ACCESS_TOKEN", "opaque")
            .with_env_var("STRATEGIES_SCOPE", "exact")
            .with_cmd(["serve", "all", "--dev"])
    };
    let container = start_within_deadline("Hydra", || image().start()).await?;

    let public_url = format!("http://127.0.0.1:{public_port}");
    let admin_url = format!("http://127.0.0.1:{admin_port}");
    let client = fixture_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    Ok(HydraContainer {
        _container: container,
        public_url,
        admin_url,
        issuer,
        login_url,
        consent_url,
        client,
        isolation,
    })
}

impl HydraContainer {
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.public_url.trim_end_matches('/')
        )
    }

    /// Admin RFC 7662 endpoint (Hydra serves introspection on the admin API).
    pub fn introspection_endpoint(&self) -> String {
        format!(
            "{}/admin/oauth2/introspect",
            self.admin_url.trim_end_matches('/')
        )
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/oauth2/token", self.public_url.trim_end_matches('/'))
    }

    /// Same-origin discovery URL whose `introspection_endpoint` proxies to the
    /// live admin introspector. Hydra advertises public discovery on :4444 and
    /// introspection on :4445; Ferrum requires discovery and introspection to
    /// share scheme/host/port, so this facade rewrites the document.
    ///
    /// Returns `(discovery_url, stats)`. `stats` counts upstream introspect
    /// calls and whether Basic vs form `client_secret` was present — never
    /// records secret values.
    pub async fn start_introspection_discovery_facade(
        &self,
    ) -> Result<(String, Arc<IntrospectionFacadeStats>), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let facade_origin = format!("http://127.0.0.1:{port}");
        let admin_introspect = self.introspection_endpoint();
        let public_discovery = self.discovery_url();
        let client = self.client.clone();
        let stats = Arc::new(IntrospectionFacadeStats::default());
        let stats_accept = Arc::clone(&stats);
        let facade_origin_accept = facade_origin.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let client = client.clone();
                let admin_introspect = admin_introspect.clone();
                let public_discovery = public_discovery.clone();
                let facade_origin = facade_origin_accept.clone();
                let stats = Arc::clone(&stats_accept);
                tokio::spawn(async move {
                    let _ = handle_introspection_facade_connection(
                        stream,
                        client,
                        public_discovery,
                        admin_introspect,
                        facade_origin,
                        stats,
                    )
                    .await;
                });
            }
        });

        // Readiness: discovery must answer through the facade.
        for _ in 0..40 {
            if let Ok(resp) = self
                .client
                .get(format!("{facade_origin}/.well-known/openid-configuration"))
                .send()
                .await
                && resp.status().is_success()
            {
                return Ok((
                    format!("{facade_origin}/.well-known/openid-configuration"),
                    stats,
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("introspection discovery facade not ready".into())
    }

    /// Loopback token endpoint that proxies to live Hydra `/oauth2/token`.
    ///
    /// Counts successful grant types (no secrets recorded). When
    /// `shorten_expires_in_secs` is set, successful JSON responses rewrite
    /// `expires_in` to that value so Ferrum's refresh skew can fire within a
    /// bounded test window without changing Hydra's signed ID-token `exp`.
    pub async fn start_token_facade(
        &self,
        shorten_expires_in_secs: Option<u64>,
    ) -> Result<(String, Arc<TokenFacadeStats>), BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let facade_url = format!("http://127.0.0.1:{port}/oauth2/token");
        let upstream_token = self.token_endpoint();
        let client = self.client.clone();
        let stats = Arc::new(TokenFacadeStats::default());
        let stats_accept = Arc::clone(&stats);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let client = client.clone();
                let upstream_token = upstream_token.clone();
                let stats = Arc::clone(&stats_accept);
                tokio::spawn(async move {
                    let _ = handle_token_facade_connection(
                        stream,
                        client,
                        upstream_token,
                        stats,
                        shorten_expires_in_secs,
                    )
                    .await;
                });
            }
        });

        for _ in 0..40 {
            // Token endpoint rejects GET; a dialable TCP accept is enough for
            // readiness — probe with an empty POST and accept any HTTP answer.
            if let Ok(resp) = self.client.post(&facade_url).send().await {
                let _ = resp.status();
                return Ok((facade_url, stats));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("token facade not ready".into())
    }

    async fn wait_ready(&self) -> Result<(), BoxError> {
        let mut last = String::new();
        let mut consecutive_ok = 0u32;
        for _ in 0..90 {
            match self.readiness_round().await {
                Ok(()) => {
                    consecutive_ok += 1;
                    if consecutive_ok >= 2 {
                        return Ok(());
                    }
                }
                Err(err) => {
                    consecutive_ok = 0;
                    last = sanitize_diag(&err.to_string());
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("Hydra not ready within 45s: {last}").into())
    }

    async fn readiness_round(&self) -> Result<(), BoxError> {
        let discovery = self
            .client
            .get(self.discovery_url())
            .send()
            .await
            .map_err(|e| format!("discovery dial: {e}"))?;
        if !discovery.status().is_success() {
            return Err(format!("discovery HTTP {}", discovery.status()).into());
        }
        let doc: Value = discovery
            .json()
            .await
            .map_err(|e| format!("discovery json: {e}"))?;
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
        ] {
            if doc.get(key).and_then(Value::as_str).is_none() {
                return Err(format!("discovery missing {key}").into());
            }
        }
        // introspection_endpoint is optional on some Hydra builds; admin path is
        // always used directly by the introspection suite.
        // Admin health: create-client listing must answer.
        let health = self
            .client
            .get(format!(
                "{}/health/ready",
                self.admin_url.trim_end_matches('/')
            ))
            .send()
            .await
            .map_err(|e| format!("admin health dial: {e}"))?;
        if !health.status().is_success() {
            // Older hydra may lack /health/ready — fall back to empty client list.
            let clients = self
                .client
                .get(format!(
                    "{}/admin/clients?page_size=1",
                    self.admin_url.trim_end_matches('/')
                ))
                .send()
                .await
                .map_err(|e| format!("admin clients dial: {e}"))?;
            if !clients.status().is_success() {
                return Err(format!("admin not ready HTTP {}", clients.status()).into());
            }
        }
        Ok(())
    }

    /// Register a confidential client for authorization-code (+ optional
    /// client_credentials / refresh) with the given token-endpoint auth method.
    pub async fn create_client(
        &self,
        label: &str,
        redirect_uri: &str,
        token_endpoint_auth_method: TokenEndpointAuthMethod,
        grant_types: &[&str],
    ) -> Result<HydraClient, BoxError> {
        let client_id = format!("ferrum-{label}-{}", self.isolation);
        let client_secret = format!("secret-{label}-{}", self.isolation);
        let audience = format!("api://ferrum-{label}-{}", self.isolation);
        let body = json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_types": grant_types,
            "response_types": ["code", "id_token"],
            "scope": "openid offline_access profile email roles",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": token_endpoint_auth_method.as_hydra_str(),
            "audience": [audience],
            "subject_type": "public",
        });
        let resp = self
            .client
            .post(format!(
                "{}/admin/clients",
                self.admin_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("create client dial: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            // Do not echo response body (may include secrets).
            return Err(format!("create client HTTP {status}").into());
        }
        Ok(HydraClient {
            client_id,
            client_secret,
            redirect_uri: redirect_uri.to_string(),
            audience,
            token_endpoint_auth_method,
        })
    }

    /// Walk Hydra's authorization redirect chain with admin login/consent accept.
    ///
    /// `authorization_url` is the Location produced by Ferrum's browser challenge
    /// (or a hand-built `/oauth2/auth` URL). Returns the callback `code` + `state`
    /// without logging either value.
    pub async fn complete_authorization_redirect(
        &self,
        authorization_url: &str,
        expected_redirect_uri: &str,
        expected_state: &str,
    ) -> Result<AuthCodeCallback, BoxError> {
        let mut cookies = CookieJar::default();
        let mut location = authorization_url.to_string();
        let expected_callback = Url::parse(expected_redirect_uri)
            .map_err(|e| format!("expected callback URL parse: {e}"))?;
        let public_origin =
            Url::parse(&self.public_url).map_err(|e| format!("Hydra public URL parse: {e}"))?;
        let login_target =
            Url::parse(&self.login_url).map_err(|e| format!("Hydra login URL parse: {e}"))?;
        let consent_target =
            Url::parse(&self.consent_url).map_err(|e| format!("Hydra consent URL parse: {e}"))?;

        // Cap redirect hops so a misconfigured fixture fails fast.
        for _ in 0..12 {
            let parsed =
                Url::parse(&location).map_err(|e| format!("redirect location parse: {e}"))?;

            if let Some(code) = query_param(&parsed, "code") {
                if !same_redirect_target(&parsed, &expected_callback) || parsed.fragment().is_some()
                {
                    return Err("authorization code used an unexpected callback target".into());
                }
                let state = query_param(&parsed, "state")
                    .filter(|state| !state.is_empty())
                    .ok_or("authorization callback missing state")?;
                if state != expected_state {
                    return Err("authorization callback state mismatch".into());
                }
                return Ok(AuthCodeCallback { code, state });
            }
            if let Some(challenge) = query_param(&parsed, "login_challenge") {
                if !same_redirect_target(&parsed, &login_target) {
                    return Err("login challenge was delivered to an unexpected target".into());
                }
                location = self.accept_login(&challenge).await?;
                continue;
            }
            if let Some(challenge) = query_param(&parsed, "consent_challenge") {
                if !same_redirect_target(&parsed, &consent_target) {
                    return Err("consent challenge was delivered to an unexpected target".into());
                }
                location = self.accept_consent(&challenge).await?;
                continue;
            }

            if !same_origin(&parsed, &public_origin)
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err("authorization redirect left the Hydra public origin".into());
            }

            let resp = self
                .client
                .get(&location)
                .header("cookie", cookies.header_value())
                .send()
                .await
                .map_err(|e| format!("auth hop dial: {e}"))?;
            cookies.absorb_set_cookie(resp.headers());
            let status = resp.status();
            let next = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| resolve_location(&location, v));
            if let Some(next) = next {
                location = next;
                continue;
            }
            return Err(
                format!("auth hop HTTP {status} without login/consent/code redirect").into(),
            );
        }
        Err("authorization redirect hop budget exhausted".into())
    }

    async fn accept_login(&self, challenge: &str) -> Result<String, BoxError> {
        let resp = self
            .client
            .put(format!(
                "{}/admin/oauth2/auth/requests/login/accept?login_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .json(&json!({
                "subject": FIXTURE_SUBJECT,
                "remember": false,
            }))
            .send()
            .await
            .map_err(|e| format!("accept login dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("accept login HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("accept login json: {e}"))?;
        body.get("redirect_to")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "accept login missing redirect_to".into())
    }

    async fn accept_consent(&self, challenge: &str) -> Result<String, BoxError> {
        // Fetch requested scope/audience from the challenge so we grant exactly
        // what Ferrum asked for.
        let info = self
            .client
            .get(format!(
                "{}/admin/oauth2/auth/requests/consent?consent_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .send()
            .await
            .map_err(|e| format!("get consent dial: {e}"))?;
        if !info.status().is_success() {
            return Err(format!("get consent HTTP {}", info.status()).into());
        }
        let info: Value = info
            .json()
            .await
            .map_err(|e| format!("get consent json: {e}"))?;
        let grant_scope = info
            .get("requested_scope")
            .cloned()
            .unwrap_or_else(|| json!(["openid", "offline_access", "profile", "email", "roles"]));
        let grant_audience = info
            .get("requested_access_token_audience")
            .cloned()
            .unwrap_or_else(|| json!([]));

        let resp = self
            .client
            .put(format!(
                "{}/admin/oauth2/auth/requests/consent/accept?consent_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .json(&json!({
                "grant_scope": grant_scope,
                "grant_access_token_audience": grant_audience,
                "remember": false,
                "session": {
                    "id_token": {
                        "email": FIXTURE_EMAIL,
                        "roles": [FIXTURE_ROLE],
                    },
                    "access_token": {
                        "email": FIXTURE_EMAIL,
                        "roles": [FIXTURE_ROLE],
                    }
                }
            }))
            .send()
            .await
            .map_err(|e| format!("accept consent dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("accept consent HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("accept consent json: {e}"))?;
        body.get("redirect_to")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "accept consent missing redirect_to".into())
    }

    /// Client-credentials opaque access token (no browser). Optionally request
    /// an audience. Request shaping follows `client.token_endpoint_auth_method`.
    pub async fn client_credentials_token(
        &self,
        client: &HydraClient,
        scope: &str,
        audience: Option<&str>,
    ) -> Result<String, BoxError> {
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("scope", scope.to_string()),
        ];
        if let Some(aud) = audience {
            form.push(("audience", aud.to_string()));
        }
        let resp = self
            .token_request(client, &mut form)
            .await
            .map_err(|e| format!("client_credentials dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("client_credentials HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("client_credentials json: {e}"))?;
        body.get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "client_credentials missing access_token".into())
    }

    /// Authorization-code token set with seeded claims (for introspection claim
    /// fan-out). Returns `(access_token, refresh_token)`.
    pub async fn authorization_code_tokens(
        &self,
        client: &HydraClient,
        scopes: &str,
    ) -> Result<(String, Option<String>), BoxError> {
        let verifier = pkce_verifier()?;
        let challenge = pkce_challenge_s256(&verifier);
        let state = format!("state-{}", self.isolation);
        let nonce = format!("nonce-{}", self.isolation);
        let mut auth = Url::parse(&format!(
            "{}/oauth2/auth",
            self.public_url.trim_end_matches('/')
        ))?;
        auth.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &client.redirect_uri)
            .append_pair("scope", scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !client.audience.is_empty() {
            auth.query_pairs_mut()
                .append_pair("audience", &client.audience);
        }

        let callback = self
            .complete_authorization_redirect(auth.as_str(), &client.redirect_uri, &state)
            .await?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", callback.code),
            ("redirect_uri", client.redirect_uri.clone()),
            ("code_verifier", verifier),
        ];
        let resp = self
            .token_request(client, &mut form)
            .await
            .map_err(|e| format!("auth_code token dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("auth_code token HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("auth_code token json: {e}"))?;
        let access = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or("auth_code token missing access_token")?
            .to_string();
        let refresh = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok((access, refresh))
    }

    /// POST `/oauth2/token` using the client's registered auth method.
    ///
    /// `client_secret_basic` → HTTP Basic, form without credentials.
    /// `client_secret_post` → credentials in the form body, no Authorization.
    async fn token_request(
        &self,
        client: &HydraClient,
        form: &mut Vec<(&str, String)>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/oauth2/token", self.public_url.trim_end_matches('/'));
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic => {
                self.client
                    .post(&url)
                    .basic_auth(&client.client_id, Some(&client.client_secret))
                    .form(form)
                    .send()
                    .await
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                form.push(("client_id", client.client_id.clone()));
                form.push(("client_secret", client.client_secret.clone()));
                self.client.post(&url).form(form).send().await
            }
        }
    }
}

/// Replace the `nonce` query parameter on an authorization URL without touching
/// other parameters (used for live nonce-mismatch negatives).
pub fn rewrite_authorization_nonce(
    authorization_url: &str,
    new_nonce: &str,
) -> Result<String, BoxError> {
    let mut url = Url::parse(authorization_url).map_err(|e| format!("auth url parse: {e}"))?;
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            if k == "nonce" {
                (k.into_owned(), new_nonce.to_string())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();
    url.query_pairs_mut().clear();
    for (k, v) in &pairs {
        url.query_pairs_mut().append_pair(k, v);
    }
    if !pairs.iter().any(|(k, _)| k == "nonce") {
        url.query_pairs_mut().append_pair("nonce", new_nonce);
    }
    Ok(url.to_string())
}

#[derive(Default)]
struct CookieJar {
    pairs: HashMap<String, String>,
}

impl CookieJar {
    fn absorb_set_cookie(&mut self, headers: &reqwest::header::HeaderMap) {
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(raw) = value.to_str() else {
                continue;
            };
            let pair = raw.split(';').next().unwrap_or("").trim();
            if let Some((name, val)) = pair.split_once('=') {
                self.pairs
                    .insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }

    fn header_value(&self) -> String {
        self.pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(k, v)| (k == name).then(|| v.into_owned()))
}

fn same_origin(left: &Url, right: &Url) -> bool {
    matches!(left.scheme(), "http" | "https")
        && left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn same_redirect_target(actual: &Url, expected: &Url) -> bool {
    same_origin(actual, expected)
        && actual.username() == expected.username()
        && actual.password() == expected.password()
        && actual.path() == expected.path()
}

fn resolve_location(current: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    if let Ok(base) = Url::parse(current)
        && let Ok(joined) = base.join(location)
    {
        return joined.to_string();
    }
    location.to_string()
}

fn urlencoding_challenge(challenge: &str) -> String {
    // Challenges are URL-safe; still escape reserved characters.
    challenge
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

fn sanitize_diag(raw: &str) -> String {
    // Bound and strip anything that looks like a bearer/secret fragment.
    let truncated: String = raw.chars().take(240).collect();
    truncated
        .replace("Bearer ", "Bearer [REDACTED] ")
        .replace("client_secret", "client_secret=[REDACTED]")
}

fn pkce_verifier() -> Result<String, BoxError> {
    use base64::Engine;
    let mut bytes = [0u8; 64];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "SystemRandom failed to fill PKCE verifier".to_string())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_challenge_s256(verifier: &str) -> String {
    use base64::Engine;
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    /// Lowercased header name → value. Authorization is retained for upstream
    /// forwarding only and must never be logged.
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Bounded read-until-headers-complete plus Content-Length body completion.
/// Fail-closed on timeout, truncation, oversize, or malformed framing.
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<ParsedHttpRequest, BoxError> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let header_end = loop {
        if buf.len() > FACADE_MAX_HEADER_BYTES {
            return Err("HTTP headers exceed facade cap".into());
        }
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        let mut chunk = [0u8; 2048];
        let n = timeout(FACADE_READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| "HTTP header read timeout")?
            .map_err(|e| format!("HTTP header read: {e}"))?;
        if n == 0 {
            return Err("HTTP connection closed before headers completed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &buf[..header_end];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| "HTTP headers are not valid UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err("malformed HTTP request line".into());
    }

    let mut headers = HashMap::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed HTTP header line".into());
        };
        let name_l = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name_l == "content-length" {
            let len: usize = value.parse().map_err(|_| "invalid Content-Length")?;
            if len > FACADE_MAX_BODY_BYTES {
                return Err("HTTP body exceeds facade cap".into());
            }
            content_length = Some(len);
        }
        headers.insert(name_l, value);
    }

    let body_start = header_end + 4;
    let mut body = if body_start <= buf.len() {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };

    if let Some(need) = content_length {
        while body.len() < need {
            let mut chunk = vec![0u8; (need - body.len()).min(4096)];
            let n = timeout(FACADE_READ_TIMEOUT, stream.read(&mut chunk))
                .await
                .map_err(|_| "HTTP body read timeout")?
                .map_err(|e| format!("HTTP body read: {e}"))?;
            if n == 0 {
                return Err("HTTP connection closed before body completed".into());
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > FACADE_MAX_BODY_BYTES {
                return Err("HTTP body exceeds facade cap".into());
            }
        }
        body.truncate(need);
    } else if method == "POST" || method == "PUT" || method == "PATCH" {
        // No Content-Length: reject rather than guessing (fail closed).
        return Err("POST/PUT/PATCH without Content-Length rejected".into());
    }

    Ok(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), BoxError> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn write_simple_status(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
) -> Result<(), BoxError> {
    write_http_response(stream, status, reason, "text/plain", reason.as_bytes()).await
}

async fn handle_introspection_facade_connection(
    mut stream: tokio::net::TcpStream,
    client: reqwest::Client,
    public_discovery: String,
    admin_introspect: String,
    facade_origin: String,
    stats: Arc<IntrospectionFacadeStats>,
) -> Result<(), BoxError> {
    let request = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(_) => {
            let _ = write_simple_status(&mut stream, 400, "Bad Request").await;
            return Ok(());
        }
    };

    if request.method == "GET"
        && request
            .path
            .starts_with("/.well-known/openid-configuration")
    {
        let upstream = client.get(&public_discovery).send().await?;
        let status = upstream.status().as_u16();
        let mut doc: Value = upstream.json().await?;
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "introspection_endpoint".to_string(),
                json!(format!("{facade_origin}/oauth2/introspect")),
            );
        }
        let body = serde_json::to_vec(&doc)?;
        write_http_response(&mut stream, status, "OK", "application/json", &body).await?;
        return Ok(());
    }

    if request.method == "POST" && request.path.starts_with("/oauth2/introspect") {
        stats
            .upstream_introspect_calls
            .fetch_add(1, Ordering::SeqCst);
        if request.headers.contains_key("authorization") {
            stats
                .basic_authorization_header
                .fetch_add(1, Ordering::SeqCst);
        }
        // Classify form client_secret presence without recording the value.
        if form_has_field(&request.body, "client_secret") {
            stats
                .post_client_secret_field
                .fetch_add(1, Ordering::SeqCst);
        }

        let mut forward = client.post(&admin_introspect);
        if let Some(authorization) = request.headers.get("authorization") {
            forward = forward.header("authorization", authorization);
        }
        if let Some(content_type) = request.headers.get("content-type") {
            forward = forward.header("content-type", content_type);
        } else {
            forward = forward.header("content-type", "application/x-www-form-urlencoded");
        }
        let upstream = forward.body(request.body).send().await?;
        let status = upstream.status().as_u16();
        let resp_body = upstream.bytes().await?;
        write_http_response(&mut stream, status, "OK", "application/json", &resp_body).await?;
        return Ok(());
    }

    write_simple_status(&mut stream, 404, "Not Found").await?;
    Ok(())
}

async fn handle_token_facade_connection(
    mut stream: tokio::net::TcpStream,
    client: reqwest::Client,
    upstream_token: String,
    stats: Arc<TokenFacadeStats>,
    shorten_expires_in_secs: Option<u64>,
) -> Result<(), BoxError> {
    let request = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(_) => {
            let _ = write_simple_status(&mut stream, 400, "Bad Request").await;
            return Ok(());
        }
    };

    if request.method != "POST" || !request.path.starts_with("/oauth2/token") {
        write_simple_status(&mut stream, 404, "Not Found").await?;
        return Ok(());
    }

    let grant_type = form_field_value(&request.body, "grant_type").unwrap_or_default();

    let mut forward = client.post(&upstream_token);
    if let Some(authorization) = request.headers.get("authorization") {
        forward = forward.header("authorization", authorization);
    }
    if let Some(content_type) = request.headers.get("content-type") {
        forward = forward.header("content-type", content_type);
    } else {
        forward = forward.header("content-type", "application/x-www-form-urlencoded");
    }
    let upstream = forward.body(request.body.clone()).send().await?;
    let status = upstream.status();
    let status_code = status.as_u16();
    let mut resp_body = upstream.bytes().await?.to_vec();

    if status.is_success() {
        match grant_type.as_str() {
            "authorization_code" => {
                stats.authorization_code_ok.fetch_add(1, Ordering::SeqCst);
            }
            "refresh_token" => {
                stats.refresh_token_ok.fetch_add(1, Ordering::SeqCst);
            }
            _ => {
                stats.other_grant_ok.fetch_add(1, Ordering::SeqCst);
            }
        }
        if let Some(secs) = shorten_expires_in_secs
            && let Ok(mut doc) = serde_json::from_slice::<Value>(&resp_body)
        {
            if let Some(obj) = doc.as_object_mut() {
                obj.insert("expires_in".to_string(), json!(secs));
            }
            // Re-serialize without logging; tokens stay only in the bytes.
            if let Ok(rewritten) = serde_json::to_vec(&doc) {
                resp_body = rewritten;
            }
        }
    }

    write_http_response(
        &mut stream,
        status_code,
        "OK",
        "application/json",
        &resp_body,
    )
    .await?;
    Ok(())
}

fn form_has_field(body: &[u8], name: &str) -> bool {
    form_field_value(body, name).is_some()
}

fn form_field_value(body: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        let key = urlencoding_decode(key);
        if key == name {
            let value = parts.next().unwrap_or("");
            return Some(urlencoding_decode(value));
        }
    }
    None
}

fn urlencoding_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &input[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
