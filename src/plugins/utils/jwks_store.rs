//! JWKS (JSON Web Key Set) key store with background refresh.
//!
//! Fetches public keys from a remote JWKS endpoint and caches them
//! for JWT validation. Supports RSA (RS256, RS384, RS512) and
//! EC (ES256, ES384) key types.

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, warn};
use url::Url;

use super::PluginHttpClient;

const EMPTY_STORE_RETRY_1: Duration = Duration::from_secs(5);
const EMPTY_STORE_RETRY_2: Duration = Duration::from_secs(15);
const EMPTY_STORE_RETRY_MAX: Duration = Duration::from_secs(30);

fn redacted_jwks_uri(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "redacted-jwks-url".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("/");
    url.to_string()
}

/// A cached JWKS key with its algorithm and decoding key.
#[derive(Clone)]
pub struct CachedJwk {
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
}

/// Thread-safe store of JWKS keys fetched from a remote endpoint.
///
/// Keys are cached in an `ArcSwap` for lock-free reads on the hot path.
/// A background task periodically refreshes the keys.
#[derive(Clone)]
pub struct JwksKeyStore {
    keys: Arc<ArcSwap<HashMap<String, CachedJwk>>>,
    jwks_uri: String,
    http_client: PluginHttpClient,
    fetch_lock: Arc<Mutex<()>>,
    refreshable: bool,
}

/// Raw JWKS response from the endpoint.
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// A single JWK (JSON Web Key) from the JWKS endpoint.
#[derive(Deserialize)]
struct JwkKey {
    /// Key ID — used to match against the `kid` in JWT headers.
    kid: Option<String>,
    /// Key type: "RSA" or "EC".
    kty: String,
    /// Algorithm hint: "RS256", "ES256", etc.
    alg: Option<String>,
    /// Key use: "sig" (signing) or "enc" (encryption).
    #[serde(rename = "use")]
    key_use: Option<String>,

    // RSA parameters
    /// RSA modulus (base64url-encoded).
    n: Option<String>,
    /// RSA exponent (base64url-encoded).
    e: Option<String>,

    // EC parameters
    /// EC curve name: "P-256", "P-384".
    crv: Option<String>,
    /// EC x coordinate (base64url-encoded).
    x: Option<String>,
    /// EC y coordinate (base64url-encoded).
    y: Option<String>,
}

impl JwksKeyStore {
    /// Create a new key store for the given JWKS URI.
    ///
    /// Does NOT fetch keys immediately — call [`fetch_keys`] or
    /// [`start_background_refresh`] after construction.
    pub fn new(jwks_uri: String, http_client: PluginHttpClient) -> Self {
        Self {
            keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            jwks_uri,
            http_client,
            fetch_lock: Arc::new(Mutex::new(())),
            refreshable: true,
        }
    }

    /// Create a non-refreshing key store from inline JWKS JSON.
    pub fn from_inline_jwks(jwks_json: &str) -> Result<Self, String> {
        let jwks: JwksResponse = serde_json::from_str(jwks_json)
            .map_err(|e| format!("inline JWKS parse failed: {}", e))?;
        let keys = Self::parse_jwks_response(&jwks)?;

        Ok(Self {
            keys: Arc::new(ArcSwap::from_pointee(keys)),
            jwks_uri: "inline".to_string(),
            http_client: PluginHttpClient::default(),
            fetch_lock: Arc::new(Mutex::new(())),
            refreshable: false,
        })
    }

    /// Get the JWKS URI this store fetches keys from.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Whether this store fetches keys from an external JWKS URI.
    pub fn is_refreshable(&self) -> bool {
        self.refreshable
    }

    /// Look up a cached key by its key ID (`kid`).
    pub fn get_key(&self, kid: &str) -> Option<CachedJwk> {
        let keys = self.keys.load();
        keys.get(kid).cloned()
    }

    /// Get all cached keys (for tokens without a `kid` header).
    pub fn all_keys(&self) -> Arc<HashMap<String, CachedJwk>> {
        self.keys.load_full()
    }

    /// Returns true if the store has any cached keys.
    pub fn has_keys(&self) -> bool {
        !self.keys.load().is_empty()
    }

    /// Fetch keys from the JWKS endpoint and update the cache.
    pub async fn fetch_keys(&self) -> Result<usize, String> {
        let _fetch_guard = self.fetch_lock.lock().await;
        self.fetch_keys_unlocked().await
    }

    /// Fetch keys only when the store is still empty.
    ///
    /// This lets an eager warmup share the store's immediate background refresh
    /// without issuing a second successful JWKS request.
    pub async fn fetch_keys_if_empty(&self) -> Result<usize, String> {
        let _fetch_guard = self.fetch_lock.lock().await;
        if self.has_keys() {
            return Ok(self.keys.load().len());
        }
        self.fetch_keys_unlocked().await
    }

    async fn fetch_keys_unlocked(&self) -> Result<usize, String> {
        if !self.refreshable {
            return Ok(self.keys.load().len());
        }

        let redacted_uri = redacted_jwks_uri(&self.jwks_uri);
        debug!("Fetching JWKS keys from {}", redacted_uri);

        let req = self.http_client.get().get(&self.jwks_uri);
        let response = self
            .http_client
            .execute_redacted(req, "jwks_fetch", &redacted_uri)
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("JWKS endpoint returned HTTP {}", response.status()));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {}", e))?;

        let new_keys = Self::parse_jwks_response(&jwks)?;

        let count = new_keys.len();
        self.keys.store(Arc::new(new_keys));
        debug!("JWKS key store updated: {} keys cached", count);
        Ok(count)
    }

    fn parse_jwks_response(jwks: &JwksResponse) -> Result<HashMap<String, CachedJwk>, String> {
        let total_keys = jwks.keys.len();
        let mut new_keys = HashMap::new();

        for (idx, jwk) in jwks.keys.iter().enumerate() {
            // Skip encryption keys — we only want signing keys
            if jwk.key_use.as_deref() == Some("enc") {
                continue;
            }

            let kid = jwk
                .kid
                .clone()
                .unwrap_or_else(|| format!("__unnamed_{}", idx));

            match Self::parse_jwk(jwk) {
                Ok(cached) => {
                    debug!("Cached JWKS key: kid={}, alg={:?}", kid, cached.algorithm);
                    new_keys.insert(kid, cached);
                }
                Err(e) => {
                    warn!("Skipping JWKS key kid={}: {}", kid, e);
                }
            }
        }

        let count = new_keys.len();
        if count == 0 && total_keys > 0 {
            return Err(
                "JWKS response contained keys but no usable signing keys were parsed".to_string(),
            );
        }

        Ok(new_keys)
    }

    /// Start a background task that refreshes keys periodically.
    ///
    /// The task runs until the returned [`tokio::task::JoinHandle`] is aborted
    /// or the process exits. Populated stores keep the configured refresh cadence
    /// based on fetch start time; empty stores retry on a short capped backoff.
    pub fn start_background_refresh(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        let interval = if interval.is_zero() {
            Duration::from_secs(1)
        } else {
            interval
        };
        tokio::spawn(async move {
            let mut empty_store_retry_attempt = 0;
            let mut next_refresh_at = Instant::now();
            let mut first_refresh = true;
            loop {
                tokio::time::sleep_until(next_refresh_at).await;
                let fetch_started_at = Instant::now();

                let fetch_result = if first_refresh {
                    store.fetch_keys_if_empty().await
                } else {
                    store.fetch_keys().await
                };
                first_refresh = false;

                if let Err(e) = fetch_result {
                    warn!("JWKS background refresh failed: {}", e);
                }

                let fetch_completed_at = Instant::now();
                let has_keys = store.has_keys();
                next_refresh_at = next_refresh_deadline(
                    fetch_started_at,
                    fetch_completed_at,
                    has_keys,
                    interval,
                    empty_store_retry_attempt,
                );

                if has_keys {
                    empty_store_retry_attempt = 0;
                } else {
                    empty_store_retry_attempt = empty_store_retry_attempt.saturating_add(1);
                }
            }
        })
    }

    /// Parse a single JWK into a cached key.
    fn parse_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        match jwk.kty.as_str() {
            "RSA" => Self::parse_rsa_jwk(jwk),
            "EC" => Self::parse_ec_jwk(jwk),
            other => Err(format!("unsupported key type: {}", other)),
        }
    }

    /// Parse an RSA JWK.
    fn parse_rsa_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        let n = jwk.n.as_deref().ok_or("missing RSA modulus 'n'")?;
        let e = jwk.e.as_deref().ok_or("missing RSA exponent 'e'")?;

        let n_bytes = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|e| format!("invalid base64url in 'n': {}", e))?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|e| format!("invalid base64url in 'e': {}", e))?;

        let algorithm = match jwk.alg.as_deref() {
            Some("RS384") => Algorithm::RS384,
            Some("RS512") => Algorithm::RS512,
            _ => Algorithm::RS256, // Default RSA algorithm
        };

        let decoding_key = DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes);

        Ok(CachedJwk {
            algorithm,
            decoding_key,
        })
    }

    /// Parse an EC (Elliptic Curve) JWK.
    fn parse_ec_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        let x = jwk.x.as_deref().ok_or("missing EC coordinate 'x'")?;
        let y = jwk.y.as_deref().ok_or("missing EC coordinate 'y'")?;

        let algorithm = match jwk.crv.as_deref() {
            Some("P-384") => Algorithm::ES384,
            Some("P-256") | None => Algorithm::ES256,
            Some(other) => return Err(format!("unsupported EC curve: {}", other)),
        };

        // Override algorithm from the `alg` field if present
        let algorithm = match jwk.alg.as_deref() {
            Some("ES384") => Algorithm::ES384,
            Some("ES256") => Algorithm::ES256,
            _ => algorithm,
        };

        // from_ec_components takes base64url-encoded strings directly
        let decoding_key = DecodingKey::from_ec_components(x, y)
            .map_err(|e| format!("invalid EC key components: {}", e))?;

        Ok(CachedJwk {
            algorithm,
            decoding_key,
        })
    }
}

fn refresh_delay_after_attempt(
    store_has_keys: bool,
    interval: Duration,
    empty_store_retry_attempt: u32,
) -> Duration {
    if store_has_keys {
        interval
    } else {
        std::cmp::min(
            interval,
            empty_store_retry_interval(empty_store_retry_attempt),
        )
    }
}

fn empty_store_retry_interval(empty_store_retry_attempt: u32) -> Duration {
    match empty_store_retry_attempt {
        0 => EMPTY_STORE_RETRY_1,
        1 => EMPTY_STORE_RETRY_2,
        _ => EMPTY_STORE_RETRY_MAX,
    }
}

fn next_refresh_deadline(
    fetch_started_at: Instant,
    fetch_completed_at: Instant,
    store_has_keys: bool,
    interval: Duration,
    empty_store_retry_attempt: u32,
) -> Instant {
    if store_has_keys {
        fetch_started_at + interval
    } else {
        fetch_completed_at + refresh_delay_after_attempt(false, interval, empty_store_retry_attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EMPTY_STORE_RETRY_1, EMPTY_STORE_RETRY_2, EMPTY_STORE_RETRY_MAX,
        empty_store_retry_interval, next_refresh_deadline, refresh_delay_after_attempt,
    };
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn populated_store_uses_configured_refresh_interval() {
        let interval = Duration::from_secs(900);
        assert_eq!(refresh_delay_after_attempt(true, interval, 2), interval);
    }

    #[test]
    fn empty_store_backs_off_until_capped_when_interval_is_longer() {
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 0),
            EMPTY_STORE_RETRY_1
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 1),
            EMPTY_STORE_RETRY_2
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 2),
            EMPTY_STORE_RETRY_MAX
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 12),
            EMPTY_STORE_RETRY_MAX
        );
    }

    #[test]
    fn empty_store_keeps_shorter_configured_interval() {
        let interval = Duration::from_secs(2);
        assert_eq!(refresh_delay_after_attempt(false, interval, 0), interval);
        assert_eq!(refresh_delay_after_attempt(false, interval, 1), interval);
        assert_eq!(refresh_delay_after_attempt(false, interval, 2), interval);
    }

    #[test]
    fn empty_store_retry_interval_uses_five_fifteen_thirty_sequence() {
        assert_eq!(empty_store_retry_interval(0), EMPTY_STORE_RETRY_1);
        assert_eq!(empty_store_retry_interval(1), EMPTY_STORE_RETRY_2);
        assert_eq!(empty_store_retry_interval(2), EMPTY_STORE_RETRY_MAX);
        assert_eq!(empty_store_retry_interval(u32::MAX), EMPTY_STORE_RETRY_MAX);
    }

    #[test]
    fn populated_store_next_refresh_is_based_on_fetch_start() {
        let started = Instant::now();
        let completed = started + Duration::from_secs(10);
        let interval = Duration::from_secs(60);

        assert_eq!(
            next_refresh_deadline(started, completed, true, interval, 0),
            started + interval
        );
    }

    #[test]
    fn empty_store_next_retry_is_based_on_fetch_completion() {
        let started = Instant::now();
        let completed = started + Duration::from_secs(10);
        let interval = Duration::from_secs(900);

        assert_eq!(
            next_refresh_deadline(started, completed, false, interval, 1),
            completed + EMPTY_STORE_RETRY_2
        );
    }
}
