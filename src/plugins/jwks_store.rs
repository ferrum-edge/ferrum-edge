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
use tracing::{debug, warn};

use super::utils::PluginHttpClient;

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
        }
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
        debug!("Fetching JWKS keys from {}", self.jwks_uri);

        let response = self
            .http_client
            .get()
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("JWKS endpoint returned HTTP {}", response.status()));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {}", e))?;

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
        self.keys.store(Arc::new(new_keys));
        debug!("JWKS key store updated: {} keys cached", count);
        Ok(count)
    }

    /// Start a background task that refreshes keys periodically.
    ///
    /// The task runs until the returned [`tokio::task::JoinHandle`] is aborted
    /// or the process exits.
    pub fn start_background_refresh(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            // Skip the first tick (keys are fetched eagerly at startup)
            timer.tick().await;
            loop {
                timer.tick().await;
                if let Err(e) = store.fetch_keys().await {
                    warn!("JWKS background refresh failed: {}", e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_store_has_no_keys() {
        let store = JwksKeyStore::new(
            "https://example.com/.well-known/jwks.json".to_string(),
            PluginHttpClient::default(),
        );
        assert!(!store.has_keys());
        assert!(store.get_key("nonexistent").is_none());
    }
}
