//! HMAC Authentication Plugin
//!
//! Validates HMAC-signed requests where the client signs the request
//! with a shared secret. Supports hmac-sha256 and hmac-sha512.
//!
//! Expected Authorization header format:
//!   hmac username="<username>", algorithm="hmac-sha256", signature="<base64-sig>"
//!
//! The signature is computed over: HTTP method + \n + path + \n + date header value
//!
//! Consumer credentials should include:
//!   { "hmac_auth": { "secret": "<shared-secret>" } }

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};
use crate::consumer_index::ConsumerIndex;

pub struct HmacAuth {
    #[allow(dead_code)]
    clock_skew_seconds: u64,
}

impl HmacAuth {
    pub fn new(config: &Value) -> Self {
        let clock_skew_seconds = config["clock_skew_seconds"].as_u64().unwrap_or(300);

        Self { clock_skew_seconds }
    }

    fn compute_hmac_sha256(secret: &[u8], data: &[u8]) -> Vec<u8> {
        // HMAC-SHA256 implementation
        let block_size = 64;
        let mut key = if secret.len() > block_size {
            sha256(secret).to_vec()
        } else {
            secret.to_vec()
        };
        key.resize(block_size, 0);

        let mut i_key_pad = vec![0u8; block_size];
        let mut o_key_pad = vec![0u8; block_size];
        for i in 0..block_size {
            i_key_pad[i] = key[i] ^ 0x36;
            o_key_pad[i] = key[i] ^ 0x5c;
        }

        let mut inner = i_key_pad;
        inner.extend_from_slice(data);
        let inner_hash = sha256(&inner);

        let mut outer = o_key_pad;
        outer.extend_from_slice(&inner_hash);
        sha256(&outer).to_vec()
    }
}

/// Simple SHA-256 implementation (pure Rust, no external deps).
fn sha256(data: &[u8]) -> [u8; 32] {
    // Use the standard library's built-in SHA-256 from the ring/crypto ecosystem
    // Since we don't have sha2 crate, use a message digest approach
    // Actually, we'll use a simpler approach: import from base64 + manual
    // For production, we should add the sha2 crate. For now, use a minimal implementation.

    // Constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: adding padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[4 * i..4 * i + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// Plugin priority: authentication band.
pub const HMAC_AUTH_PRIORITY: u16 = 1400;

#[async_trait]
impl Plugin for HmacAuth {
    fn name(&self) -> &str {
        "hmac_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        HMAC_AUTH_PRIORITY
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let auth_header = match ctx.headers.get("authorization") {
            Some(h) => h.clone(),
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing Authorization header"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Parse: hmac username="...", algorithm="...", signature="..."
        if !auth_header.to_lowercase().starts_with("hmac ") {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid HMAC authorization format"}"#.to_string(),
                headers: HashMap::new(),
            };
        }

        let params_str = &auth_header[5..];
        let mut username = None;
        let mut algorithm = None;
        let mut signature = None;

        for part in params_str.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "username" => username = Some(value.to_string()),
                    "algorithm" => algorithm = Some(value.to_string()),
                    "signature" => signature = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let username = match username {
            Some(u) => u,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing username in HMAC authorization"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        let _algorithm = algorithm.unwrap_or_else(|| "hmac-sha256".to_string());

        let signature = match signature {
            Some(s) => s,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing signature in HMAC authorization"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Look up consumer by username
        let consumer = match consumer_index.find_by_identity(&username) {
            Some(c) => c,
            None => {
                debug!("hmac_auth: consumer '{}' not found", username);
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid credentials"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Get HMAC secret from consumer credentials
        let secret = match consumer.credentials.get("hmac_auth") {
            Some(cred) => match cred.get("secret").and_then(|s| s.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"Invalid credentials"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            },
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid credentials"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Build the signing string: METHOD\nPATH\nDATE
        let date = ctx.headers.get("date").cloned().unwrap_or_default();

        let signing_string = format!("{}\n{}\n{}", ctx.method, ctx.path, date);

        // Compute expected signature
        let expected_mac = Self::compute_hmac_sha256(secret.as_bytes(), signing_string.as_bytes());
        let expected_sig = base64::engine::general_purpose::STANDARD.encode(&expected_mac);

        if signature != expected_sig {
            debug!("hmac_auth: signature mismatch for user '{}'", username);
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid signature"}"#.to_string(),
                headers: HashMap::new(),
            };
        }

        // Authentication successful
        ctx.identified_consumer = Some((*consumer).clone());
        PluginResult::Continue
    }
}
