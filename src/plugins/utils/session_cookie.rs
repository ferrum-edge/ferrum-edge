use crate::fips::backend::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use crate::fips::backend::hkdf::{HKDF_SHA256, KeyType, Salt};
use crate::fips::backend::rand::{SecureRandom, SystemRandom};
use base64::Engine;

const SALT: &[u8] = b"ferrum-edge oidc-rp session v1";
const INFO: &[u8] = b"AEAD-AES-256-GCM";
const NONCE_LEN: usize = 12;

struct Aes256KeyLen;

impl KeyType for Aes256KeyLen {
    fn len(&self) -> usize {
        32
    }
}

pub struct SessionCookieCodec {
    current: LessSafeKey,
    previous: Option<LessSafeKey>,
    max_cookie_bytes: usize,
    rng: SystemRandom,
    aad: Vec<u8>,
}

impl SessionCookieCodec {
    /// Convenience constructor with no additional AAD, used only by tests;
    /// production paths use `new_with_aad` for context binding.
    #[cfg(test)]
    pub fn new(
        current_secret: &str,
        previous_secret: Option<&str>,
        max_cookie_bytes: usize,
    ) -> Result<Self, String> {
        Self::new_with_aad(current_secret, previous_secret, max_cookie_bytes, &[])
    }

    /// Build a codec that cryptographically binds every sealed value to
    /// `associated_data`.
    ///
    /// The associated data is authenticated but not encrypted or serialized
    /// into the cookie. Callers should pass a stable, versioned context that
    /// identifies the trust boundary in which the cookie is valid.
    pub fn new_with_aad(
        current_secret: &str,
        previous_secret: Option<&str>,
        max_cookie_bytes: usize,
        associated_data: &[u8],
    ) -> Result<Self, String> {
        Ok(Self {
            current: derive_key(current_secret)?,
            previous: previous_secret.map(derive_key).transpose()?,
            max_cookie_bytes,
            rng: SystemRandom::new(),
            aad: associated_data.to_vec(),
        })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<String, String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| "session_cookie: random nonce generation failed".to_string())?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.current
            .seal_in_place_append_tag(nonce, Aad::from(self.aad.as_slice()), &mut in_out)
            .map_err(|_| "session_cookie: seal failed".to_string())?;
        let mut encoded = Vec::with_capacity(NONCE_LEN + in_out.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&in_out);
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded);
        if value.len() > self.max_cookie_bytes {
            return Err("session_cookie: sealed payload exceeds max_cookie_bytes".to_string());
        }
        Ok(value)
    }

    pub fn open(&self, value: &str) -> Option<Vec<u8>> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .ok()?;
        if decoded.len() <= NONCE_LEN {
            return None;
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let nonce_array: [u8; NONCE_LEN] = nonce_bytes.try_into().ok()?;
        self.open_with_key(&self.current, nonce_array, ciphertext)
            .or_else(|| {
                self.previous
                    .as_ref()
                    .and_then(|key| self.open_with_key(key, nonce_array, ciphertext))
            })
    }

    fn open_with_key(
        &self,
        key: &LessSafeKey,
        nonce_bytes: [u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = ciphertext.to_vec();
        key.open_in_place(nonce, Aad::from(self.aad.as_slice()), &mut in_out)
            .ok()
            .map(|plaintext| plaintext.to_vec())
    }
}

/// Literal OIDC session-secret values that are known to be public: Ferrum
/// Edge's own documented placeholder, the key Ferrum Foundry's OIDC template
/// published (GHSA-hjw6-685j-p5hw), and the fixtures Edge's own tests and
/// examples used for `session.encryption_secret`. Anyone reading the
/// repository can hold these, so accepting one as an AEAD key would let a third
/// party forge or decrypt session and pending-flow cookies.
///
/// Keep this list small and exact. Length is validated separately, and a
/// genuinely random operator secret must never collide with an entry here.
const DENIED_SESSION_SECRETS: &[&str] = &[
    "${OIDC_SESSION_SECRET_32_BYTES_MIN}",
    "change-me-32-byte-minimum-secret!!",
    "9f3a7c1e5b2d8406a1c9e7f3b5d20486ab",
    "2d8b6f0a4c1e9375b8d2f6a0c4e19753",
    "01234567890123456789012345678901",
    "0123456789012345678901234567890123",
    "abcdefghijklmnopqrstuvwxyz123456",
];

/// Case-insensitive substrings that mark an obvious placeholder secret.
const DENIED_SESSION_SECRET_SUBSTRINGS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "replace-me",
    "replace_me",
    "placeholder",
    "your-secret",
    "your_secret",
];

/// Reject a `session.encryption_secret` or `session.encryption_secret_previous`
/// value that is a published or placeholder secret. `field` is the dotted
/// config path used in the error so an Admin API 400 names the offending key.
///
/// Screen both the supplied spelling and the effective pre-HKDF key material,
/// using the same normalization as key derivation. A `${NAME}` env placeholder
/// anywhere in either value is refused as well: it would be stored literally
/// rather than resolved before admission.
pub fn reject_published_session_secret(secret: &str, field: &str) -> Result<(), String> {
    // Known public values and templates are textual; binary Base64 key
    // material remains supported without interpreting it as a template.
    if contains_unresolved_env_placeholder(secret) {
        return Err(format!(
            "oidc_relying_party: `{field}` contains an unresolved `${{NAME}}` placeholder"
        ));
    }
    let normalized = normalize_secret(secret)?;
    let decoded = std::str::from_utf8(&normalized).ok();
    if decoded.is_some_and(contains_unresolved_env_placeholder) {
        return Err(format!(
            "oidc_relying_party: `{field}` contains an unresolved `${{NAME}}` placeholder"
        ));
    }
    if is_denied_session_secret(secret) || decoded.is_some_and(is_denied_session_secret) {
        return Err(format!(
            "oidc_relying_party: `{field}` must not be a published or placeholder secret; \
             generate a unique random value"
        ));
    }
    Ok(())
}

fn is_denied_session_secret(secret: &str) -> bool {
    let trimmed = secret.trim();
    let lowered = trimmed.to_ascii_lowercase();
    let denied_exact = DENIED_SESSION_SECRETS
        .iter()
        .any(|known| trimmed.eq_ignore_ascii_case(known));
    let denied_substring = DENIED_SESSION_SECRET_SUBSTRINGS
        .iter()
        .any(|token| lowered.contains(*token));
    denied_exact || denied_substring
}

fn contains_unresolved_env_placeholder(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    let mut offset = 0;
    while let Some(relative_start) = secret[offset..].find("${") {
        let start = offset + relative_start;
        let name_start = start + 2;
        let Some(first) = bytes.get(name_start).copied() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == b'_') {
            offset = name_start;
            continue;
        }
        let mut end = name_start + 1;
        while bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            end += 1;
        }
        if bytes.get(end) == Some(&b'}') {
            return true;
        }
        offset = name_start;
    }
    false
}

pub fn normalize_secret(secret: &str) -> Result<Vec<u8>, String> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(secret)
        && decoded.len() >= 32
    {
        return Ok(decoded);
    }
    if secret.len() < 32 {
        return Err(
            "session_cookie: encryption secret must be at least 32 bytes/chars".to_string(),
        );
    }
    Ok(secret.as_bytes().to_vec())
}

fn derive_key(secret: &str) -> Result<LessSafeKey, String> {
    let ikm = normalize_secret(secret)?;
    let salt = Salt::new(HKDF_SHA256, SALT);
    let prk = salt.extract(&ikm);
    let okm = prk
        .expand(&[INFO], Aes256KeyLen)
        .map_err(|_| "session_cookie: HKDF expand failed".to_string())?;
    let mut key_bytes = [0u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| "session_cookie: HKDF fill failed".to_string())?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| "session_cookie: AEAD key creation failed".to_string())?;
    Ok(LessSafeKey::new(unbound))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "9f3a7c1e5b2d8406a1c9e7f3b5d20486";

    #[test]
    fn seal_open_roundtrip_recovers_payload() {
        let codec = SessionCookieCodec::new(SECRET, None, 4000).expect("codec");
        let sealed = codec.seal(br#"{"sub":"user"}"#).expect("seal");
        assert_eq!(
            codec.open(&sealed).as_deref(),
            Some(&br#"{"sub":"user"}"#[..])
        );
    }

    #[test]
    fn open_with_wrong_key_returns_none() {
        let codec = SessionCookieCodec::new(SECRET, None, 4000).expect("codec");
        let other =
            SessionCookieCodec::new("2d8b6f0a4c1e9375b8d2f6a0c4e19753", None, 4000).expect("codec");
        let sealed = codec.seal(b"payload").expect("seal");
        assert!(other.open(&sealed).is_none());
    }

    #[test]
    fn large_payload_above_cap_seal_fails() {
        let codec = SessionCookieCodec::new(SECRET, None, 10).expect("codec");
        assert!(codec.seal(b"payload").is_err());
    }

    #[test]
    fn associated_data_prevents_cross_context_reuse() {
        let first =
            SessionCookieCodec::new_with_aad(SECRET, None, 4000, b"issuer-a").expect("first codec");
        let second = SessionCookieCodec::new_with_aad(SECRET, None, 4000, b"issuer-b")
            .expect("second codec");
        let sealed = first.seal(b"payload").expect("seal");

        assert_eq!(first.open(&sealed).as_deref(), Some(&b"payload"[..]));
        assert!(second.open(&sealed).is_none());
    }
}
