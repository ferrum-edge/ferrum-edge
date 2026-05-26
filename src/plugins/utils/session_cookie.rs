use base64::Engine;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::{SecureRandom, SystemRandom};

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
}

impl SessionCookieCodec {
    pub fn new(
        current_secret: &str,
        previous_secret: Option<&str>,
        max_cookie_bytes: usize,
    ) -> Result<Self, String> {
        Ok(Self {
            current: derive_key(current_secret)?,
            previous: previous_secret.map(derive_key).transpose()?,
            max_cookie_bytes,
            rng: SystemRandom::new(),
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
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
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
        key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .ok()
            .map(|plaintext| plaintext.to_vec())
    }
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

    const SECRET: &str = "01234567890123456789012345678901";

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
            SessionCookieCodec::new("abcdefghijklmnopqrstuvwxyz123456", None, 4000).expect("codec");
        let sealed = codec.seal(b"payload").expect("seal");
        assert!(other.open(&sealed).is_none());
    }

    #[test]
    fn large_payload_above_cap_seal_fails() {
        let codec = SessionCookieCodec::new(SECRET, None, 10).expect("codec");
        assert!(codec.seal(b"payload").is_err());
    }
}
