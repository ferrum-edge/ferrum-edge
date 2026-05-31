//! Shared jittered exponential backoff helpers.

use std::time::Duration;

use ring::rand::SecureRandom;

pub const BACKOFF_INITIAL_SECS: u64 = 1;
pub const BACKOFF_MAX_SECS: u64 = 30;

pub fn jittered_backoff(backoff_secs: u64) -> Duration {
    jittered_backoff_with_entropy(backoff_secs, random_backoff_entropy())
}

pub fn random_backoff_entropy() -> u64 {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 8];
    if rng.fill(&mut bytes).is_ok() {
        return u64::from_ne_bytes(bytes);
    }

    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn jittered_backoff_with_entropy(backoff_secs: u64, entropy: u64) -> Duration {
    let base_ms = backoff_secs.saturating_mul(1000);
    let jitter_range_ms = base_ms / 4;
    let jitter_ms = if jitter_range_ms > 0 {
        let full_range = jitter_range_ms.saturating_mul(2);
        (entropy % full_range) as i128 - jitter_range_ms as i128
    } else {
        0
    };
    let sleep_ms = (base_ms as i128 + jitter_ms).max(100) as u64;
    Duration::from_millis(sleep_ms)
}

pub fn next_backoff_secs(current_secs: u64, increase: bool) -> u64 {
    if increase {
        current_secs.saturating_mul(2).min(BACKOFF_MAX_SECS)
    } else {
        BACKOFF_INITIAL_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_backoff_resets_after_clean_stream_end() {
        assert_eq!(
            next_backoff_secs(BACKOFF_INITIAL_SECS, false),
            BACKOFF_INITIAL_SECS
        );
        assert_eq!(next_backoff_secs(16, false), BACKOFF_INITIAL_SECS);
    }

    #[test]
    fn next_backoff_increases_until_cap() {
        assert_eq!(next_backoff_secs(1, true), 2);
        assert_eq!(next_backoff_secs(16, true), 30);
        assert_eq!(next_backoff_secs(30, true), 30);
    }

    #[test]
    fn jittered_backoff_with_entropy_stays_within_expected_range() {
        let samples = [0, 249, 250, 499, u64::MAX];

        for entropy in samples {
            let duration = jittered_backoff_with_entropy(1, entropy);
            assert!(duration >= Duration::from_millis(750));
            assert!(duration < Duration::from_millis(1250));
        }
    }

    #[test]
    fn jittered_backoff_preserves_max_backoff_floor() {
        for entropy in [0, 1, 7_499, u64::MAX] {
            let duration = jittered_backoff_with_entropy(BACKOFF_MAX_SECS, entropy);
            assert!(duration >= Duration::from_millis(22_500));
            assert!(duration < Duration::from_millis(37_500));
        }
    }

    #[test]
    fn jittered_backoff_never_sleeps_below_minimum() {
        assert_eq!(
            jittered_backoff_with_entropy(0, 0),
            Duration::from_millis(100)
        );
    }
}
