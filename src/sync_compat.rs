//! Toolchain compatibility shim for atomic read-modify-write updates.
//!
//! Rust 1.99 deprecates `Atomic*::fetch_update` in favour of the renamed
//! `try_update`, which is stable only since Rust 1.95. The fuzz lanes
//! (`fuzz/rust-toolchain.toml`, `.github/workflows/fuzz.yml`, the fuzz job in
//! `.github/workflows/ci.yml`, and `.github/workflows/native-compiler-store.yml`)
//! still compile this crate on the pinned `nightly-2025-07-01` toolchain
//! (Rust 1.90), where `try_update` is unstable. Neither name therefore builds
//! warning-free on both toolchains.
//!
//! [`AtomicUpdate::update_with`] mirrors `fetch_update` exactly — same
//! arguments, same orderings, same closure contract, same result — and is the
//! single place the deprecation is allowed. Once every fuzz lane moves to a
//! nightly at or above Rust 1.95, call `try_update` directly and delete this
//! module (tracked by the fuzz-toolchain follow-up issue).

use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// `fetch_update` under a name that is not deprecated on any supported
/// toolchain. See the module docs for why this exists.
pub(crate) trait AtomicUpdate {
    /// The primitive value stored by the atomic.
    type Value;

    /// Fetches the value and applies `f` to it, storing the new value if `f`
    /// returns `Some`. Returns `Ok(previous)` on success and `Err(previous)`
    /// when `f` returns `None`. Identical to the std `fetch_update`.
    fn update_with<F>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<Self::Value, Self::Value>
    where
        F: FnMut(Self::Value) -> Option<Self::Value>;
}

macro_rules! impl_atomic_update {
    ($atomic:ty, $value:ty) => {
        impl AtomicUpdate for $atomic {
            type Value = $value;

            // Rust 1.99 deprecates `fetch_update`; `try_update` is unstable
            // on the pinned fuzz nightly. This is the one allowed call.
            #[allow(deprecated)]
            #[inline]
            fn update_with<F>(
                &self,
                set_order: Ordering,
                fetch_order: Ordering,
                f: F,
            ) -> Result<$value, $value>
            where
                F: FnMut($value) -> Option<$value>,
            {
                self.fetch_update(set_order, fetch_order, f)
            }
        }
    };
}

impl_atomic_update!(AtomicU8, u8);
impl_atomic_update!(AtomicU32, u32);
impl_atomic_update!(AtomicU64, u64);
impl_atomic_update!(AtomicI64, i64);
impl_atomic_update!(AtomicUsize, usize);
