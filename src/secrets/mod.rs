//! Secret resolution with pluggable backends.
//!
//! Any `FERRUM_*` environment variable can be loaded from an external source
//! by setting a suffixed variant instead of the variable itself.
//!
//! Startup secret resolution finishes before non-blocking logging and the
//! multi-threaded gateway runtime, and its temporary runtime is dropped before
//! env mutation happens.

#[cfg(feature = "secrets-aws")]
mod aws;
#[cfg(feature = "secrets-azure")]
mod azure;
pub mod env;
pub mod file;
#[cfg(feature = "secrets-gcp")]
mod gcp;
mod registry;
#[cfg(feature = "secrets-vault")]
mod vault;

#[cfg(any(feature = "secrets-aws", feature = "secrets-vault"))]
pub(crate) fn split_reference_field(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once('#') {
        Some((base, field)) => (base, Some(field)),
        None => (reference, None),
    }
}

#[allow(unused_imports)]
pub use registry::{
    ResolvedEnvSecrets, ResolvedSecret, resolve_all_env_secrets, resolve_external_reference,
    resolve_secret,
};

#[cfg(all(test, any(feature = "secrets-aws", feature = "secrets-vault")))]
mod tests {
    use super::split_reference_field;

    #[test]
    fn split_reference_field_handles_optional_suffix() {
        assert_eq!(
            split_reference_field("secret/data/app#password"),
            ("secret/data/app", Some("password"))
        );
        assert_eq!(
            split_reference_field("secret/data/app"),
            ("secret/data/app", None)
        );
    }
}
