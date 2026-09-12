//! `FERRUM_TLS_OFFLOAD_THREADS` is reserved: `0`/unset is accepted, nonzero
//! fails closed.
//!
//! These tests mutate process-global environment variables, so they MUST run
//! serially through the shared [`crate::unit::env_lock::ENV_LOCK`].

use ferrum_edge::config::EnvConfig;

use crate::unit::env_lock::with_env_vars;

const TLS_OFFLOAD_NOT_IMPLEMENTED: &str =
    "FERRUM_TLS_OFFLOAD_THREADS must remain 0; TLS handshake offload is not implemented";

const FILE_MODE: &[(&str, &str)] = &[
    ("FERRUM_MODE", "file"),
    ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
];

#[test]
fn tls_offload_threads_unset_defaults_to_zero() {
    with_env_vars(FILE_MODE, || {
        let config =
            EnvConfig::from_env().expect("unset FERRUM_TLS_OFFLOAD_THREADS must be accepted");
        assert_eq!(config.tls_offload_threads, 0);
    });
}

#[test]
fn tls_offload_threads_zero_is_accepted() {
    let mut vars = FILE_MODE.to_vec();
    vars.push(("FERRUM_TLS_OFFLOAD_THREADS", "0"));
    with_env_vars(&vars, || {
        let config = EnvConfig::from_env().expect("FERRUM_TLS_OFFLOAD_THREADS=0 must be accepted");
        assert_eq!(config.tls_offload_threads, 0);
    });
}

#[test]
fn tls_offload_threads_nonzero_is_rejected() {
    let mut vars = FILE_MODE.to_vec();
    vars.push(("FERRUM_TLS_OFFLOAD_THREADS", "8"));
    with_env_vars(&vars, || {
        let error =
            EnvConfig::from_env().expect_err("nonzero FERRUM_TLS_OFFLOAD_THREADS must fail closed");
        assert_eq!(error, TLS_OFFLOAD_NOT_IMPLEMENTED);
    });
}
