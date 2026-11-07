//! Frontend TLS live-reload arming parity (issue #3857).
//!
//! `modes::startup_security` decides whether to install the live client-trust
//! handshake wrapper from `{proxy,admin}_frontend_live_reload_can_arm`, while
//! `prepare_{proxy,admin}_frontend_tls` decide whether to build the live slot
//! and watcher. If the two disagree, either the wrapper strips the
//! CertificateRequest CA hints on a listener that can never publish a
//! generation, or a generation is published on a listener whose handshakes were
//! never fenced. Both now classify through one shared source set; this file
//! pins that they agree across the configuration matrix, and that each listener
//! reads only its own `EnvConfig` fields (plus the shared CRL source).

use std::sync::{Arc, OnceLock};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::modes::tls_reload::{
    admin_frontend_live_reload_can_arm, prepare_admin_frontend_tls, prepare_proxy_frontend_tls,
    proxy_frontend_live_reload_can_arm,
};
use ferrum_edge::tls::{CrlList, TlsPolicy};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn ensure_crypto_provider() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_policy() -> TlsPolicy {
    ensure_crypto_provider();
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("tls policy")
}

struct SelfSigned {
    cert_pem: String,
    key_pem: String,
}

fn self_signed() -> SelfSigned {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("self-sign");
    SelfSigned {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn server_config(material: &SelfSigned) -> Arc<ServerConfig> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("cert pem");
    let key = PrivateKeyDer::from_pem_slice(material.key_pem.as_bytes()).expect("key pem");
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config"),
    )
}

#[derive(Clone, Copy, Debug)]
enum Listener {
    Proxy,
    Admin,
}

/// Material shapes for one listener's cert/key (and optionally its client CA
/// or OCSP response).
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// No cert/key configured for this listener.
    Absent,
    /// Cert and key as inline PEM, nothing else watched.
    InlineOnly,
    /// Cert and key as file paths.
    FileBacked,
    /// Inline cert/key, but a file-backed client-CA bundle.
    InlineWithFileClientCa,
    /// Inline cert/key, but a file-backed OCSP response.
    InlineWithFileOcsp,
}

struct Fixture {
    _dir: tempfile::TempDir,
    material: SelfSigned,
    cert_path: String,
    key_path: String,
    ca_path: String,
    ocsp_path: String,
    crl_path: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let material = self_signed();
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let (cert_path, key_path, ca_path, ocsp_path, crl_path) = (
        path("cert.pem"),
        path("key.pem"),
        path("ca.pem"),
        path("ocsp.der"),
        path("crl.pem"),
    );
    // The watcher only fingerprints files until a change is observed; the
    // rebuild closure is never invoked here.
    std::fs::write(&cert_path, &material.cert_pem).expect("write cert");
    std::fs::write(&key_path, &material.key_pem).expect("write key");
    std::fs::write(&ca_path, &material.cert_pem).expect("write ca");
    std::fs::write(&ocsp_path, b"placeholder ocsp").expect("write ocsp");
    std::fs::write(&crl_path, b"placeholder crl").expect("write crl");
    Fixture {
        _dir: dir,
        material,
        cert_path,
        key_path,
        ca_path,
        ocsp_path,
        crl_path,
    }
}

fn apply_shape(env: &mut EnvConfig, fx: &Fixture, listener: Listener, shape: Shape) {
    let inline_cert = || Some(fx.material.cert_pem.clone());
    let inline_key = || Some(fx.material.key_pem.clone());
    let (cert, key, client_ca, ocsp) = match shape {
        Shape::Absent => (None, None, None, None),
        Shape::InlineOnly => (inline_cert(), inline_key(), None, None),
        Shape::FileBacked => (
            Some(fx.cert_path.clone()),
            Some(fx.key_path.clone()),
            None,
            None,
        ),
        Shape::InlineWithFileClientCa => {
            (inline_cert(), inline_key(), Some(fx.ca_path.clone()), None)
        }
        Shape::InlineWithFileOcsp => (
            inline_cert(),
            inline_key(),
            None,
            Some(fx.ocsp_path.clone()),
        ),
    };
    match listener {
        Listener::Proxy => {
            env.frontend_tls_cert_path = cert;
            env.frontend_tls_key_path = key;
            env.frontend_tls_client_ca_bundle_path = client_ca;
            env.frontend_tls_ocsp_response_source = ocsp;
        }
        Listener::Admin => {
            env.admin_tls_cert_path = cert;
            env.admin_tls_key_path = key;
            env.admin_tls_client_ca_bundle_path = client_ca;
            env.admin_tls_ocsp_response_source = ocsp;
        }
    }
}

fn can_arm(listener: Listener, env: &EnvConfig) -> bool {
    match listener {
        Listener::Proxy => proxy_frontend_live_reload_can_arm(env),
        Listener::Admin => admin_frontend_live_reload_can_arm(env),
    }
}

/// Run the real `prepare_*` entry point and report whether it built a live
/// slot (and with it a watcher).
fn prepare_arms(listener: Listener, env: &EnvConfig, fx: &Fixture) -> bool {
    let policy = tls_policy();
    let crls: CrlList = Arc::new(Vec::new());
    let tls_config = server_config(&fx.material);
    match listener {
        Listener::Proxy => {
            let handles = prepare_proxy_frontend_tls(tls_config, None, env, &policy, &crls, None);
            assert_eq!(handles.slot.is_some(), handles.watcher_handle.is_some());
            assert_eq!(handles.slot.is_some(), handles.revision_rx.is_some());
            if let Some(handle) = handles.watcher_handle {
                handle.abort();
            }
            handles.slot.is_some()
        }
        Listener::Admin => {
            let handles = prepare_admin_frontend_tls(tls_config, None, env, &policy, &crls, None);
            assert_eq!(handles.slot.is_some(), handles.watcher_handle.is_some());
            if let Some(handle) = handles.watcher_handle {
                handle.abort();
            }
            handles.slot.is_some()
        }
    }
}

#[tokio::test]
async fn can_arm_matches_prepare_across_the_configuration_matrix() {
    let fx = fixture();
    for listener in [Listener::Proxy, Listener::Admin] {
        for live_reload in [false, true] {
            for shape in [
                Shape::Absent,
                Shape::InlineOnly,
                Shape::FileBacked,
                Shape::InlineWithFileClientCa,
                Shape::InlineWithFileOcsp,
            ] {
                for shared_crl in [false, true] {
                    let mut env = EnvConfig {
                        frontend_tls_live_reload_enabled: live_reload,
                        frontend_tls_watch_interval_seconds: 60,
                        tls_crl_file_path: shared_crl.then(|| fx.crl_path.clone()),
                        ..EnvConfig::default()
                    };
                    apply_shape(&mut env, &fx, listener, shape);

                    let expected = live_reload
                        && match shape {
                            Shape::Absent => false,
                            // All-inline material is static unless the shared
                            // CRL source is file-backed.
                            Shape::InlineOnly => shared_crl,
                            Shape::FileBacked
                            | Shape::InlineWithFileClientCa
                            | Shape::InlineWithFileOcsp => true,
                        };
                    let case = format!(
                        "{listener:?} live_reload={live_reload} shape={shape:?} \
                         shared_crl={shared_crl}"
                    );
                    assert_eq!(can_arm(listener, &env), expected, "can_arm: {case}");
                    assert_eq!(
                        prepare_arms(listener, &env, &fx),
                        expected,
                        "prepare: {case}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn each_listener_reads_only_its_own_tls_fields() {
    let fx = fixture();
    for (owner, other) in [
        (Listener::Proxy, Listener::Admin),
        (Listener::Admin, Listener::Proxy),
    ] {
        let mut env = EnvConfig {
            frontend_tls_live_reload_enabled: true,
            frontend_tls_watch_interval_seconds: 60,
            ..EnvConfig::default()
        };
        apply_shape(&mut env, &fx, owner, Shape::FileBacked);

        assert!(can_arm(owner, &env), "{owner:?} owns the configured fields");
        assert!(prepare_arms(owner, &env, &fx), "{owner:?} prepare");
        assert!(
            !can_arm(other, &env),
            "{other:?} must not arm from {owner:?}'s TLS fields"
        );
        assert!(
            !prepare_arms(other, &env, &fx),
            "{other:?} prepare must not read {owner:?}'s TLS fields"
        );
    }
}

#[tokio::test]
async fn client_ca_field_is_watched_as_listener_owned_material() {
    // The client-CA bundle is listener-owned: a file-backed admin CA makes
    // only admin reload refreshable, even when both listeners serve inline
    // certificates.
    let fx = fixture();
    let mut env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        frontend_tls_watch_interval_seconds: 60,
        ..EnvConfig::default()
    };
    apply_shape(&mut env, &fx, Listener::Proxy, Shape::InlineOnly);
    apply_shape(
        &mut env,
        &fx,
        Listener::Admin,
        Shape::InlineWithFileClientCa,
    );

    assert!(!can_arm(Listener::Proxy, &env));
    assert!(!prepare_arms(Listener::Proxy, &env, &fx));
    assert!(can_arm(Listener::Admin, &env));
    assert!(prepare_arms(Listener::Admin, &env, &fx));
}

#[tokio::test]
async fn ocsp_field_is_watched_as_listener_owned_material() {
    // The OCSP response source is listener-owned: with inline certificates on
    // both listeners and no shared CRL, a file-backed OCSP response makes only
    // its own listener refreshable. Run in both directions so swapping the
    // proxy/admin OCSP fields in the classifier fails here, and with live
    // reload off nothing arms at all.
    let fx = fixture();
    for (owner, other) in [
        (Listener::Proxy, Listener::Admin),
        (Listener::Admin, Listener::Proxy),
    ] {
        for live_reload in [false, true] {
            let mut env = EnvConfig {
                frontend_tls_live_reload_enabled: live_reload,
                frontend_tls_watch_interval_seconds: 60,
                ..EnvConfig::default()
            };
            apply_shape(&mut env, &fx, owner, Shape::InlineWithFileOcsp);
            apply_shape(&mut env, &fx, other, Shape::InlineOnly);

            let case = format!("ocsp owner={owner:?} live_reload={live_reload}");
            assert_eq!(can_arm(owner, &env), live_reload, "owner can_arm: {case}");
            assert_eq!(
                prepare_arms(owner, &env, &fx),
                live_reload,
                "owner prepare: {case}"
            );
            assert!(!can_arm(other, &env), "other can_arm: {case}");
            assert!(!prepare_arms(other, &env, &fx), "other prepare: {case}");
        }
    }
}
