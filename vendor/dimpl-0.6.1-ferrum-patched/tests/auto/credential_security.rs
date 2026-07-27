use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls, DtlsCertificate, DtlsCertificateChain, DtlsPrivateKey, ProtocolVersion};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

use crate::common::{default_config, deliver_packets, drain_outputs};

fn hooked_key(bytes: Vec<u8>, observations: Arc<Mutex<Vec<Vec<u8>>>>) -> DtlsPrivateKey {
    DtlsPrivateKey::new_with_drop_hook(bytes, move |zeroized| {
        observations
            .lock()
            .expect("lock zeroization observations")
            .push(zeroized.to_vec());
    })
}

#[test]
fn private_key_clones_and_failed_construction_zeroize_before_drop() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let key = hooked_key(vec![0xa5; 48], observations.clone());
    let clone_one = key.clone();
    let clone_two = clone_one.clone();

    drop(key);
    drop(clone_one);
    drop(clone_two);

    let failed_key = hooked_key(vec![0x5a; 48], observations.clone());
    assert!(DtlsCertificateChain::new(Vec::new(), failed_key).is_err());

    let observations = observations.lock().expect("lock zeroization observations");
    assert_eq!(observations.len(), 4);
    assert!(
        observations
            .iter()
            .all(|bytes| bytes.iter().all(|byte| *byte == 0)),
        "drop hook must observe only zeroized private-key storage"
    );
}

#[test]
fn dtls13_shutdown_zeroizes_retained_private_key_owner() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let mut identity = generate_self_signed_certificate().expect("identity");
    let chain = DtlsCertificateChain::new(
        vec![std::mem::take(&mut identity.certificate)],
        hooked_key(identity.private_key.as_slice().to_vec(), observations.clone()),
    )
    .expect("identity chain");
    let endpoint = Dtls::new_13(default_config(), chain, Instant::now());

    drop(endpoint);

    let observations = observations.lock().expect("lock zeroization observations");
    assert_eq!(observations.len(), 1);
    assert!(
        observations[0].iter().all(|byte| *byte == 0),
        "shutdown must clear the retained DTLS 1.3 fallback credential"
    );
}

#[test]
fn auto_server_fallback_zeroizes_transferred_private_key_owner() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let mut server_identity = generate_self_signed_certificate().expect("server identity");
    let server_chain = DtlsCertificateChain::new(
        vec![std::mem::take(&mut server_identity.certificate)],
        hooked_key(
            server_identity.private_key.as_slice().to_vec(),
            observations.clone(),
        ),
    )
    .expect("server chain");
    let client_identity = generate_self_signed_certificate().expect("client identity");
    let config = default_config();
    let now = Instant::now();
    let mut client = Dtls::new_12(config.clone(), client_identity, now);
    client.set_active(true);
    let mut server = Dtls::new_auto(config, server_chain, now);

    let mut tick = now;
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..80 {
        client.handle_timeout(tick).expect("client timeout");
        server.handle_timeout(tick).expect("server timeout");
        let client_output = drain_outputs(&mut client);
        let server_output = drain_outputs(&mut server);
        client_connected |= client_output.connected;
        server_connected |= server_output.connected;
        deliver_packets(&client_output.packets, &mut server);
        deliver_packets(&server_output.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        tick += Duration::from_millis(10);
    }

    assert!(client_connected && server_connected);
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::DTLS1_2));
    drop(server);

    let observations = observations.lock().expect("lock zeroization observations");
    assert!(!observations.is_empty());
    assert!(
        observations
            .iter()
            .all(|bytes| bytes.iter().all(|byte| *byte == 0)),
        "fallback and shutdown must zeroize every retained owner"
    );
}

fn assert_server_chain_transmitted_with_identity(
    version: ProtocolVersion,
    mut server_identity: DtlsCertificate,
    intermediates: Vec<Vec<u8>>,
) {
    let client_identity = generate_self_signed_certificate().expect("client identity");
    let mut expected_chain = vec![server_identity.certificate.clone()];
    expected_chain.extend(intermediates);
    let server_chain = DtlsCertificateChain::new(
        expected_chain.clone(),
        std::mem::take(&mut server_identity.private_key),
    )
    .expect("server chain");
    let config = Arc::new(Config::default());
    let now = Instant::now();
    let mut client = match version {
        ProtocolVersion::DTLS1_2 => Dtls::new_12(config.clone(), client_identity, now),
        ProtocolVersion::DTLS1_3 => Dtls::new_13(config.clone(), client_identity, now),
        other => panic!("unsupported test version: {other:?}"),
    };
    client.set_active(true);
    let mut server = match version {
        ProtocolVersion::DTLS1_2 => Dtls::new_12(config, server_chain, now),
        ProtocolVersion::DTLS1_3 => Dtls::new_13(config, server_chain, now),
        other => panic!("unsupported test version: {other:?}"),
    };

    let mut tick = now;
    let mut received_leaf = None;
    let mut received_chain = None;
    for _ in 0..80 {
        client.handle_timeout(tick).expect("client timeout");
        server.handle_timeout(tick).expect("server timeout");
        let client_output = drain_outputs(&mut client);
        let server_output = drain_outputs(&mut server);
        if client_output.peer_cert.is_some() {
            received_leaf = client_output.peer_cert;
        }
        if client_output.peer_cert_chain.is_some() {
            received_chain = client_output.peer_cert_chain;
        }
        deliver_packets(&client_output.packets, &mut server);
        deliver_packets(&server_output.packets, &mut client);
        if received_chain.is_some() {
            break;
        }
        tick += Duration::from_millis(10);
    }

    assert_eq!(received_leaf, Some(expected_chain[0].clone()));
    assert_eq!(received_chain, Some(expected_chain));
}

fn assert_server_chain_transmitted(version: ProtocolVersion) {
    assert_server_chain_transmitted_with_identity(
        version,
        generate_self_signed_certificate().expect("server identity"),
        vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
    );
}

fn large_server_identity() -> DtlsCertificate {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("large identity key");
    let names: Vec<String> = (0..128)
        .map(|index| format!("dtls-{index:03}.certificate-buffer-regression.example.test"))
        .collect();
    let params = CertificateParams::new(names).expect("large identity params");
    let certificate = params
        .self_signed(&key_pair)
        .expect("large self-signed identity");
    let identity = DtlsCertificate {
        certificate: certificate.der().to_vec(),
        private_key: key_pair.serialize_der(),
    };
    assert!(
        identity.certificate.len() > 2048,
        "fixture must exceed drain_outputs' poll buffer"
    );
    identity
}

#[test]
fn dtls12_transmits_full_certificate_chain_in_configured_order() {
    assert_server_chain_transmitted(ProtocolVersion::DTLS1_2);
}

#[test]
fn dtls13_transmits_full_certificate_chain_in_configured_order() {
    assert_server_chain_transmitted(ProtocolVersion::DTLS1_3);
}

#[test]
fn dtls12_peer_leaf_output_is_not_limited_by_poll_buffer() {
    assert_server_chain_transmitted_with_identity(
        ProtocolVersion::DTLS1_2,
        large_server_identity(),
        Vec::new(),
    );
}

#[test]
fn dtls13_peer_leaf_output_is_not_limited_by_poll_buffer() {
    assert_server_chain_transmitted_with_identity(
        ProtocolVersion::DTLS1_3,
        large_server_identity(),
        Vec::new(),
    );
}
