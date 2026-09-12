//! Signed no-AKI CRLs for compatibility tests. rcgen always emits AKI, so
//! remove only that extension from its fixture and sign the changed TBS again.

use base64::Engine;
use rcgen::SigningKey;
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

fn fields(mut der: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    while !der.is_empty() {
        let (_, header, length) = bounds(der);
        result.push(&der[..header + length]);
        der = &der[header + length..];
    }
    result
}

fn bounds(der: &[u8]) -> (u8, usize, usize) {
    let first = der[1];
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 0x7f);
        assert!(
            (1..=4).contains(&count),
            "fixture requires definite DER length"
        );
        let length = der[2..2 + count]
            .iter()
            .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
        (2 + count, length)
    };
    assert!(header + length <= der.len());
    (der[0], header, length)
}

fn content(der: &[u8]) -> &[u8] {
    let (_, header, length) = bounds(der);
    &der[header..header + length]
}

fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if body.len() < 128 {
        result.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        result.push(0x80 | (bytes.len() - first) as u8);
        result.extend_from_slice(&bytes[first..]);
    }
    result.extend_from_slice(body);
    result
}

pub fn without_authority_key_identifier(pem: &str, key: &rcgen::KeyPair, ca_pem: &str) -> String {
    let crl = rustls_pemfile::crls(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let outer = fields(content(crl.as_ref()));
    assert_eq!(outer.len(), 3);
    let mut tbs = fields(content(outer[0]));
    let extensions = tbs.pop().unwrap();
    assert_eq!(extensions[0], 0xa0);
    let extension_sequence = fields(content(extensions));
    assert_eq!(extension_sequence.len(), 1);
    let mut removed = 0;
    let remaining: Vec<u8> = fields(content(extension_sequence[0]))
        .into_iter()
        .filter(|extension| {
            let is_aki = fields(content(extension))[0] == [0x06, 0x03, 0x55, 0x1d, 0x23];
            removed += usize::from(is_aki);
            !is_aki
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(removed, 1);
    let extensions = wrap(0xa0, &wrap(0x30, &remaining));
    let mut body = tbs.concat();
    body.extend_from_slice(&extensions);
    let tbs = wrap(0x30, &body);
    let mut signature = vec![0]; // DER BIT STRING: zero unused bits.
    signature.extend_from_slice(&key.sign(&tbs).unwrap());
    let der = wrap(
        0x30,
        &[tbs.as_slice(), outer[1], &wrap(0x03, &signature)].concat(),
    );

    // Verify that this is genuinely signed by the supplied CA, not just a
    // parseable CRL whose signature was invalidated by extension removal.
    let ca = rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, ca) = X509Certificate::from_der(ca.as_ref()).unwrap();
    let (rest, parsed) = CertificateRevocationList::from_der(&der).unwrap();
    assert!(rest.is_empty());
    parsed.verify_signature(ca.public_key()).unwrap();
    assert!(parsed.extensions().iter().all(|extension| {
        extension.oid != x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
    }));
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN X509 CRL-----\n{encoded}\n-----END X509 CRL-----\n")
}
