//! Hosted-only H3 identity fixture. No throughput result is produced here.
use anyhow::{Context, bail};
use bytes::{Buf, Bytes};
use multi_protocol_perf::tls_utils;
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

fn certificates() -> anyhow::Result<()> {
    let dir = Path::new("certs");
    std::fs::create_dir_all(dir)?;
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = params.self_signed(&key)?;
    std::fs::write(dir.join("ca.pem"), ca.pem())?;
    for (name, dns) in [("valid", "localhost"), ("wrong", "wrong.invalid")] {
        let leaf_key = rcgen::KeyPair::generate()?;
        // Wrong leaf deliberately retains the connect IP SAN. Only DNS identity
        // distinguishes the two; a regression to IP verification must fail.
        let mut params = rcgen::CertificateParams::new(vec![dns.to_owned()])?;
        params.subject_alt_names.push(rcgen::SanType::IpAddress(
            "127.0.0.1".parse().context("fixed IP")?,
        ));
        let leaf = params.signed_by(&leaf_key, &ca, &key)?;
        std::fs::write(dir.join(format!("{name}.pem")), leaf.pem() + &ca.pem())?;
        std::fs::write(dir.join(format!("{name}.key")), leaf_key.serialize_pem())?;
    }
    std::fs::copy(dir.join("valid.pem"), dir.join("cert.pem"))?;
    std::fs::copy(dir.join("valid.key"), dir.join("key.pem"))?;
    Ok(())
}

fn config(identity: &str) -> anyhow::Result<quinn::ServerConfig> {
    tls_utils::make_h3_server_config(
        &Path::new("certs").join(format!("{identity}.pem")),
        &Path::new("certs").join(format!("{identity}.key")),
    )
}

async fn backend() -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(config("valid")?, "127.0.0.1:3445".parse()?)?;
    // A TCP accept here is evidence of attempted fallback, never an HTTP server.
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:3445").await?;
    let mut commands = BufReader::new(tokio::io::stdin()).lines();
    let mut connections = Vec::<quinn::Connection>::new();
    let mut identity = "valid";
    println!("{}", json!({"event": "ready", "identity": identity}));
    loop {
        tokio::select! {
            line = commands.next_line() => {
                let Some(line) = line? else {
                    break;
                };
                identity = match line.as_str() {
                    "valid" => "valid",
                    "wrong" => "wrong",
                    _ => bail!("unknown identity command"),
                };
                endpoint.set_server_config(Some(config(identity)?));
                for conn in connections.drain(..) {
                    conn.close(0u32.into(), b"identity fixture certificate transition");
                }
                println!("{}", json!({"event": "identity", "identity": identity}));
            }
            accepted = tcp.accept() => {
                let (stream, peer) = accepted?;
                println!("{}", json!({"event": "tcp_fallback", "identity": identity, "peer": peer.to_string()}));
                drop(stream);
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let peer = incoming.remote_address();
                // Bound each handshake; fixture requests are sequential.
                let conn = match tokio::time::timeout(Duration::from_secs(10), incoming).await {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(error)) => {
                        let crypto_close = matches!(&error, quinn::ConnectionError::ConnectionClosed(close)
                            if (0x100..=0x1ff).contains(&u64::from(close.error_code)));
                        println!("{}", json!({"event": "handshake_rejected", "identity": identity,
                            "peer": peer.to_string(), "crypto_close": crypto_close, "error": error.to_string()}));
                        continue;
                    }
                    Err(error) => {
                        println!("{}", json!({"event": "handshake_timeout", "identity": identity,
                            "peer": peer.to_string(), "error": error.to_string()}));
                        continue;
                    }
                };
                let sni = conn.handshake_data()
                    .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|data| data.server_name);
                println!("{}", json!({"event": "handshake", "identity": identity,
                    "peer": peer.to_string(), "sni": sni}));
                connections.push(conn.clone());
                if connections.len() > 256 {
                    bail!("connection cap");
                }
                tokio::spawn(async move {
                    let result = async {
                        let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await?;
                        while let Some(resolver) = h3.accept().await? {
                            let (request, mut stream) = resolver.resolve_request().await?;
                            let mut body = Vec::new();
                            while let Some(mut chunk) = stream.recv_data().await? {
                                if body.len() + chunk.remaining() > 10240 {
                                    bail!("request cap");
                                }
                                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                            }
                            if request.uri().path() != "/echo" {
                                bail!("unexpected request path");
                            }
                            stream.send_response(http::Response::builder().status(200).body(())?).await?;
                            let body_len = body.len();
                            stream.send_data(Bytes::from(body)).await?;
                            stream.finish().await?;
                            println!("{}", json!({"event": "echo", "identity": identity, "bytes": body_len}));
                        }
                        Ok::<(), anyhow::Error>(())
                    }.await;
                    if let Err(error) = result {
                        println!("{}", json!({"event": "connection_end", "identity": identity, "error": error.to_string()}));
                    }
                });
            }
        }
    }
    Ok(())
}

async fn request() -> anyhow::Result<()> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(tls_utils::make_h3_client_config_insecure());
    let conn = endpoint
        .connect("127.0.0.1:8443".parse()?, "localhost")?
        .await?;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let driver =
        tokio::spawn(
            async move { futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await },
        );
    let payload = vec![0x5a; 10240];
    let mut stream = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("https://localhost:8443/echo")
                .body(())?,
        )
        .await?;
    stream.send_data(Bytes::from(payload.clone())).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if body.len() + chunk.remaining() > 65536 {
            bail!("response cap");
        }
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    println!(
        "{}",
        json!({"status": response.status().as_u16(), "bytes": body.len(),
        "exact_body": body == payload, "protocol": "h3", "offered_requests": 1,
        "offered_bytes": payload.len(), "retries": 0})
    );
    drop(stream);
    drop(sender);
    endpoint.close(0u32.into(), b"fixture complete");
    endpoint.wait_idle().await;
    driver.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
    {
        bail!("hosted fixture only");
    }
    match std::env::args().nth(1).as_deref() {
        Some("certificates") => certificates(),
        Some("backend") => tokio::time::timeout(Duration::from_secs(120), backend()).await?,
        Some("request") => tokio::time::timeout(Duration::from_secs(20), request()).await?,
        _ => bail!("expected certificates, backend, or request"),
    }
}
