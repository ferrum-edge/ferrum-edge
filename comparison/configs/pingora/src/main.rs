// Minimal Pingora reverse proxy for benchmark comparison.
// Mirrors Ferrum's comparison test setup: listens on 8000 (HTTP) and 8443 (HTTPS),
// proxies all requests to a backend on 127.0.0.1:3001 (HTTP) or 127.0.0.1:3443 (HTTPS).
//
// Usage:
//   pingora-bench-proxy --backend-port 3001
//   pingora-bench-proxy --backend-port 3001 --tls-cert cert.pem --tls-key key.pem
//   pingora-bench-proxy --backend-port 3443 --backend-tls   (for E2E TLS)

use async_trait::async_trait;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use std::env;

struct BenchProxy {
    backend_addr: String,
    backend_tls: bool,
}

#[async_trait]
impl ProxyHttp for BenchProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            &self.backend_addr as &str,
            self.backend_tls,
            String::new(),
        ));
        Ok(peer)
    }
}

fn main() {
    env_logger::init();

    let http_port = env::var("PINGORA_HTTP_PORT").unwrap_or_else(|_| "8000".to_string());
    let https_port = env::var("PINGORA_HTTPS_PORT").unwrap_or_else(|_| "8443".to_string());
    let backend_host = env::var("PINGORA_BACKEND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let backend_port = env::var("PINGORA_BACKEND_PORT").unwrap_or_else(|_| "3001".to_string());
    let backend_tls = env::var("PINGORA_BACKEND_TLS").unwrap_or_else(|_| "false".to_string()) == "true";
    let tls_cert = env::var("PINGORA_TLS_CERT").ok();
    let tls_key = env::var("PINGORA_TLS_KEY").ok();

    let backend_addr = format!("{}:{}", backend_host, backend_port);
    eprintln!(
        "Pingora bench proxy: HTTP={}, HTTPS={}, backend={} (tls={})",
        http_port, https_port, backend_addr, backend_tls
    );

    let opt = Opt::default();
    let mut server = Server::new(Some(opt)).expect("Failed to create Pingora server");
    server.bootstrap();

    let proxy = BenchProxy {
        backend_addr: backend_addr.clone(),
        backend_tls,
    };

    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&format!("0.0.0.0:{}", http_port));

    if let (Some(cert), Some(key)) = (&tls_cert, &tls_key) {
        let tls_settings =
            pingora_core::listeners::tls::TlsSettings::intermediate(cert, key)
                .expect("Failed to load TLS settings");
        service.add_tls_with_settings(
            &format!("0.0.0.0:{}", https_port),
            None,
            tls_settings,
        );
        eprintln!("HTTPS listener on port {}", https_port);
    }

    server.add_service(service);
    eprintln!("Pingora bench proxy running");
    server.run_forever();
}
