use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use std::error::Error;
use tracing::{info, error, debug};
use tokio::net::{TcpListener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    
    // Use a simple approach - start a regular WebSocket server on port 8443
    // We'll test the gateway's ability to proxy to it, even without TLS
    // The gateway will handle the TLS termination
    let addr = "127.0.0.1:8443";
    let listener = TcpListener::bind(addr).await?;
    info!("🔐 Echo server for secure gateway testing listening on: {}", addr);
    
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("🔗 New connection from: {}", addr);
        
        tokio::spawn(async move {
            match accept_async(stream).await {
                Ok(ws_stream) => {
                    info!("🌐 WebSocket handshake completed for: {}", addr);
                    handle_websocket_connection(ws_stream, addr).await;
                }
                Err(e) => {
                    error!("❌ WebSocket handshake failed: {}", e);
                }
            }
        });
    }
}

async fn handle_websocket_connection(
    mut ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    addr: std::net::SocketAddr,
) {
    info!("🔄 Starting secure echo for: {}", addr);
    
    while let Some(msg) = ws_stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let echo_text = format!("Secure Echo: {}", text);
                info!("📤 Echoing secure text: {}", echo_text);
                if let Err(e) = ws_stream.send(Message::Text(echo_text)).await {
                    error!("❌ Failed to send echo: {}", e);
                    break;
                }
            }
            Ok(Message::Binary(data)) => {
                let echo_text = format!("Secure Echo Binary: {} bytes", data.len());
                info!("📤 Echoing secure binary: {}", echo_text);
                if let Err(e) = ws_stream.send(Message::Text(echo_text)).await {
                    error!("❌ Failed to send binary echo: {}", e);
                    break;
                }
            }
            Ok(Message::Ping(data)) => {
                info!("🏓 Received secure ping, sending pong");
                if let Err(e) = ws_stream.send(Message::Pong(data)).await {
                    error!("❌ Failed to send pong: {}", e);
                    break;
                }
            }
            Ok(Message::Close(_)) => {
                info!("🔚 Client sent secure close frame");
                break;
            }
            Ok(Message::Pong(_)) => {
                info!("🏓 Received secure pong");
            }
            Ok(Message::Frame(_)) => {
                debug!("📋 Received secure raw frame");
            }
            Err(e) => {
                error!("❌ Error receiving secure message: {}", e);
                break;
            }
        }
    }
    
    info!("🔚 Secure WebSocket connection closed for: {}", addr);
}
