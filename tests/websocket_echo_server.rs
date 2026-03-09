use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use std::error::Error;
use tracing::{info, error, debug};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).await?;
    info!("WebSocket echo server listening on: {}", addr);
    
    loop {
        let (_stream, addr) = listener.accept().await?;
        info!("New connection from: {}", addr);
        
        tokio::spawn(async move {
            let ws_stream = match accept_async(_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Error during WebSocket handshake: {}", e);
                    return;
                }
            };
            
            info!("WebSocket connection established from: {}", addr);
            
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();
            
            while let Some(msg) = ws_receiver.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        debug!("Received text: {}", text);
                        let echo_text = format!("Echo: {}", text);
                        if let Err(e) = ws_sender.send(Message::Text(echo_text)).await {
                            error!("Failed to send echo: {}", e);
                            break;
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        debug!("Received binary data: {} bytes", data.len());
                        let echo_data = format!("Echo binary: {} bytes", data.len());
                        if let Err(e) = ws_sender.send(Message::Text(echo_data)).await {
                            error!("Failed to send binary echo: {}", e);
                            break;
                        }
                    }
                    Ok(Message::Ping(data)) => {
                        debug!("Received ping, sending pong");
                        if let Err(e) = ws_sender.send(Message::Pong(data)).await {
                            error!("Failed to send pong: {}", e);
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Client sent close frame");
                        break;
                    }
                    Ok(Message::Pong(_)) => {
                        debug!("Received pong");
                    }
                    Ok(Message::Frame(_)) => {
                        // Handle raw frames if needed
                        debug!("Received raw frame");
                    }
                    Err(e) => {
                        error!("Error receiving message: {}", e);
                        break;
                    }
                }
            }
            
            info!("WebSocket connection closed for: {}", addr);
        });
    }
}
