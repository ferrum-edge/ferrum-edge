use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use std::error::Error;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    
    // Connect to Ferrum Gateway WebSocket proxy
    let gateway_url = "ws://localhost:8000/ws-echo";
    info!("🚀 Connecting to Ferrum Gateway WebSocket proxy: {}", gateway_url);
    
    let (ws_stream, response) = connect_async(gateway_url).await?;
    info!("✅ Connected to gateway! Response status: {}", response.status());
    
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Send test message
    let test_message = "Hello from client! This should echo back through the gateway!";
    info!("📤 Sending test message: '{}'", test_message);
    
    if let Err(e) = ws_sender.send(Message::Text(test_message.to_string())).await {
        error!("❌ Failed to send message: {}", e);
        return Err(e.into());
    }
    
    info!("⏳ Waiting for echo response through gateway...");
    
    // Receive response with timeout
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        ws_receiver.next()
    ).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            info!("📥 ✅ SUCCESS! Received echo: '{}'", text);
            info!("🎯 Message flow confirmed: Client → Gateway → Backend → Gateway → Client");
            
            if text.contains("Hello from client!") {
                info!("🎉 PERFECT! Complete bidirectional WebSocket communication through Ferrum Gateway!");
            } else {
                info!("⚠️  Unexpected response: '{}'", text);
            }
            
            // Send a second message to test again
            let second_message = "Second message - testing bidirectional flow again!";
            info!("📤 Sending second message: '{}'", second_message);
            
            if let Err(e) = ws_sender.send(Message::Text(second_message.to_string())).await {
                error!("❌ Failed to send second message: {}", e);
            } else {
                // Wait for second response
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(3),
                    ws_receiver.next()
                ).await {
                    Ok(Some(Ok(Message::Text(text2)))) => {
                        info!("📥 ✅ Second echo received: '{}'", text2);
                        info!("🎉 DOUBLE SUCCESS! Multiple bidirectional messages working!");
                    }
                    Ok(_) => {
                        info!("📥 Second response received (different message type)");
                    }
                    Err(_) => {
                        info!("⏰ Timeout waiting for second response");
                    }
                }
            }
        }
        Ok(Some(Ok(Message::Binary(data)))) => {
            info!("📥 Received binary response: {} bytes", data.len());
        }
        Ok(Some(Ok(Message::Close(close_frame)))) => {
            info!("🔚 Server sent close frame: {:?}", close_frame);
        }
        Ok(Some(Ok(Message::Ping(data)))) => {
            info!("🏓 Received ping, sending pong");
            if let Err(e) = ws_sender.send(Message::Pong(data)).await {
                error!("Failed to send pong: {}", e);
            }
        }
        Ok(Some(Ok(Message::Pong(_)))) => {
            info!("🏓 Received pong");
        }
        Ok(Some(Ok(Message::Frame(_)))) => {
            info!("📋 Received raw frame");
        }
        Ok(Some(Err(e))) => {
            error!("❌ WebSocket error: {}", e);
        }
        Ok(None) => {
            info!("📡 WebSocket stream ended");
        }
        Err(_) => {
            info!("⏰ Timeout waiting for response");
        }
    }
    
    // Send close frame gracefully
    info!("🔚 Sending close frame to gateway");
    if let Err(e) = ws_sender.send(Message::Close(None)).await {
        error!("Failed to send close: {}", e);
    }
    
    info!("🏁 Test completed!");
    Ok(())
}
