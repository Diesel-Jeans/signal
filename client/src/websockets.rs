use tokio_tungstenite::*;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use url::Url;
use tokio::*;

#[tokio::main]
async fn main() {}


#[cfg(test)]
mod tests {
    use futures_util::future::ok;
    use super::*;
    #[tokio::test]
    async fn test_websocket() {
        // Define the WebSocket server URL
        let mut ws_url = "wss://echo.websocket.org".into_client_request().unwrap();

        // Connect to the WebSocket server
        let (mut ws_stream, _) = tungstenite::connect(ws_url).expect("Failed to connect");

        println!("WebSocket connection established!");

        let fuck_rust = ws_stream.read();
        match fuck_rust {
            Ok(msg) => println!("Got message: {}", msg),
            Err(e) => println!("Got error: {:?}", e),
        }

        
        /*
        // Split the stream into a sender and receiver
        let (mut write, mut read) = ws_stream.split();

        // Send a message to the WebSocket server
        let msg = Message::Text("Hello WebSocket".into());
        write.send(msg).await.expect("Failed to send message");

        // Wait for a response from the server
        if let Some(Ok(message)) = read.next().await {
            match message {
                Message::Text(text) => {
                    println!("Received: {}", text);
                }
                _ => {
                    println!("Received non-text message");
                }
            }
        }

        println!("Closing WebSocket connection...");*/
        assert!(true)
    }
}




