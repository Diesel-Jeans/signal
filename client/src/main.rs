use std::error::Error;

use crate::client::Client;
use crate::socket_manager::{signal_ws_connect, SignalStream, SocketManager};
use common::websocket::net_helper::create_request;
use std::env;

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_manager;
mod server;
mod socket_manager;
mod storage;
#[cfg(test)]
mod test_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut socket_manager = SocketManager::new(5);
    let ws = signal_ws_connect(
        "../server/cert/rootCA.crt",
        "wss://127.0.0.1:443/v1/websocket",
        "7db772c1-5ae2-4d25-9daf-025be34aa7b1",
        "password",
    )
    .await
    .expect("Failed to connect");
    let wrap = SignalStream::new(ws);
    socket_manager.set_stream(wrap).await;

    let id = socket_manager.next_id();

    let body = r#" 
        {
            "messages":
            [
                {
                    "type": 1,
                    "destinationDeviceId": 1,
                    "destinationRegistrationId": 3,
                    "content": "aGVsbG8="
                }
            ],
            "online": false,
            "urgent": true,
            "timestamp": 1730217386
        }
        "#
    .as_bytes()
    .to_vec();

    let mut receiver = socket_manager.subscribe();
    let hdnl = tokio::spawn(async move {
        loop {
            let msg = receiver.recv().await;
            println!("Thread {:?}", msg);
        }
    });
    println!("---------------------------------------------");
    let req = create_request(
        id,
        "PUT",
        "/v1/messages/7db772c1-5ae2-4d25-9daf-025be34aa7b1",
        vec![],
        Some(body),
    );
    println!("{:?}", socket_manager.send(id, req).await.expect("benis"));

    hdnl.await;
    Ok(())
}
