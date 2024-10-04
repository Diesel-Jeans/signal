use crate::client::Client;

mod client;
mod contact_manager;
mod encryption;
mod key_management;
mod server;
mod storage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    client
        .send_message("Hello, world!")
        .await
        .expect("Error sending message");
    Ok(())
}
