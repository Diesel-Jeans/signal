use std::{error::Error, time::Duration};

use contact_manager::Contact;

use crate::client::Client;

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
mod websockets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::from_filename("client/.env")?;
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut alice = Client::register("alice", "a".to_string()).await.unwrap();
    let mut bob = Client::register("bob", "b".to_string()).await.unwrap();

    println!("Logged in, sending message to bob");

    alice
        .send_message("Hello, World!", bob.aci())
        .await
        .unwrap();
    println!("Sent message");

    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("{}", bob.receive_message().await.unwrap());

    Ok(())
}
