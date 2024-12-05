use std::{env::var, error::Error};

use client::Client;
use dotenv::dotenv;
use errors::SignalClientError;
use server::SignalServer;
use storage::in_memory::InMemory;

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_manager;
mod persistent_receiver;
mod server;
mod socket_manager;
mod storage;
#[cfg(test)]
mod test_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().map_err(|err| SignalClientError::DotenvError(format!("{err}")))?;
    let server_url = var("SERVER_URL")?;
    let cert_path = var("CERT_PATH")?;

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut alice = Client::<InMemory, SignalServer>::register(
        "alice_device",
        "123456789".into(),
        &server_url,
        &cert_path,
    )
    .await?;
    let mut bob = Client::<InMemory, SignalServer>::register(
        "bob_device",
        "987654321".into(),
        &server_url,
        &cert_path,
    )
    .await?;

    alice.send_message("Hello Bob!", &bob.aci.into()).await?;

    let message_from_alice = bob.receive_message().await;

    match message_from_alice {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    bob.send_message("Hello Alice!", &alice.aci.into()).await?;

    let message_from_bob = alice.receive_message().await;

    match message_from_bob {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    Ok(())
}
