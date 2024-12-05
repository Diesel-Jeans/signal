use std::error::Error;

use client::Client;
use dotenv::dotenv;
use server::SignalBackend;
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
    dotenv();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut alice =
        Client::<InMemory, SignalBackend>::register("alice_device", "1234567891".into()).await?;
    let mut bob =
        Client::<InMemory, SignalBackend>::register("bob_device", "9876543211".into()).await?;

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
