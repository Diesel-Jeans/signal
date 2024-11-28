use std::error::Error;

use client::Client;
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut alice =
        Client::<InMemory, SignalBackend>::register("A_d_name", "1234567891aababaaaaa".into())
            .await?;
    let mut bob =
        Client::<InMemory, SignalBackend>::register("B_d_name", "9876543211aabnaaaaaa".into())
            .await?;

    alice
        .send_message("Hello, World!", &bob.aci.into())
        .await
        .unwrap();

    let message = bob.receive_message().await;
    match message {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    Ok(())
}
