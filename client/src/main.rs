use std::error::Error;

use client::Client;
use server::SignalBackend;
use storage::device::Device;

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
    let mut alice = Client::<Device, SignalBackend>::register("alice_device", "a".into()).await?;
    let mut bob = Client::<Device, SignalBackend>::register("bob_device", "b".into()).await?;

    alice
        .send_message("Hello, World!", &bob.aci.into())
        .await
        .unwrap();

    let message = bob.receive_message().await.unwrap();
    println!("{message}");

    Ok(())
}
