use client::Client;
use dotenv::dotenv;
use server::{SignalServer, SignalServerAPI};
use std::{env::var, error::Error, fs, path::PathBuf};
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
    dotenv()?;

    let alice_db_url = format!(
        "sqlite://{}",
        fs::canonicalize(PathBuf::from("./client_db".to_string()))
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    ) + "/alice.db";
    let bob_db_url = format!(
        "sqlite://{}",
        fs::canonicalize(PathBuf::from("./client_db".to_string()))
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    ) + "/bob.db";
    let server_url = var("SERVER_URL").expect("Could not find SERVER_URL");
    let cert_path = var("CERT_PATH").expect("Could not find CERT_PATH");

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    /*let mut alice = Client::<Device, SignalServer>::register(
        "alice_device",
        "123456789".into(),
        &alice_db_url,
        &server_url,
        &cert_path,
    )
    .await?;
    let mut bob = Client::<Device, SignalServer>::register(
        "bob_device",
        "987654321".into(),
        &bob_db_url,
        &server_url,
        &cert_path,
    )
    .await?;*/
    let mut alice =
        Client::<Device, SignalServer>::login(&alice_db_url, &cert_path, &server_url).await?;
    let mut bob =
        Client::<Device, SignalServer>::login(&bob_db_url, &cert_path, &server_url).await?;

    // 1st message
    alice
        .send_message("Hello Bob!", &bob.aci.into(), "bob")
        .await?;

    let message_from_alice = bob.receive_message().await;

    match message_from_alice {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    bob.send_message("Hello Alice!", &alice.aci.into(), "alice")
        .await?;

    let message_from_bob = alice.receive_message().await;

    match message_from_bob {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    // 2nd message
    alice
        .send_message("Hello Bob again!", &bob.aci.into(), "bob")
        .await?;

    let message_from_alice = bob.receive_message().await;

    match message_from_alice {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    bob.send_message("Hello Alice again!", &alice.aci.into(), "alice")
        .await?;

    let message_from_bob = alice.receive_message().await;

    match message_from_bob {
        Ok(message) => println!("{message}"),
        Err(err) => println!("{:?}", err),
    }

    Ok(())
}
