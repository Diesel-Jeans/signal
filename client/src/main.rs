use client::Client;
use common::errors::DecodeEnvelopeError;
use dotenv::dotenv;
use server::SignalServer;
use std::{
    collections::HashMap,
    env::var,
    error::Error,
    fs,
    path::{Path, PathBuf},
};
use storage::{device::Device, generic::SignalStore};

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

fn client_db_path() -> String {
    fs::canonicalize(PathBuf::from("./client_db".to_string()))
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap()
        .replace("\\", "/")
        .trim_start_matches("//?/")
        .to_owned()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv()?;
    let client_db_dir = client_db_path();
    let alice_path = client_db_dir.clone() + "/alice.db";
    let bob_path = client_db_dir + "/bob.db";

    let alice_db_url = format!("sqlite://{}", alice_path);
    let bob_db_url = format!("sqlite://{}", bob_path);

    let server_url = var("SERVER_URL").expect("Could not find SERVER_URL");
    let cert_path = var("CERT_PATH").expect("Could not find CERT_PATH");

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let mut alice = if Path::exists(Path::new(&alice_path)) {
        Client::<Device, SignalServer>::login(&alice_db_url, &cert_path, &server_url).await?
    } else {
        Client::<Device, SignalServer>::register(
            "alice_device",
            "123456789".into(),
            &alice_db_url,
            &server_url,
            &cert_path,
        )
        .await?
    };

    let mut bob = if Path::exists(Path::new(&bob_path)) {
        Client::<Device, SignalServer>::login(&bob_db_url, &cert_path, &server_url).await?
    } else {
        Client::<Device, SignalServer>::register(
            "bob_device",
            "987654321".into(),
            &bob_db_url,
            &server_url,
            &cert_path,
        )
        .await?
    };

    let mut names = HashMap::new();
    names.insert(
        alice.storage.get_aci().await?.service_id_string(),
        "Alice".to_owned(),
    );
    names.insert(
        bob.storage.get_aci().await?.service_id_string(),
        "Bob".to_owned(),
    );

    // 1st message
    alice
        .send_message("Hello Bob!", &bob.aci.into(), "bob")
        .await?;

    let unknown_sender = "Unknown Sender".to_owned();

    let message_from_alice = bob.receive_message().await?;
    let alice_sender = names
        .get(&message_from_alice.source_service_id()?.service_id_string())
        .unwrap_or(&unknown_sender);
    let alice_message_content = message_from_alice.try_get_message_as_string()?;

    println!("{alice_sender}: {alice_message_content}");

    bob.send_message("Hello Alice!", &alice.aci.into(), "alice")
        .await?;

    let message_from_bob = alice.receive_message().await?;
    let bob_sender = names
        .get(&message_from_bob.source_service_id()?.service_id_string())
        .unwrap_or(&unknown_sender);
    let bob_message_content = message_from_bob.try_get_message_as_string()?;

    println!("{bob_sender}: {bob_message_content}");

    // 2nd message
    alice
        .send_message("Hello Bob again!", &bob.aci.into(), "bob")
        .await?;

    let message_from_alice = bob.receive_message().await?;
    let alice_sender = names
        .get(&message_from_alice.source_service_id()?.service_id_string())
        .unwrap_or(&unknown_sender);
    let alice_message_content = message_from_alice.try_get_message_as_string()?;

    println!("{alice_sender}: {alice_message_content}");

    bob.send_message("Hello Alice again!", &alice.aci.into(), "alice")
        .await?;

    let message_from_bob = alice.receive_message().await?;
    let bob_sender = names
        .get(&message_from_bob.source_service_id()?.service_id_string())
        .unwrap_or(&unknown_sender);
    let bob_message_content = message_from_bob.try_get_message_as_string()?;

    println!("{bob_sender}: {bob_message_content}");

    Ok(())
}
