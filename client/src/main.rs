use client::Client;
use dotenv::dotenv;
use server::SignalServer;
use std::env;
use std::{env::var, error::Error, fs, path::Path, path::PathBuf};
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
    let use_tls = !env::args().any(|arg| arg == "--no-tls");
    println!("Using tls: {}", use_tls);
    dotenv()?;
    let client_db_dir = client_db_path();
    let alice_path = client_db_dir.clone() + "/alice.db";
    let bob_path = client_db_dir + "/bob.db";

    let alice_db_url = format!("sqlite://{}", alice_path);
    let bob_db_url = format!("sqlite://{}", bob_path);

    let (cert_path, server_url) = if use_tls {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        (Some(var("CERT_PATH").expect("Could not find CERT_PATH")), var("HTTPS_SERVER_URL").expect("Could not find SERVER_URL"))
    } else {
        (None, var("HTTP_SERVER_URL").expect("Could not find SERVER_URL"))
    };

    let mut alice = if Path::exists(Path::new(&alice_path)) {
        Client::<Device, SignalServer>::login(&alice_db_url, &cert_path, &server_url).await?
    } else {
        Client::<Device, SignalServer>::register(
            "alice_device",
            "123456789".into(),
            &alice_db_url,
            &server_url,
            &cert_path
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


    alice.disconnect().await;
    bob.disconnect().await;
    Ok(())
}
