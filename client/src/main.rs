use axum::serve;
use client::Client;
use dotenv::dotenv;
use server::SignalServer;
use std::{
    collections::HashMap,
    env::{self, var},
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

async fn make_client(
    name: &str,
    phone: &str,
    certificate_path: &Option<String>,
    server_url: &str,
) -> Client<Device, SignalServer> {
    let db_path = client_db_path() + "/" + name + ".db";
    let db_url = format!("sqlite://{}", db_path);
    let client = if Path::exists(Path::new(&db_path)) {
        Client::<Device, SignalServer>::login(&db_url, certificate_path, server_url).await
    } else {
        Client::<Device, SignalServer>::register(
            name,
            phone.into(),
            &db_url,
            server_url,
            certificate_path,
        )
        .await
    };
    client.expect("Failed to create client")
}

fn get_server_info() -> (Option<String>, String) {
    let use_tls = !env::args().any(|arg| arg == "--no-tls");
    println!("Using tls: {}", use_tls);
    if use_tls {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        (
            Some(var("CERT_PATH").expect("Could not find CERT_PATH")),
            var("HTTPS_SERVER_URL").expect("Could not find SERVER_URL"),
        )
    } else {
        (
            None,
            var("HTTP_SERVER_URL").expect("Could not find SERVER_URL"),
        )
    }
}

async fn add_name(
    names: &mut HashMap<String, String>,
    client: &Client<Device, SignalServer>,
    name: &str,
) {
    names.insert(
        client
            .storage
            .get_aci()
            .await
            .expect("No ACI")
            .service_id_string(),
        name.to_owned(),
    );
}

async fn receive_message(
    client: &mut Client<Device, SignalServer>,
    names: &HashMap<String, String>,
    default: &String,
) {
    let msg = client.receive_message().await.expect("Expected Message");
    let name = names
        .get(
            &msg.source_service_id()
                .expect("Failed to decode")
                .service_id_string(),
        )
        .unwrap_or(default);
    let msg_text = msg.try_get_message_as_string().expect("No Text Content");
    println!("{name}: {msg_text}");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv()?;

    let (cert_path, server_url) = get_server_info();
    let mut alice = make_client("alice", "123456789", &cert_path, &server_url).await;
    let mut bob = make_client("bob", "123456784", &cert_path, &server_url).await;

    alice
        .add_contact("bob", &bob.aci.into())
        .await
        .expect("No bob?");
    bob.add_contact("alice", &alice.aci.into())
        .await
        .expect("No alice?");

    let mut contact_names = HashMap::new();
    let default_sender = "Unknown Sender".to_owned();
    add_name(&mut contact_names, &alice, "Alice").await;
    add_name(&mut contact_names, &bob, "Bob").await;

    alice.send_message("Hello Bob!", "bob").await?;
    receive_message(&mut bob, &contact_names, &default_sender).await;

    bob.send_message("Hello Alice!", "alice").await?;
    receive_message(&mut alice, &contact_names, &default_sender).await;

    alice.send_message("Hello Bob again!", "bob").await?;
    receive_message(&mut bob, &contact_names, &default_sender).await;

    bob.send_message("Hello Alice again!", "alice").await?;
    receive_message(&mut alice, &contact_names, &default_sender).await;

    alice.disconnect().await;
    bob.disconnect().await;
    Ok(())
}
