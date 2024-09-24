use contact::{Contact, Device};
use libsignal_protocol::*;
use rand::rngs::OsRng;

mod client;
mod client_common;
mod contact;
mod server;

use crate::client::Client;

use common::signal_protobuf::Envelope;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // test encryption
    let mut rng = OsRng;

    // alice and bob starts their clients
    let mut alice_client = Client::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
        InMemSignalProtocolStore::new(KeyPair::generate(&mut rng).into(), 1)?,
        rng.clone(),
    );

    let mut bob_client = Client::new(
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string(),
        InMemSignalProtocolStore::new(KeyPair::generate(&mut rng).into(), 2)?,
        rng,
    );

    // alice registers bob as one of her contacts
    let mut bob_contact = Contact::new("796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string());

    // bob registers alice as one of his contacts
    let alice_contact = Contact::new("9d0652a3-dcc3-4d11-975f-74d61598733f".to_string());
    let alice_device = Device::new(alice_contact.uuid, 1, None);

    // bob creates his bundle
    let bob_bundle = bob_client.create_bundle().await?;

    // *bob uploads his bundle to the server*

    // *alice fetches bob's bundle, verifies and updates his contact info*
    bob_contact.add_device(Device::new(bob_contact.uuid.clone(), 0, Some(bob_bundle)));

    alice_client
        .verify_contact_devices(&mut bob_contact)
        .await?;

    // alice encrypts message to bob
    let to_bob = alice_client.encrypt(&bob_contact, "hello bibob").await;

    // *send over server*
    let envelope = Envelope {
        r#type: None,
        source_service_id: None,
        source_device: None,
        client_timestamp: None,
        content: Some(Vec::from(to_bob.first().unwrap().serialize())),
        server_guid: None,
        server_timestamp: None,
        ephemeral: None,
        destination_service_id: None,
        urgent: None,
        updated_pni: None,
        story: None,
        report_spam_token: None,
        shared_mrm_key: None,
    };

    surf::put("http://127.0.0.1:50051/messages")
        .body_json(&envelope)?
        .await?;

    // *end server send*

    // server.receive(|to_bob: vec<u8>| {
    let alice_bytes = bob_client
        .decrypt(&alice_device, to_bob.first().unwrap())
        .await?; // how to get device?
    let alice_msg = String::from_utf8(alice_bytes)?;
    println!("{alice_msg}");
    //})

    Ok(())
}
