use rand::{CryptoRng, Rng};
use contact::Contact;
use libsignal_protocol::*;
use rand::rngs::OsRng;

mod client_common;
mod client;
mod contact;
mod server;



use crate::client::Client;

use common::signal_protobuf::Envelope;
pub(crate) const CIPHERTEXT_MESSAGE_CURRENT_VERSION: u8 = 4;

fn create_signal_message<T>(csprng: &mut T) -> error::Result<SignalMessage>
where
    T: Rng + CryptoRng,
{
    let mut mac_key = [0u8; 32];
    csprng.fill_bytes(&mut mac_key);
    let mac_key = mac_key;

    let mut ciphertext = [0u8; 20];
    csprng.fill_bytes(&mut ciphertext);
    let ciphertext = ciphertext;

    let sender_ratchet_key_pair = KeyPair::generate(csprng);
    let sender_identity_key_pair = KeyPair::generate(csprng);
    let receiver_identity_key_pair = KeyPair::generate(csprng);

    SignalMessage::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        &mac_key,
        sender_ratchet_key_pair.public_key,
        42,
        41,
        &ciphertext,
        &sender_identity_key_pair.public_key.into(),
        &receiver_identity_key_pair.public_key.into(),
    )
}





#[tokio::main]  
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = create_signal_message(&mut OsRng)?;

    let envelope = Envelope {
        r#type: None,
        source_service_id: None,
        source_device: None,
        client_timestamp: None,
        content: Some(Vec::from(message.serialized())),
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
    // test encryption
    let mut rng = OsRng;
    
    // alice and bob creates their key pairs public / private keys
    let alice_pair = KeyPair::generate(&mut rng).into();
    let bob_pair = KeyPair::generate(&mut rng).into();

    // alice and bob starts their clients
    let mut alice_client = Client::new(
        23, 
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
        "+4588888888".to_string(),
        alice_pair,
        InMemSignalProtocolStore::new(alice_pair, 1)?,
        rng.clone()
    );

    let mut bob_client = Client::new(
        42, 
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string(), 
        "+4538383138".to_string(), 
        bob_pair, 
        InMemSignalProtocolStore::new(bob_pair, 2)?, 
        rng
    );

    // alice registers bob as one of her contacts
    let mut bob_contact = Contact::new(
        42, 
        "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string(), 
        "+4538383138".to_string()
    );
    
    // bob registers alice as one of his contacts
    let alice_contact = Contact::new(
        23,
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
        "+4588888888".to_string(),
    );

    // bob creates his bundle
    let bob_bundle = bob_client.create_bundle().await?;

    // *bob uploads his bundle to the server*
    // server.publish_bundle(bob_bundle);

    // *alice fetches bob's bundle, verifies and updates his contact info*
    // let bob_bundle = server.fetch_bundle(bob_contact).await?

    alice_client.set_contact_bundle(&mut bob_contact, bob_bundle).await?;

    // alice encrypts message to bob
    let to_bob = alice_client.encrypt(&bob_contact, "hello bibob").await?;

    // *send over server*
    // server.send(bob_contact, to_bob)

    // server.receive(|to_bob: vec<u8>| {
        let alice_bytes = bob_client.decrypt(alice_contact, &to_bob).await?;
        let alice_msg = String::from_utf8(alice_bytes)?;
        println!("{alice_msg}");
    //})

    Ok(())
}
