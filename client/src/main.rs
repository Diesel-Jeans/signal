use libsignal_protocol::error;
use libsignal_protocol::KeyPair;
use libsignal_protocol::SignalMessage;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

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

    Ok(())
}
