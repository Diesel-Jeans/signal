use base64::{prelude::BASE64_STANDARD, Engine as _};
use bon::{vec, Builder};
use common::protocol_address::parse_protocol_address;
use common::signalservice::{envelope, Content, DataMessage};
use common::web_api::{
    AccountAttributes, DeviceCapabilities, RegistrationRequest, RegistrationResponse,
};
use core::str;
use libsignal_core::{Aci, Pni, ServiceId};
use prost::Message;
use rand::CryptoRng;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use common::web_api::{SignalMessage, SignalMessages};
use libsignal_protocol::{
    message_decrypt, CiphertextMessage, CiphertextMessageType, IdentityKeyPair, KyberPreKeyRecord,
    SignalProtocolError, SignedPreKeyRecord,
};
use rand::{rngs::OsRng, Rng};
use surf::StatusCode;

use crate::contact_manager::{Contact, ContactManager};
use crate::encryption::{encrypt, pad_message};
use crate::errors::{ClientError, LoginError, RegistrationError};
use crate::key_management::key_manager::KeyManager;
use crate::server::{Server, ServerAPI};
use crate::storage::device::{DeviceProtocolStore, DeviceStorage};
use crate::storage::storage_trait::Storage;

pub struct Client {
    aci: Aci,
    pni: Pni,
    contact_manager: ContactManager,
    server_api: ServerAPI,
    storage: DeviceStorage,
}

pub struct VerifiedSession {
    session_id: String,
}

impl VerifiedSession {
    pub fn session_id(&self) -> &String {
        &self.session_id
    }
}

const PROFILE_KEY_LENGTH: usize = 32;
const MASTER_KEY_LENGTH: usize = 32;
const PASSWORD_LENGTH: usize = 16;

#[derive(Builder)]
pub struct RegistrationInformation {
    pub aci_registration_id: u32,
    pub pni_registration_id: u32,
    pub aci_identity_key_pair: IdentityKeyPair,
    pub pni_identity_key_pair: IdentityKeyPair,
    pub aci_signed_pk: SignedPreKeyRecord,
    pub pni_signed_pk: SignedPreKeyRecord,
    pub aci_pq_last_resort: KyberPreKeyRecord,
    pub pni_pq_last_resort: KyberPreKeyRecord,
    pub name: String,
    pub password: String,
    pub access_key: [u8; 16],
}

impl RegistrationInformation {
    fn to_registration_request(self) -> RegistrationRequest {
        let capabilities = DeviceCapabilities::default();

        let account_attributes = AccountAttributes::new(
            self.name,
            true,
            self.aci_registration_id,
            self.pni_registration_id,
            capabilities,
            Box::new(self.access_key),
        );
        RegistrationRequest::new(
            "".into(),
            "".into(),
            account_attributes,
            true, // Require atomic is always true
            true, // Skip device transfer is always true
            self.aci_identity_key_pair.identity_key().to_owned(),
            self.pni_identity_key_pair.identity_key().to_owned(),
            self.aci_signed_pk.into(),
            self.pni_signed_pk.into(),
            self.aci_pq_last_resort.into(),
            self.pni_pq_last_resort.into(),
            None,
            None,
        )
    }
}

#[derive(Builder)]
pub struct RegistrationIdentity {
    pub aci_registration_id: u32,
    pub pni_registration_id: u32,
    pub aci_key_pair: IdentityKeyPair,
    pub pni_key_pair: IdentityKeyPair,
}

impl Client {
    fn new(
        aci: Aci,
        pni: Pni,
        contact_manager: ContactManager,
        server_api: ServerAPI,
        storage: DeviceStorage,
    ) -> Self {
        Self {
            aci,
            pni,
            contact_manager,
            server_api,
            storage,
        }
    }

    pub fn aci(&self) -> Aci {
        self.aci
    }

    /// Register a new account with the server.
    /// `phone_number` must be unique.
    pub async fn register(name: &str, phone_number: String) -> Result<Self, RegistrationError> {
        let mut csprng = OsRng;
        let identity = get_registration_identity(&mut csprng);
        let mut protocol_store =
            DeviceProtocolStore::new(identity.aci_key_pair, identity.aci_registration_id).await;
        let mut key_manager = KeyManager::new(&mut protocol_store);
        let aci_signed_pk: SignedPreKeyRecord = key_manager
            .generate_signed_prekey(&mut csprng)
            .await
            .unwrap();
        let pni_signed_pk: SignedPreKeyRecord = key_manager
            .generate_signed_prekey(&mut csprng)
            .await
            .unwrap();

        let aci_pq_last_resort: KyberPreKeyRecord =
            key_manager.generate_kyber_prekey().await.unwrap();
        let pni_pq_last_resort: KyberPreKeyRecord =
            key_manager.generate_kyber_prekey().await.unwrap();

        let mut password = [0u8; PASSWORD_LENGTH];
        csprng.fill(&mut password);
        let password = BASE64_STANDARD.encode(password);
        let password = password[0..password.len() - 2].to_owned();

        let mut profile_key = [0u8; PROFILE_KEY_LENGTH];
        csprng.fill(&mut profile_key);

        let access_key = [0u8; 16];
        // This should be derived from profile_key

        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        csprng.fill(&mut master_key);

        let info = RegistrationInformation::builder()
            .aci_registration_id(identity.aci_registration_id)
            .pni_registration_id(identity.pni_registration_id)
            .aci_identity_key_pair(identity.aci_key_pair)
            .pni_identity_key_pair(identity.pni_key_pair)
            .aci_signed_pk(aci_signed_pk)
            .pni_signed_pk(pni_signed_pk)
            .aci_pq_last_resort(aci_pq_last_resort)
            .pni_pq_last_resort(pni_pq_last_resort)
            .name(name.to_owned())
            .password(password.to_owned())
            .access_key(access_key)
            .build();

        let server_api = ServerAPI::new(None, password.to_owned());

        let mut response = server_api
            .register_client(
                phone_number,
                password.to_owned(),
                info.to_registration_request(),
                None,
            )
            .await
            .map_err(|_| RegistrationError::NoResponse)?;
        match response.status() {
            StatusCode::Ok => {
                let body: RegistrationResponse = response
                    .body_json()
                    .await
                    .map_err(|_| RegistrationError::BadResponse)?;

                let aci: Aci = body.uuid.into();
                let pni: Pni = body.pni.into();

                let contact_manager = ContactManager::new();

                let storage = DeviceStorage::builder()
                    .aci_registration_id(identity.aci_registration_id)
                    .aci(aci)
                    .pni(pni)
                    .password(password)
                    .identity_key_pair(identity.aci_key_pair)
                    .build()
                    .await;
                let client = Client::new(aci, pni, contact_manager, server_api, storage);
                Ok(client)
            }
            _ => Err(RegistrationError::PhoneNumberTaken),
        }
    }

    /// Log in to a local account that is already registered with the server.
    pub async fn login() -> Result<Self, LoginError> {
        todo!()
    }

    /// Send a message to a specific contact using websockets.
    pub async fn send_message(&mut self, message: &str, to: &Contact) -> Result<(), ClientError> {
        let username = self.storage.get_aci().service_id_string();
        let password = self.storage.get_password();
        let url = "wss://127.0.0.1:443/v1/websocket";
        let tls_cert = "server/cert/rootCA.crt";
        self.server_api
            .connect(&username, password, url, tls_cert)
            .await
            .unwrap();
        println!("Connected");
        // Prepare a message to be sent

        let content = Content::builder()
            .data_message(
                DataMessage::builder()
                    .body(message.to_owned())
                    .contact(vec![])
                    .body_ranges(vec![])
                    .preview(vec![])
                    .attachments(vec![])
                    .build(),
            )
            .build();

        let protocol_store = &mut self.storage.protocol_store;
        // pad and encrypt message.

        let timestamp = SystemTime::now();

        let msgs = encrypt(
            &mut protocol_store.session_store,
            &mut protocol_store.identity_key_store,
            to,
            pad_message(content.encode_to_vec().as_ref()).as_ref(),
            timestamp,
        )
        .await;

        // TODO: What to do if encryption fails?
        let msgs = handle_encryption_failed(msgs)?;

        // Put messages into structure ready.
        let msgs = SignalMessages {
            messages: msgs
                .into_iter()
                .map(|(id, msg)| SignalMessage {
                    r#type: match msg {
                        CiphertextMessage::SignalMessage(_) => envelope::Type::Ciphertext.into(),
                        CiphertextMessage::SenderKeyMessage(_) => {
                            envelope::Type::KeyExchange.into()
                        }
                        CiphertextMessage::PreKeySignalMessage(_) => {
                            envelope::Type::PrekeyBundle.into()
                        }
                        CiphertextMessage::PlaintextContent(_) => {
                            envelope::Type::PlaintextContent.into()
                        }
                    },
                    destination_device_id: id,
                    destination_registration_id: todo!(),
                    content: BASE64_STANDARD.encode(msg.serialize()),
                })
                .collect(),
            online: false, // Should this be true?
            urgent: true,
            timestamp: timestamp
                .duration_since(UNIX_EPOCH)
                .expect("can get the time since epoch")
                .as_secs(),
        };

        // TODO: Fix contact. It should not be a uuid string. it should be a ServiceId.
        let user_id = ServiceId::parse_from_service_id_string(&to.uuid).unwrap();
        println!("Handing message off to websocket");
        self.server_api.send_msg(msgs, user_id).await.unwrap();
        Ok(())
    }

    pub async fn receive_message(&mut self) -> Result<String, ClientError> {
        // I get Envelope from Server.
        let envelope = self
            .server_api
            .get_message()
            .await
            .ok_or(ClientError::NoPendingMessage)?;

        // Envelope contains a ciphertext message; a so called `encrypted [Content]`
        let ciphertext_content = envelope.content();

        // The content of the envelope is base64 encoded.
        let bytes = BASE64_STANDARD
            .decode(ciphertext_content)
            .map_err(ClientError::Base64MessageDecodeError)?;

        // The evelope contains information about which message type is received.
        let t_id = envelope.r#type.ok_or(ClientError::NoMessageType)?;
        let _type = match t_id {
            2 => Ok(CiphertextMessageType::Whisper),
            3 => Ok(CiphertextMessageType::PreKey),
            7 => Ok(CiphertextMessageType::SenderKey),
            8 => Ok(CiphertextMessageType::Plaintext),
            _ => Err(ClientError::InvalidMessageType(t_id)),
        }?;

        // Use the information from envelope to construct a CiphertextMessage.
        let ciphertext = decode_ciphertext(bytes, _type).map_err(ClientError::DecryptionError)?;

        let address = parse_protocol_address(envelope.source_service_id())
            .map_err(ClientError::ParseProtocolAddress)?;

        let mut csprng = OsRng;
        let store = &mut self.storage.protocol_store;

        // Decrypt the message.
        let plaintext = message_decrypt(
            &ciphertext,
            &address,
            &mut store.session_store,
            &mut store.identity_key_store,
            &mut store.pre_key_store,
            &mut store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut csprng,
        )
        .await
        .map_err(ClientError::DecryptionError)?;

        // The final message is stored within a DataMessage inside a Content.
        Ok(Content::decode(plaintext.as_ref())
            .map_err(ClientError::ProtobufMessageDecodeError)?
            .data_message
            .ok_or_else(|| ClientError::InvalidContent)?
            .body()
            .to_owned())
    }

    #[cfg(test)]
    fn test_client(_name: &str) -> Self {
        todo!()
    }
}

fn get_registration_identity<R>(mut csprng: &mut R) -> RegistrationIdentity
where
    R: Rng + CryptoRng,
{
    RegistrationIdentity::builder()
        .aci_registration_id(OsRng.gen_range(1..16383))
        .pni_registration_id(OsRng.gen_range(1..16383))
        .aci_key_pair(IdentityKeyPair::generate(&mut csprng))
        .pni_key_pair(IdentityKeyPair::generate(&mut csprng))
        .build()
}

fn decode_ciphertext(
    bytes: Vec<u8>,
    _type: CiphertextMessageType,
) -> Result<CiphertextMessage, SignalProtocolError> {
    match _type {
        CiphertextMessageType::Whisper => {
            Ok(CiphertextMessage::SignalMessage((&*bytes).try_into()?))
        }
        CiphertextMessageType::PreKey => Ok(CiphertextMessage::PreKeySignalMessage(
            (&*bytes).try_into()?,
        )),
        CiphertextMessageType::SenderKey => {
            Ok(CiphertextMessage::SenderKeyMessage((&*bytes).try_into()?))
        }
        CiphertextMessageType::Plaintext => {
            Ok(CiphertextMessage::PlaintextContent((&*bytes).try_into()?))
        }
    }
}

/// Currently, we do not handle the case when encryption fails.
/// If a message fails to encrypt, we return a [ClientError]
/// and do not recover.
/// TODO: Figure out how to recover when we cannot send to a device.
fn handle_encryption_failed(
    msgs: HashMap<u32, Result<CiphertextMessage, SignalProtocolError>>,
) -> Result<HashMap<u32, CiphertextMessage>, ClientError> {
    transform_hashmap_result(msgs).map_err(ClientError::EncryptionError)
}

fn transform_hashmap_result<K, T, E>(map: HashMap<K, Result<T, E>>) -> Result<HashMap<K, T>, E>
where
    K: Eq + std::hash::Hash,
{
    map.into_iter()
        .fold(Ok(HashMap::new()), |acc, (key, value)| {
            let mut new_map = acc?;
            new_map.insert(key, value?);
            Ok(new_map)
        })
}

#[cfg(test)]
mod client_test {

    use crate::Client;

    #[tokio::test]
    async fn test_client_send_and_receive() {
        let _alice = Client::test_client("alice");
    }
}
