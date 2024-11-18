use anyhow::Result;
use base64::Engine;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use bon::vec;
use common::signalservice::{envelope, Content, DataMessage, Envelope};
use common::{
    signalservice::WebSocketResponseMessage,
    web_api::{AccountAttributes, DeviceCapabilities, RegistrationRequest, RegistrationResponse},
};
use core::str;
use libsignal_core::{Aci, Pni};
use serde::de::value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use common::web_api::{SignalMessage, SignalMessages};
use libsignal_protocol::{
    CiphertextMessage, IdentityKey, IdentityKeyPair, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyRecord, SessionStore, SignalProtocolError, SignedPreKeyRecord,
};
use rand::{rngs::OsRng, Rng};
use surf::StatusCode;

use crate::contact_manager::{Contact, ContactManager};
use crate::encryption::{encrypt, pad_message};
use crate::errors::{ClientError, LoginError, RegistrationError};
use crate::key_management::key_manager::{InMemoryKeyManager, KeyManager};
use crate::server::{Server, ServerAPI};
use crate::storage::device::DeviceStorage;
use crate::storage::protocol_store::ProtocolStore;

pub struct Client {
    aci: Aci,
    pni: Pni,
    contact_manager: ContactManager,
    server_api: ServerAPI,
    key_manager: InMemoryKeyManager,
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

impl Client {
    fn new(
        aci: Aci,
        pni: Pni,
        contact_manager: ContactManager,
        server_api: ServerAPI,
        key_manager: InMemoryKeyManager,
        storage: DeviceStorage,
    ) -> Self {
        Client {
            aci,
            pni,
            contact_manager,
            server_api,
            key_manager,
            storage,
        }
    }

    /// Register a new account with the server.
    /// `phone_number` must be unique.
    pub async fn register(name: &str, phone_number: String) -> Result<Self, RegistrationError> {
        let mut csprng = OsRng;
        let aci_registration_id = OsRng.gen_range(1..16383);
        let pni_registration_id = OsRng.gen_range(1..16383);
        let aci_key_pair = KeyPair::generate(&mut csprng);
        let pni_key_pair = KeyPair::generate(&mut csprng);
        let id_key = IdentityKey::new(aci_key_pair.public_key);
        let id_key_pair = IdentityKeyPair::new(id_key, aci_key_pair.private_key);

        let storage = InMemSignalProtocolStore::new(id_key_pair, aci_registration_id)
            .expect("Can always create a protocol store.");
        let mut key_manager = InMemoryKeyManager::new(storage);

        let aci_signed_pk: SignedPreKeyRecord = key_manager.generate(&mut csprng).await.unwrap();
        let pni_signed_pk: SignedPreKeyRecord = key_manager.generate(&mut csprng).await.unwrap();

        let aci_pq_last_resort: KyberPreKeyRecord =
            key_manager.generate(&mut csprng).await.unwrap();
        let pni_pq_last_resort: KyberPreKeyRecord =
            key_manager.generate(&mut csprng).await.unwrap();

        let mut password = [0u8; PASSWORD_LENGTH];
        csprng.fill(&mut password);
        let password = BASE64_STANDARD.encode(password);
        let password = password[0..password.len() - 2].to_owned();

        let mut profile_key = [0u8; PROFILE_KEY_LENGTH];
        csprng.fill(&mut profile_key);

        let access_key = [0u8; 16]; // This should be derived from profile_key

        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        csprng.fill(&mut master_key);

        let capabilities = DeviceCapabilities::default();

        let account_attributes = AccountAttributes::new(
            name.into(),
            true,
            aci_registration_id,
            pni_registration_id,
            capabilities,
            Box::new(access_key),
        );
        let server_api = ServerAPI::new();
        let req = RegistrationRequest::new(
            "".into(),
            "".into(),
            account_attributes,
            true, // Require atomic is always true
            true, // Skip device transfer is always true
            IdentityKey::new(aci_key_pair.public_key),
            IdentityKey::new(pni_key_pair.public_key),
            aci_signed_pk.into(),
            pni_signed_pk.into(),
            aci_pq_last_resort.into(),
            pni_pq_last_resort.into(),
            None,
            None,
        );

        let mut response = server_api
            .register_client(phone_number, password.to_owned(), req, None)
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
                    .aci(aci)
                    .pni(pni)
                    .password(password)
                    .identity_key_pair(IdentityKeyPair::new(
                        aci_key_pair.public_key.into(),
                        aci_key_pair.private_key,
                    ))
                    .aci_registration_id(aci_registration_id as u32)
                    .build();
                let client = Client::new(
                    aci,
                    pni,
                    contact_manager,
                    server_api,
                    key_manager,
                    storage.await,
                );
                Ok(client)
            }
            _ => Err(RegistrationError::PhoneNumberTaken),
        }
    }

    /// Log in to a local account that is already registered with the server.
    pub async fn login() -> Result<Self, LoginError> {
        todo!()
        /*let storage = DeviceStorage::load().await?;

        let key_pair = KeyPair::new(
            storage.get_public_key().to_owned(),
            storage.get_private_key().to_owned(),
        );

        let proto_store =
            InMemSignalProtocolStore::new(key_pair.into(), storage.get_aci_registration_id())
                .expect("Can construct Protocol Store from valid parts.");
        Ok(Client::new(
            storage.get_aci().to_owned(),
            storage.get_pni().to_owned(),
            ContactManager::new(),
            ServerAPI::new(),
            InMemoryKeyManager::new(proto_store),
            storage,
        ))*/
    }

    /// Send a message to a specific contact using websockets.
    pub async fn send_message(&mut self, message: &str, to: &Contact) -> Result<(), ClientError> {
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
            pad_message(message.as_bytes()).as_ref(),
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
                    r#type: envelope::Type::Ciphertext.into(),
                    destination_device_id: id,
                    destination_registration_id: todo!(),
                    content: BASE64_STANDARD.encode(msg.serialize()),
                })
                .collect(),
            online: true, // Should this be false?
            urgent: true,
            timestamp: timestamp
                .duration_since(UNIX_EPOCH)
                .expect("can get the time since epoch")
                .as_secs(),
        };

        todo!("Use websockets to send the messages");
    }

    pub async fn receive_message(&mut self) -> Result<String, ClientError> {
        todo!()
    }
}

/// Currently, we do not handle the case when encryption fails.
/// If a message fails to encrypt, we return a [ClientError]
/// and do not recover.
/// TODO: Figure out how to recover when we cannot send to a device.
fn handle_encryption_failed(
    msgs: HashMap<u32, Result<CiphertextMessage, SignalProtocolError>>,
) -> Result<HashMap<u32, CiphertextMessage>, ClientError> {
    transform_hashmap_result(msgs).map_err(|err| ClientError::EncryptionError(err))
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
