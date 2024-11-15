use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use core::str;
use libsignal_core::{Aci, Pni};
use std::default;
use std::error::Error;
use std::fmt::{self, format, Debug, Display};
use surf::StatusCode;

use crate::contact_manager::ContactManager;
use crate::errors::{LoginError, RegistrationError};
use crate::key_management::key_manager::{InMemoryKeyManager, KeyManager};
use crate::server::{Server, ServerAPI};
use crate::storage::{self, DeviceStorage, Storage};
use common::signal_protobuf::WebSocketResponseMessage;
use common::web_api::{
    AccountAttributes, DeviceCapabilities, RegistrationRequest, RegistrationResponse,
    UploadSignedPreKey,
};
use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, PublicKey,
    SignedPreKeyRecord,
};
use rand::rngs::OsRng;
use rand::Rng;

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
            .map_err(|err| RegistrationError::NoResponse)?;
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
                    .set_aci(aci)
                    .set_pni(pni)
                    .set_password(password)
                    .set_public_key(aci_key_pair.public_key)
                    .set_private_key(aci_key_pair.private_key)
                    .set_aci_registration_id(aci_registration_id)
                    .set_pni_registration_id(pni_registration_id)
                    .try_into()
                    .expect("Missing field in builder");
                let client =
                    Client::new(aci, pni, contact_manager, server_api, key_manager, storage);
                Ok(client)
            }
            _ => Err(RegistrationError::PhoneNumberTaken),
        }
    }

    pub async fn login() -> Result<Self, LoginError> {
        let storage = DeviceStorage::load()?;

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
        ))
    }

    pub async fn send_message(
        &mut self,
        message: &str,
        user_id: &str,
        device_id: u32,
    ) -> Result<WebSocketResponseMessage, Box<dyn std::error::Error>> {
        Ok(self
            .server_api
            .send_msg(message.into(), user_id.into(), device_id)
            .await?)
    }
}
