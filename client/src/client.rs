use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use common::web_api::{AccountAttributes, DeviceCapabilities, RegistrationRequest};
use core::str;
use dotenv::dotenv;
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair};
use rand::{rngs::OsRng, Rng};
use sqlx::sqlite::SqlitePoolOptions;

use crate::{
    contact_manager::ContactManager,
    errors::{LoginError, SignalClientError},
    key_manager::KeyManager,
    server::{Server, ServerAPI},
    storage::{
        device::Device,
        generic::{ProtocolStore, Storage, StorageType},
    },
};

pub struct Client<T: StorageType> {
    aci: Aci,
    pni: Pni,
    contact_manager: ContactManager,
    server_api: ServerAPI,
    key_manager: KeyManager,
    storage: Storage<T>,
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

impl<T: StorageType> Client<T> {
    fn new(
        aci: Aci,
        pni: Pni,
        contact_manager: ContactManager,
        server_api: ServerAPI,
        key_manager: KeyManager,
        storage: Storage<T>,
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
    pub async fn register(
        name: &str,
        phone_number: String,
    ) -> Result<Client<Device>, SignalClientError> {
        let mut csprng = OsRng;
        let aci_registration_id = OsRng.gen_range(1..16383);
        let pni_registration_id = OsRng.gen_range(1..16383);
        let aci_key_pair = KeyPair::generate(&mut csprng);
        let pni_key_pair = KeyPair::generate(&mut csprng);
        let id_key = IdentityKey::new(aci_key_pair.public_key);
        let id_key_pair = IdentityKeyPair::new(id_key, aci_key_pair.private_key);
        dotenv().map_err(|err| SignalClientError::DotenvError(format!("{err}")))?;
        let db_url =
            std::env::var("DATABASE_URL").expect("Expected to read database url from .env file");
        let pool = SqlitePoolOptions::new()
            .connect(&db_url)
            .await
            .expect("Could not connect to database");

        sqlx::migrate!("client_db/migrations")
            .run(&pool)
            .await
            .expect("Could not run migrations");

        let mut proto_storage = ProtocolStore::create_device_protocol_store(
            id_key_pair,
            aci_registration_id,
            pool.clone(),
        )
        .await;
        let mut key_manager = KeyManager::new();

        let aci_signed_pk = key_manager
            .generate_signed_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.signed_pre_key_store,
                &mut csprng,
            )
            .await
            .unwrap();
        let pni_signed_pk = key_manager
            .generate_signed_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.signed_pre_key_store,
                &mut csprng,
            )
            .await
            .unwrap();

        let aci_pq_last_resort = key_manager
            .generate_kyber_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.kyber_pre_key_store,
            )
            .await
            .unwrap();
        let pni_pq_last_resort = key_manager
            .generate_kyber_pre_key(
                &mut proto_storage.identity_key_store,
                &mut proto_storage.kyber_pre_key_store,
            )
            .await
            .unwrap();

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
        let mut server_api = ServerAPI::new();
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

        let response = server_api
            .register_client(phone_number, &password, req, None)
            .await?;

        let aci: Aci = response.uuid.into();
        let pni: Pni = response.pni.into();

        server_api.create_auth_header(aci, &password, 1.into());

        let contact_manager = ContactManager::new();
        let mut storage = Storage::create(aci, pni, password, proto_storage, pool).await?;
        let key_bundle = key_manager
            .generate_key_bundle(&mut storage.protocol_store)
            .await
            .expect("Should create key bundle");

        println!("Publishing keybundle!");

        server_api.publish_bundle(key_bundle).await?;

        Ok(Client::new(
            aci,
            pni,
            contact_manager,
            server_api,
            key_manager,
            storage,
        ))
    }

    pub async fn login() -> Result<Self, LoginError> {
        todo!("Implement when Storage<Device> is done")
    }

    pub async fn send_message(
        &mut self,
        message: &str,
        user_id: &str,
        device_id: u32,
    ) -> Result<(), SignalClientError> {
        self.server_api
            .send_msg(message.into(), user_id.into(), device_id)
            .await
    }
}
