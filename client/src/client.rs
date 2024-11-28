use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use common::web_api::{AccountAttributes, DeviceCapabilities, RegistrationRequest};
use core::str;
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::IdentityKeyPair;
use rand::{rngs::OsRng, Rng};
use sqlx::{
    migrate::MigrateDatabase,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Sqlite, SqlitePool,
};
use std::collections::HashMap;

use crate::{
    contact_manager::ContactManager,
    errors::SignalClientError,
    key_manager::KeyManager,
    server::{Server, ServerAPI},
    storage::{
        database::ClientDB,
        device::Device,
        generic::{ProtocolStore, Storage},
    },
};

pub struct Client<T: ClientDB> {
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

impl<T: ClientDB> Client<T> {
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

    async fn connect(database_url: &str, create_db: bool) -> Result<SqlitePool, SignalClientError> {
        if create_db {
            if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
                Sqlite::create_database(database_url).await.unwrap();
            } else {
                return Err(SignalClientError::DatabaseError(
                    "Database already exists".to_string(),
                ));
            }
        }
        let pool = SqlitePool::connect(database_url).await.unwrap();

        sqlx::migrate!("client_db/migrations")
            .run(&pool)
            .await
            .expect("Could not run migrations");

        Ok(pool)
    }

    /// Register a new account with the server.
    /// `phone_number` must be unique.
    pub async fn register(
        name: &str,
        phone_number: String,
        database_url: &str,
    ) -> Result<Client<Device>, SignalClientError> {
        let mut csprng = OsRng;
        let aci_registration_id = OsRng.gen_range(1..16383);
        let pni_registration_id = OsRng.gen_range(1..16383);
        let pni_key_pair = IdentityKeyPair::generate(&mut csprng);
        let aci_key_pair = IdentityKeyPair::generate(&mut csprng);
        let pool = Client::<T>::connect(database_url, true).await?;

        let device = Device::new(pool.clone());
        device
            .insert_account_key_information(aci_key_pair, aci_registration_id)
            .await
            .unwrap();

        let mut proto_storage = ProtocolStore::new(device.clone());

        let mut key_manager = KeyManager::default();

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
        let server_api = ServerAPI::new();
        let req = RegistrationRequest::new(
            "".into(),
            "".into(),
            account_attributes,
            true, // Require atomic is always true
            true, // Skip device transfer is always true
            *aci_key_pair.identity_key(),
            *pni_key_pair.identity_key(),
            aci_signed_pk.into(),
            pni_signed_pk.into(),
            aci_pq_last_resort.into(),
            pni_pq_last_resort.into(),
            None,
            None,
        );

        let response = server_api
            .register_client(phone_number, password.to_owned(), req, None)
            .await?;

        let aci: Aci = response.uuid.into();
        let pni: Pni = response.pni.into();

        let contact_manager = ContactManager::new();
        device
            .insert_account_information(aci, pni, password)
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;
        let storage = Storage::new(device.clone(), proto_storage);
        //storage.device
        Ok(Client::new(
            aci,
            pni,
            contact_manager,
            server_api,
            key_manager,
            storage,
        ))
    }

    pub async fn login(database_url: &str) -> Result<Client<Device>, SignalClientError> {
        let pool = Client::<T>::connect(database_url, false).await?;
        let device = Device::new(pool.clone());
        let contacts = match device.load_contacts().await {
            Ok(contacts) => {
                let mut c = HashMap::new();
                for contact in contacts {
                    c.insert(contact.service_id, contact);
                }
                Ok(c)
            }
            Err(err) => Err(SignalClientError::DatabaseError(format!("{err}"))),
        }?;
        let (one_time, signed, kyber) = device
            .get_key_ids()
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;

        Ok(Client::new(
            device
                .get_aci()
                .await
                .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?,
            device
                .get_pni()
                .await
                .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?,
            ContactManager::new_with_contacts(contacts),
            ServerAPI::new(),
            KeyManager::new(signed, kyber, one_time),
            Storage::new(device.clone(), ProtocolStore::new(device.clone())),
        ))
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

    pub async fn add_contact(
        &mut self,
        alias: &str,
        service_id: ServiceId,
    ) -> Result<(), SignalClientError> {
        self.contact_manager
            .add_contact(&service_id)
            .map_err(|err| SignalClientError::ContactError(err))?;
        let contact = self
            .contact_manager
            .get_contact(&service_id)
            .map_err(|err| SignalClientError::ContactError(err))?;

        self.storage
            .device
            .store_contact(contact)
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;

        self.storage
            .device
            .insert_service_id_for_nickname(alias, &service_id)
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }

    pub async fn remove_contact(&mut self, alias: &str) -> Result<(), SignalClientError> {
        let service_id = self
            .storage
            .device
            .get_service_id_by_nickname(alias)
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;

        self.contact_manager
            .remove_contact(&service_id)
            .map_err(|err| SignalClientError::DatabaseError(err))?;

        self.storage
            .device
            .remove_contact(&service_id)
            .await
            .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }
}
