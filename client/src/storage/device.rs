use crate::errors::LoginError;
use anyhow::Result;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::{fs, u32};

use super::protocol_store::{self, GenericProtocolStore};
use super::serializations::{
    aci_serde, identity_key_pair_serde, identity_map_serde, kyber_pre_key_map_serde, pni_serde,
    pre_key_map_serde, private_key_serde, public_key_serde, sender_key_map_serde,
    session_map_serde, signed_pre_key_map_serde,
};
use super::storage_trait::Storage;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use base64::Engine;
use bon::bon;
use http_client::async_trait;
use libsignal_core::{Aci, Pni, ProtocolAddress};
use libsignal_protocol::{
    Direction, GenericSignedPreKey as _, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    PrivateKey, PublicKey, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use serde;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use uuid::Uuid;

/// The [DeviceProtocolStore] is an implementation of the [libsignal_protocol::ProtocolStore].
/// This implementation stores on disk so that a user can access their data the next time
/// they login.
/// TODO: Signal uses a local SQL database to store their data. We should maybe do the same.
pub type DeviceProtocolStore = GenericProtocolStore<
    DeviceIdentityKeyStore,
    DevicePreKeyStore,
    DeviceSignedPreKeyStore,
    DeviceKyberPreKeyStore,
    DeviceSessionStore,
    DeviceSenderKeyStore,
>;

impl DeviceProtocolStore {
    pub async fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        let db_url =
            std::env::var("DATABASE_URL").expect("Expected to read database url from .env file");

        println!("{db_url}");
        let pool = SqlitePoolOptions::new()
            .connect(&db_url)
            .await
            .expect("Could not connect to database");
        sqlx::migrate!("client_db/migrations")
            .run(&pool)
            .await
            .unwrap();

        Self {
            identity_key_store: DeviceIdentityKeyStore::new(
                identity_key_pair,
                registration_id,
                pool.clone(),
            )
            .await,
            pre_key_store: DevicePreKeyStore::new(pool.clone()),
            signed_pre_key_store: DeviceSignedPreKeyStore::new(pool.clone()),
            kyber_pre_key_store: DeviceKyberPreKeyStore::new(pool.clone()),
            session_store: DeviceSessionStore::new(pool.clone()),
            sender_key_store: DeviceSenderKeyStore::new(pool.clone()),
        }
    }
}

pub struct DeviceIdentityKeyStore {
    pool: SqlitePool,
}

impl DeviceIdentityKeyStore {
    pub async fn new(key_pair: IdentityKeyPair, registration_id: u32, pool: SqlitePool) -> Self {
        let pk = BASE64_STANDARD.encode(key_pair.identity_key().serialize());
        let sk = BASE64_STANDARD.encode(key_pair.private_key().serialize());

        sqlx::query!(
            r#"
            INSERT INTO Identity (public_key, private_key, registration_id)
            VALUES (?, ?, ?)
            "#,
            pk,
            sk,
            registration_id,
        )
        .execute(&pool)
        .await
        .unwrap();
        Self { pool }
    }

    async fn insert_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<(), SignalProtocolError> {
        let addr = format!("{}", address);
        let key = BASE64_STANDARD.encode(identity.serialize());

        sqlx::query!(
            r#"
            INSERT INTO DeviceIdentityKeyStore (address, identity_key)
            VALUES (?, ?)
            ON CONFLICT(address) DO UPDATE SET identity_key = ?
            "#,
            addr,
            key,
            key
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }
}
#[async_trait(?Send)]
impl IdentityKeyStore for DeviceIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        sqlx::query!(
            r#"
            SELECT
                public_key, private_key
            FROM
                Identity 
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| {
            IdentityKeyPair::new(
                IdentityKey::decode(&BASE64_STANDARD.decode(row.public_key).unwrap()).unwrap(),
                PrivateKey::deserialize(&BASE64_STANDARD.decode(row.private_key).unwrap()).unwrap(),
            )
        })
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        sqlx::query!(
            r#"
            SELECT
                registration_id
            FROM
                Identity
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| row.registration_id as u32)
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        match self.get_identity(address).await.unwrap() {
            Some(key) if key == *identity => Ok(false),
            Some(_key) => {
                self.insert_identity(address, identity).await?;
                Ok(false)
            }
            None => {
                self.insert_identity(address, identity).await?;
                Ok(true)
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.get_identity(address).await {
            Ok(Some(i)) => Ok(i == *identity),
            Ok(None) => Ok(true),
            Err(_) => panic!("This function cannot return err"),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let addr = format!("{}", address);

        match sqlx::query!(
            r#"
            SELECT
                identity_key
            FROM
                DeviceIdentityKeyStore
            WHERE
                address = ?
            "#,
            addr
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => Ok(Some(
                BASE64_STANDARD
                    .decode(row.identity_key)
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            )),
            Err(err) => Ok(None),
        }
    }
}

pub struct DevicePreKeyStore {
    pool: SqlitePool,
}

impl DevicePreKeyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl PreKeyStore for DevicePreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();

        match sqlx::query!(
            r#"
            SELECT
                pre_key_record
            FROM
                DevicePreKeyStore
            WHERE
                pre_key_id = ?
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => PreKeyRecord::deserialize(row.pre_key_record.as_bytes())
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(err) => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let rec = String::from_utf8(record.serialize().unwrap())
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?;

        sqlx::query!(
            r#"
            INSERT INTO DevicePreKeyStore (pre_key_id, pre_key_record)
            VALUES (?, ?)
            ON CONFLICT(pre_key_id) DO UPDATE SET pre_key_record = ?
            "#,
            id,
            rec,
            rec
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();

        sqlx::query!(
            r#"
            DELETE FROM
                DevicePreKeyStore
            WHERE
                pre_key_id = ?
            "#,
            id
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }
}

pub struct DeviceSignedPreKeyStore {
    pool: SqlitePool,
}

impl DeviceSignedPreKeyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl SignedPreKeyStore for DeviceSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let sid: u32 = id.into();

        match sqlx::query!(
            r#"
            SELECT
                signed_pre_key_record
            FROM
                DeviceSignedPreKeyStore
            WHERE
                signed_pre_key_id = ?
            "#,
            sid
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => SignedPreKeyRecord::deserialize(row.signed_pre_key_record.as_bytes())
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(err) => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = id.into();
        let rec = String::from_utf8(record.serialize().unwrap())
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?;

        sqlx::query!(
            r#"
            INSERT INTO DeviceSignedPreKeyStore (signed_pre_key_id, signed_pre_key_record)
            VALUES (?, ?)
            ON CONFLICT(signed_pre_key_id) DO UPDATE SET signed_pre_key_record = ?
            "#,
            id,
            rec,
            rec
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }
}

pub struct DeviceKyberPreKeyStore {
    pool: SqlitePool,
}

impl DeviceKyberPreKeyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl KyberPreKeyStore for DeviceKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();

        match sqlx::query!(
            r#"
            SELECT
                kyber_pre_key_record
            FROM
                DeviceKyberPreKeyStore
            WHERE
                kyber_pre_key_id = ?
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => KyberPreKeyRecord::deserialize(row.kyber_pre_key_record.as_bytes())
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(err) => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let rec = String::from_utf8(record.serialize().unwrap())
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?;

        sqlx::query!(
            r#"
            INSERT INTO DeviceKyberPreKeyStore (kyber_pre_key_id, kyber_pre_key_record)
            VALUES (?, ?)
            ON CONFLICT(kyber_pre_key_id) DO UPDATE SET kyber_pre_key_record = ?
            "#,
            id,
            rec,
            rec
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        panic!("THIS IS NOT USED")
    }
}

pub struct DeviceSessionStore {
    pool: SqlitePool,
}

impl DeviceSessionStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl SessionStore for DeviceSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let addr = format!("{}", address);

        match sqlx::query!(
            r#"
            SELECT
                session_record
            FROM
                DeviceSessionStore
            WHERE
                address = ?
            "#,
            addr
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => SessionRecord::deserialize(row.session_record.as_bytes())
                .map(|res| Some(res))
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(err) => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let addr = format!("{}", address);
        let rec = String::from_utf8(record.serialize().unwrap())
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?;

        sqlx::query!(
            r#"
            INSERT INTO DeviceSessionStore (address, session_record)
            VALUES (?, ?)
            ON CONFLICT(address) DO UPDATE SET session_record = ?
            "#,
            addr,
            rec,
            rec
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }
}

pub struct DeviceSenderKeyStore {
    pool: SqlitePool,
}

impl DeviceSenderKeyStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl SenderKeyStore for DeviceSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let addr = format!("{}:{}", sender, distribution_id);
        let rec = String::from_utf8(record.serialize().unwrap())
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?;

        sqlx::query!(
            r#"
            INSERT INTO DeviceSenderKeyStore (address, sender_key_record)
            VALUES (?, ?)
            ON CONFLICT(address) DO UPDATE SET sender_key_record = ?
            "#,
            addr,
            rec,
            rec
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let addr = format!("{}:{}", sender, distribution_id);

        match sqlx::query!(
            r#"
            SELECT
                sender_key_record
            FROM
                DeviceSenderKeyStore
            WHERE
                address = ?
            "#,
            addr
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => SenderKeyRecord::deserialize(row.sender_key_record.as_bytes())
                .map(|res| Some(res))
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(err) => Ok(None),
        }
    }
}

pub struct DeviceStorage {
    aci: Aci,
    pni: Pni,
    password: String,
    pub protocol_store: DeviceProtocolStore,
    pool: SqlitePool,
}

#[bon]
impl DeviceStorage {
    #[builder]
    pub async fn new(
        aci: Aci,
        pni: Pni,
        password: String,
        identity_key_pair: IdentityKeyPair,
        aci_registration_id: u32,
    ) -> Self {
        let db_url =
            std::env::var("DATABASE_URL").expect("Expected to read database url from .env file");
        let pool = SqlitePoolOptions::new()
            .connect(&db_url)
            .await
            .expect("Could not connect to database");
        sqlx::migrate!("client_db/migrations")
            .run(&pool)
            .await
            .unwrap();

        let storage = Self {
            aci,
            pni,
            password,
            protocol_store: DeviceProtocolStore::new(identity_key_pair, aci_registration_id).await,
            pool,
        };
        storage
    }
}

impl
    Storage<
        DeviceIdentityKeyStore,
        DevicePreKeyStore,
        DeviceSignedPreKeyStore,
        DeviceKyberPreKeyStore,
        DeviceSessionStore,
        DeviceSenderKeyStore,
    > for DeviceStorage
{
    fn set_password(&mut self, new_password: &str) {
        self.password = new_password.to_owned();
    }

    fn get_password(&self) -> &str {
        &self.password
    }

    fn set_aci(&mut self, new_aci: &Aci) {
        self.aci = new_aci.to_owned();
    }

    fn get_aci(&self) -> &Aci {
        &self.aci
    }

    fn set_pni(&mut self, new_pni: &Pni) {
        self.pni = new_pni.to_owned();
    }

    fn get_pni(&self) -> &Pni {
        &self.pni
    }

    fn protocol_store(&mut self) -> &mut DeviceProtocolStore {
        &mut self.protocol_store
    }
}

#[cfg(test)]
mod device_protocol_test {
    use async_once_cell::Lazy;
    use base64::{prelude::BASE64_STANDARD, Engine as _};
    use libsignal_core::{Aci, ProtocolAddress};
    use libsignal_protocol::{
        Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair, PreKeyId, PreKeyRecord,
        PreKeyStore, PrivateKey, PublicKey,
    };
    use rand::rngs::OsRng;
    use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
    use uuid::Uuid;

    use crate::storage::device::{DeviceIdentityKeyStore, DevicePreKeyStore, DeviceProtocolStore};

    async fn connect() -> SqlitePool {
        dotenv::dotenv().unwrap();
        let db_url =
            std::env::var("DATABASE_URL").expect("Expected to read database url from .env file");
        let pool = SqlitePoolOptions::new()
            .connect(&db_url)
            .await
            .expect("Could not connect to database");
        sqlx::migrate!("client_db/migrations")
            .run(&pool)
            .await
            .unwrap();

        pool
    }

    #[tokio::test]
    async fn save_and_get_identity_test() {
        let key_pair = IdentityKeyPair::generate(&mut OsRng);
        let mut device_identity_key_store =
            DeviceIdentityKeyStore::new(key_pair, 1, connect().await).await;
        let address = ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let other_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let new_other_key_pair = IdentityKeyPair::generate(&mut OsRng);

        // Test no identity exists
        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap(),
            None
        );

        // Test that a new identity have been added
        assert_eq!(
            device_identity_key_store
                .save_identity(&address, other_key_pair.identity_key())
                .await
                .unwrap(),
            true
        );

        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap()
                .unwrap(),
            *other_key_pair.identity_key()
        );

        // Test we did not overwrite our identity
        assert_eq!(
            device_identity_key_store
                .save_identity(&address, other_key_pair.identity_key())
                .await
                .unwrap(),
            false
        );

        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap()
                .unwrap(),
            *other_key_pair.identity_key()
        );

        // Test we overwrite our identity
        assert_eq!(
            device_identity_key_store
                .save_identity(&address, new_other_key_pair.identity_key())
                .await
                .unwrap(),
            false
        );

        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap()
                .unwrap(),
            *new_other_key_pair.identity_key()
        );
    }
    #[tokio::test]
    async fn is_trusted_identity_test() {
        let key_pair = IdentityKeyPair::generate(&mut OsRng);
        let mut device_identity_key_store =
            DeviceIdentityKeyStore::new(key_pair, 1, connect().await).await;
        let address = ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let other_key_pair = IdentityKeyPair::generate(&mut OsRng);

        let random_address =
            ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let random_key_pair = IdentityKeyPair::generate(&mut OsRng);

        // First use
        assert_eq!(
            device_identity_key_store
                .is_trusted_identity(&address, other_key_pair.identity_key(), Direction::Sending)
                .await
                .unwrap(),
            true
        );

        // Added identity
        device_identity_key_store
            .save_identity(&address, other_key_pair.identity_key())
            .await
            .unwrap();

        assert_eq!(
            device_identity_key_store
                .is_trusted_identity(&address, other_key_pair.identity_key(), Direction::Sending)
                .await
                .unwrap(),
            true
        );

        // Not trusted
        device_identity_key_store
            .save_identity(&random_address, random_key_pair.identity_key())
            .await
            .unwrap();

        assert_eq!(
            device_identity_key_store
                .is_trusted_identity(&address, random_key_pair.identity_key(), Direction::Sending)
                .await
                .unwrap(),
            false
        );
    }

    #[tokio::test]
    async fn save_and_get_pre_key_test() {
        let mut device_pre_key_store = DevicePreKeyStore::new(connect().await);
        let pre_key_id: PreKeyId = 1.into();
        let key_pair = KeyPair::generate(&mut OsRng);
        let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);

        device_pre_key_store
            .save_pre_key(pre_key_id, &pre_key_record)
            .await
            .unwrap();

        let retrived_pre_key = device_pre_key_store.get_pre_key(pre_key_id).await.unwrap();

        assert_eq!(retrived_pre_key.id().unwrap(), pre_key_id);

        assert_eq!(
            retrived_pre_key.key_pair().unwrap().public_key,
            key_pair.public_key
        );

        assert_eq!(
            retrived_pre_key.key_pair().unwrap().private_key.serialize(),
            key_pair.private_key.serialize()
        );
    }
    #[tokio::test]
    async fn remove_pre_key_test() {
        let mut device_pre_key_store = DevicePreKeyStore::new(connect().await);
        let pre_key_id: PreKeyId = 1.into();
        let key_pair = KeyPair::generate(&mut OsRng);
        let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);

        device_pre_key_store
            .save_pre_key(pre_key_id, &pre_key_record)
            .await
            .unwrap();

        let retrived_pre_key = device_pre_key_store.get_pre_key(pre_key_id).await.unwrap();

        device_pre_key_store
            .remove_pre_key(pre_key_id)
            .await
            .unwrap();

        device_pre_key_store
            .get_pre_key(pre_key_id)
            .await
            .expect_err("We should not be able to retrive the key after deletion");
    }

    #[tokio::test]
    async fn get_signed_pre_key_test() {}
    #[tokio::test]
    async fn save_signed_pre_key_test() {}

    #[tokio::test]
    async fn get_kyber_pre_key_test() {}
    #[tokio::test]
    async fn save_kyber_pre_key_test() {}

    #[tokio::test]
    async fn load_session_test() {}
    #[tokio::test]
    async fn store_session_test() {}

    #[tokio::test]
    async fn store_sender_key_test() {}
    #[tokio::test]
    async fn load_sender_key_test() {}
}
