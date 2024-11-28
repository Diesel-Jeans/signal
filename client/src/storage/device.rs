use super::generic::{ProtocolStore, SignalStore, Storage};
use crate::{errors::SignalClientError, storage::generic::StorageType};
use axum::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use libsignal_core::{Aci, Pni, ProtocolAddress};
use libsignal_protocol::{
    Direction, GenericSignedPreKey as _, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    PrivateKey, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug)]
pub struct Device {
    pool: SqlitePool,
}

impl Device {
    pub async fn create(
        aci: Aci,
        pni: Pni,
        password: String,
        pool: SqlitePool,
    ) -> Result<Self, SignalClientError> {
        let aci = aci.service_id_string();
        let pni = pni.service_id_string();

        sqlx::query!(
            r#"
            INSERT INTO Identity (aci, pni, password)
            VALUES (?, ?, ?)
            "#,
            aci,
            pni,
            password,
        )
        .execute(&pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;

        Ok(Self { pool })
    }
}

impl Storage<Device> {
    pub async fn create(
        aci: Aci,
        pni: Pni,
        password: String,
        protocol_store: ProtocolStore<Device>,
        pool: SqlitePool,
    ) -> Result<Self, SignalClientError> {
        Ok(Self {
            inner: Device::create(aci, pni, password, pool).await?,
            protocol_store,
        })
    }
}

#[async_trait]
impl SignalStore for Storage<Device> {
    type Error = SignalClientError;

    async fn set_password(&mut self, new_password: String) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            UPDATE identity
            SET password = ?
            "#,
            new_password
        )
        .execute(&self.inner.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }

    async fn get_password(&self) -> Result<String, Self::Error> {
        sqlx::query!(
            r#"
            SELECT
                password
            FROM
                identity
            "#
        )
        .fetch_one(&self.inner.pool)
        .await
        .map(|row| row.password)
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }

    async fn set_aci(&mut self, new_aci: Aci) -> Result<(), Self::Error> {
        let new_aci = new_aci.service_id_string();

        sqlx::query!(
            r#"
            UPDATE identity
            SET aci = ?
            "#,
            new_aci
        )
        .execute(&self.inner.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }

    async fn get_aci(&self) -> Result<Aci, Self::Error> {
        match sqlx::query!(
            r#"
            SELECT
                aci
            FROM
                identity
            "#
        )
        .fetch_one(&self.inner.pool)
        .await
        {
            Ok(row) => Ok(Aci::parse_from_service_id_string(row.aci.as_str()).ok_or(
                SignalClientError::DatabaseError(format!("Could not convert {} to aci", row.aci)),
            )?),
            Err(err) => Err(SignalClientError::DatabaseError(format!("{err}"))),
        }
    }

    async fn set_pni(&mut self, new_pni: Pni) -> Result<(), Self::Error> {
        let new_pni = new_pni.service_id_string();

        sqlx::query!(
            r#"
            UPDATE identity
            SET pni = ?
            "#,
            new_pni
        )
        .execute(&self.inner.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))
    }

    async fn get_pni(&self) -> Result<Pni, Self::Error> {
        match sqlx::query!(
            r#"
            SELECT
                pni
            FROM
                identity
            "#
        )
        .fetch_one(&self.inner.pool)
        .await
        {
            Ok(row) => Ok(Pni::parse_from_service_id_string(row.pni.as_str()).ok_or(
                SignalClientError::DatabaseError(format!("Could not convert {} to pni", row.pni)),
            )?),
            Err(err) => Err(SignalClientError::DatabaseError(format!("{err}"))),
        }
    }
}

impl StorageType for Device {
    type IdentityKeyStore = DeviceIdentityKeyStore;
    type PreKeyStore = DevicePreKeyStore;
    type SignedPreKeyStore = DeviceSignedPreKeyStore;
    type KyberPreKeyStore = DeviceKyberPreKeyStore;
    type SessionStore = DeviceSessionStore;
    type SenderKeyStore = DeviceSenderKeyStore;
}

impl ProtocolStore<Device> {
    pub async fn create_device_protocol_store(
        id_key_pair: IdentityKeyPair,
        aci_registration_id: u32,
        pool: SqlitePool,
    ) -> Self {
        Self {
            identity_key_store: DeviceIdentityKeyStore::create(
                id_key_pair,
                aci_registration_id,
                pool.clone(),
            )
            .await
            .unwrap(),
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
    pub async fn create(
        key_pair: IdentityKeyPair,
        registration_id: u32,
        pool: SqlitePool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pk = BASE64_STANDARD.encode(key_pair.identity_key().serialize());
        let sk = BASE64_STANDARD.encode(key_pair.private_key().serialize());

        sqlx::query!(
            r#"
            INSERT INTO IdentityKeys (public_key, private_key, registration_id)
            VALUES (?, ?, ?)
            "#,
            pk,
            sk,
            registration_id,
        )
        .execute(&pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalClientError::DatabaseError(format!("{err}")))?;
        Ok(Self { pool })
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
        match sqlx::query!(
            r#"
            SELECT
                public_key, private_key
            FROM
                IdentityKeys 
            "#
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => Ok(IdentityKeyPair::new(
                IdentityKey::decode(
                    &BASE64_STANDARD
                        .decode(row.public_key)
                        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?,
                )
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?,
                PrivateKey::deserialize(
                    &BASE64_STANDARD
                        .decode(row.private_key)
                        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?,
                )
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?,
            )),
            Err(err) => Err(SignalProtocolError::InvalidArgument(format!("{}", err))),
        }
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        sqlx::query!(
            r#"
            SELECT
                registration_id
            FROM
                IdentityKeys
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
        match self
            .get_identity(address)
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?
        {
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
        match self
            .get_identity(address)
            .await
            .expect("This function cannot return err")
        {
            Some(i) => Ok(i == *identity),
            None => Ok(true),
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
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?
                    .as_slice()
                    .try_into()?,
            )),
            Err(_) => Ok(None),
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
            Ok(row) => PreKeyRecord::deserialize(
                BASE64_STANDARD
                    .decode(row.pre_key_record)
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))?
                    .as_slice(),
            )
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(_) => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let rec = BASE64_STANDARD.encode(record.serialize()?);

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
            Ok(row) => SignedPreKeyRecord::deserialize(
                BASE64_STANDARD
                    .decode(row.signed_pre_key_record)
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?
                    .as_slice(),
            )
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err))),
            Err(_) => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = id.into();
        let rec = BASE64_STANDARD.encode(record.serialize()?);

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
            Ok(row) => KyberPreKeyRecord::deserialize(
                BASE64_STANDARD
                    .decode(row.kyber_pre_key_record)
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?
                    .as_slice(),
            ),
            Err(_) => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let rec = BASE64_STANDARD.encode(record.serialize()?);

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
            Ok(row) => SessionRecord::deserialize(
                BASE64_STANDARD
                    .decode(row.session_record)
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?
                    .as_slice(),
            )
            .map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let addr = format!("{}", address);
        let rec = BASE64_STANDARD.encode(record.serialize()?);

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
        let rec = BASE64_STANDARD.encode(record.serialize()?);

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
            Ok(row) => SenderKeyRecord::deserialize(
                BASE64_STANDARD
                    .decode(row.sender_key_record)
                    .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))?
                    .as_slice(),
            )
            .map(Some),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod device_protocol_test {
    use common::utils::time_now;
    use libsignal_core::{Aci, ProtocolAddress};
    use libsignal_protocol::{
        kem::KeyType, Direction, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, KeyPair,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
        SessionRecord, SessionStore, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
    };
    use rand::rngs::OsRng;
    use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
    use uuid::Uuid;

    use crate::storage::device::{
        DeviceIdentityKeyStore, DeviceKyberPreKeyStore, DevicePreKeyStore, DeviceSessionStore,
        DeviceSignedPreKeyStore,
    };

    async fn connect() -> SqlitePool {
        dotenv::dotenv().ok();
        let db_url = std::env::var("DATABASE_URL_TEST")
            .expect("Expected to read database url from .env file");
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
            DeviceIdentityKeyStore::create(key_pair, 1, connect().await)
                .await
                .unwrap();
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
        assert!(device_identity_key_store
            .save_identity(&address, other_key_pair.identity_key())
            .await
            .unwrap());

        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap()
                .unwrap(),
            *other_key_pair.identity_key()
        );

        // Test we did not overwrite our identity
        assert!(!device_identity_key_store
            .save_identity(&address, other_key_pair.identity_key())
            .await
            .unwrap());

        assert_eq!(
            device_identity_key_store
                .get_identity(&address)
                .await
                .unwrap()
                .unwrap(),
            *other_key_pair.identity_key()
        );

        // Test we overwrite our identity
        assert!(!device_identity_key_store
            .save_identity(&address, new_other_key_pair.identity_key())
            .await
            .unwrap());

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
            DeviceIdentityKeyStore::create(key_pair, 1, connect().await)
                .await
                .unwrap();
        let address = ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let other_key_pair = IdentityKeyPair::generate(&mut OsRng);

        let random_address =
            ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let random_key_pair = IdentityKeyPair::generate(&mut OsRng);

        // First use
        assert!(device_identity_key_store
            .is_trusted_identity(&address, other_key_pair.identity_key(), Direction::Sending)
            .await
            .unwrap());

        // Added identity
        device_identity_key_store
            .save_identity(&address, other_key_pair.identity_key())
            .await
            .unwrap();

        assert!(device_identity_key_store
            .is_trusted_identity(&address, other_key_pair.identity_key(), Direction::Sending)
            .await
            .unwrap());

        // Not trusted
        device_identity_key_store
            .save_identity(&random_address, random_key_pair.identity_key())
            .await
            .unwrap();

        assert!(!device_identity_key_store
            .is_trusted_identity(&address, random_key_pair.identity_key(), Direction::Sending)
            .await
            .unwrap());
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

        assert_eq!(retrived_pre_key.public_key().unwrap(), key_pair.public_key);

        assert_eq!(
            retrived_pre_key.private_key().unwrap().serialize(),
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

        let _ = device_pre_key_store.get_pre_key(pre_key_id).await.unwrap();

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
    async fn get_and_save_signed_pre_key_test() {
        let mut device_signed_pre_key_store = DeviceSignedPreKeyStore::new(connect().await);
        let signed_pre_key_id: SignedPreKeyId = 1.into();
        let now = time_now();
        let key_pair = KeyPair::generate(&mut OsRng);
        let signed_pre_key_record =
            SignedPreKeyRecord::new(signed_pre_key_id, now, &key_pair, &[0u8]);

        device_signed_pre_key_store
            .save_signed_pre_key(signed_pre_key_id, &signed_pre_key_record)
            .await
            .unwrap();

        let retrived_record = device_signed_pre_key_store
            .get_signed_pre_key(signed_pre_key_id)
            .await
            .unwrap();

        assert_eq!(retrived_record.id().unwrap(), signed_pre_key_id);

        assert_eq!(retrived_record.public_key().unwrap(), key_pair.public_key);

        assert_eq!(
            retrived_record.private_key().unwrap().serialize(),
            key_pair.private_key.serialize()
        );
    }

    #[tokio::test]
    async fn get_and_save_kyber_pre_key_test() {
        let mut device_kyber_pre_key_store = DeviceKyberPreKeyStore::new(connect().await);
        let kyber_pre_key_id: KyberPreKeyId = 1.into();
        let now = time_now();
        let key_pair = libsignal_protocol::kem::KeyPair::generate(KeyType::Kyber1024);
        let kyber_pre_key_record = KyberPreKeyRecord::new(kyber_pre_key_id, now, &key_pair, &[0u8]);

        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record)
            .await
            .unwrap();

        let retrived_record = device_kyber_pre_key_store
            .get_kyber_pre_key(kyber_pre_key_id)
            .await
            .unwrap();

        assert_eq!(retrived_record.id().unwrap(), kyber_pre_key_id);

        assert_eq!(
            retrived_record.public_key().unwrap().serialize(),
            key_pair.public_key.serialize()
        );

        assert_eq!(
            retrived_record.secret_key().unwrap().serialize(),
            key_pair.secret_key.serialize()
        );
    }

    #[tokio::test]
    async fn load_and_store_session_test() {
        let mut device_session_store = DeviceSessionStore::new(connect().await);
        let address = ProtocolAddress::new(Aci::from(Uuid::new_v4()).service_id_string(), 1.into());
        let record = SessionRecord::new_fresh();

        // Not stored yet
        assert!(device_session_store
            .load_session(&address)
            .await
            .unwrap()
            .is_none());

        // Stored
        device_session_store
            .store_session(&address, &record)
            .await
            .unwrap();

        assert_eq!(
            device_session_store
                .load_session(&address)
                .await
                .unwrap()
                .unwrap()
                .serialize()
                .unwrap(),
            record.serialize().unwrap()
        );
    }
}
