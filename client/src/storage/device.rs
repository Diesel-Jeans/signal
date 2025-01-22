use std::collections::HashSet;

use super::{
    database::ClientDB,
    generic::{SignalStore, Storage},
};
use crate::contact_manager::Contact;
use axum::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::{
    Direction, GenericSignedPreKey as _, IdentityKey, IdentityKeyPair, KyberPreKeyId,
    KyberPreKeyRecord, PreKeyId, PreKeyRecord, PrivateKey, SenderKeyRecord, SessionRecord,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Device {
    pool: SqlitePool,
}

impl Device {
    pub fn new(pool: SqlitePool) -> Self {
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
impl ClientDB for Device {
    type Error = SignalProtocolError;

    async fn insert_account_information(
        &self,
        aci: Aci,
        pni: Pni,
        password: String,
    ) -> Result<(), Self::Error> {
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
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn insert_account_key_information(
        &self,
        key_pair: IdentityKeyPair,
        registration_id: u32,
    ) -> Result<(), Self::Error> {
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
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn get_key_ids(&self) -> Result<(u32, u32, u32), Self::Error> {
        sqlx::query!(
            r#"
            WITH max_pre_key_id_table AS (
                SELECT
                    1 AS _id,
                    MAX(pre_key_id) AS max_pre_key_id
                FROM
                    DevicePreKeyStore
            ), max_signed_pre_key_id_table AS (
                SELECT
                    1 AS _id,
                    MAX(signed_pre_key_id) AS max_signed_pre_key_id
                FROM
                    DeviceSignedPreKeyStore
            ), max_kyber_pre_key_id_table AS (
                SELECT
                    1 AS _id,
                    MAX(kyber_pre_key_id) AS max_kyber_pre_key_id
                FROM
                    DeviceKyberPreKeyStore
            )
            SELECT
                CASE WHEN mpk.max_pre_key_id IS NOT NULL
                    THEN mpk.max_pre_key_id
                ELSE
                    0
                END AS mpkid,
                CASE WHEN spk.max_signed_pre_key_id IS NOT NULL
                    THEN spk.max_signed_pre_key_id
                ELSE
                    0
                END AS spkid,
                CASE WHEN kpk.max_kyber_pre_key_id IS NOT NULL
                    THEN kpk.max_kyber_pre_key_id
                ELSE
                    0
                END AS kpkid
            FROM
                max_pre_key_id_table mpk
                INNER JOIN max_signed_pre_key_id_table spk ON spk._id = mpk._id
                INNER JOIN max_kyber_pre_key_id_table kpk ON kpk._id = mpk._id
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| (row.mpkid as u32, row.spkid as u32, row.kpkid as u32))
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn store_contact(&self, contact: &Contact) -> Result<(), Self::Error> {
        let service_id = contact.service_id.service_id_string();
        let device_ids = contact
            .device_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");

        sqlx::query!(
            r#"
            INSERT INTO Contacts(service_id, device_ids)
            VALUES(?, ?)
            ON CONFLICT(service_id) DO UPDATE SET device_ids = ?
            "#,
            service_id,
            device_ids,
            device_ids,
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn load_contacts(&self) -> Result<Vec<Contact>, Self::Error> {
        match sqlx::query!(
            r#"
            SELECT
                service_id,
                device_ids
            FROM
                Contacts
            "#
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => {
                let mut contacts = vec![];
                for row in rows {
                    let mut device_ids = HashSet::new();
                    if row.device_ids != "" {
                        for device_id in row.device_ids.split(",") {
                            device_ids.insert(DeviceId::from(device_id.parse::<u32>().map_err(
                                |err| {
                                    SignalProtocolError::InvalidArgument(format!(
                                        "Could not parse device id: {err}"
                                    ))
                                },
                            )?));
                        }
                    }
                    contacts.push(Contact {
                        service_id: ServiceId::parse_from_service_id_string(
                            row.service_id.as_str(),
                        )
                        .ok_or(SignalProtocolError::InvalidArgument(format!(
                            "Could not parse service_id: {}",
                            row.service_id
                        )))?,
                        device_ids,
                    });
                }
                Ok(contacts)
            }
            Err(err) => Err(SignalProtocolError::InvalidArgument(format!("{err}"))),
        }
    }

    async fn remove_contact(&self, service_id: &ServiceId) -> Result<(), Self::Error> {
        let name = service_id.service_id_string();

        sqlx::query!(
            r#"
            DELETE FROM
                Contacts
            WHERE
                service_id = ?
            "#,
            name
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn insert_service_id_for_nickname(
        &self,
        nickname: &str,
        service_id: &ServiceId,
    ) -> Result<(), Self::Error> {
        let service_id = service_id.service_id_string();
        sqlx::query!(
            r#"
            INSERT INTO Nicknames(name, service_id)
            VALUES(?, ?)
            "#,
            nickname,
            service_id,
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{err}")))
    }

    async fn get_service_id_by_nickname(&self, nickname: &str) -> Result<ServiceId, Self::Error> {
        match sqlx::query!(
            r#"
            SELECT
                service_id
            FROM
                Nicknames
            WHERE
                name = ?
            "#,
            nickname
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => Ok(
                ServiceId::parse_from_service_id_string(row.service_id.as_str()).ok_or(
                    SignalProtocolError::InvalidArgument(format!("Could not parse service_id")),
                )?,
            ),
            Err(err) => Err(SignalProtocolError::InvalidArgument(format!("{err}"))),
        }
    }

    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, Self::Error> {
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

    async fn get_local_registration_id(&self) -> Result<u32, Self::Error> {
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
    ) -> Result<bool, Self::Error> {
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
    ) -> Result<bool, Self::Error> {
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
    ) -> Result<Option<IdentityKey>, Self::Error> {
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

    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, Self::Error> {
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
    ) -> Result<(), Self::Error> {
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

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), Self::Error> {
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

    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, Self::Error> {
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
    ) -> Result<(), Self::Error> {
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

    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, Self::Error> {
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
    ) -> Result<(), Self::Error> {
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
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, Self::Error> {
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
    ) -> Result<(), Self::Error> {
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
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), Self::Error> {
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
    ) -> Result<Option<SenderKeyRecord>, Self::Error> {
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

    async fn set_password(&mut self, new_password: String) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            UPDATE identity
            SET password = ?
            "#,
            new_password
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
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
        .fetch_one(&self.pool)
        .await
        .map(|row| row.password)
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
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
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
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
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => Ok(Aci::parse_from_service_id_string(row.aci.as_str()).ok_or(
                SignalProtocolError::InvalidArgument(format!(
                    "Could not convert {} to aci",
                    row.aci
                )),
            )?),
            Err(err) => Err(SignalProtocolError::InvalidArgument(format!("{}", err))),
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
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
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
        .fetch_one(&self.pool)
        .await
        {
            Ok(row) => Ok(Pni::parse_from_service_id_string(row.pni.as_str()).ok_or(
                SignalProtocolError::InvalidArgument(format!(
                    "Could not convert {} to pni",
                    row.pni
                )),
            )?),
            Err(err) => Err(SignalProtocolError::InvalidArgument(format!("{}", err))),
        }
    }
}

#[async_trait(?Send)]
impl SignalStore for Storage<Device> {
    type Error = SignalProtocolError;

    async fn set_password(&mut self, new_password: String) -> Result<(), Self::Error> {
        self.device
            .set_password(new_password)
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn get_password(&self) -> Result<String, Self::Error> {
        self.device
            .get_password()
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn set_aci(&mut self, new_aci: Aci) -> Result<(), Self::Error> {
        self.device
            .set_aci(new_aci)
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn get_aci(&self) -> Result<Aci, Self::Error> {
        self.device
            .get_aci()
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn set_pni(&mut self, new_pni: Pni) -> Result<(), Self::Error> {
        self.device
            .set_pni(new_pni)
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }

    async fn get_pni(&self) -> Result<Pni, Self::Error> {
        self.device
            .get_pni()
            .await
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("{}", err)))
    }
}

#[cfg(test)]
mod device_protocol_test {
    use crate::{
        key_manager::KeyManager,
        storage::{
            database::{
                ClientDB, DeviceIdentityKeyStore, DeviceKyberPreKeyStore, DevicePreKeyStore,
                DeviceSessionStore, DeviceSignedPreKeyStore,
            },
            device::Device,
        },
        test_utils::user::{new_contact, new_protocol_address, new_rand_number, new_service_id},
    };
    use libsignal_protocol::{
        Direction, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyStore,
        PreKeyStore, SessionRecord, SessionStore, SignedPreKeyStore,
    };
    use rand::rngs::OsRng;
    use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
    use std::collections::HashMap;

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
        let device = Device::new(connect().await);
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device);
        let address = new_protocol_address();
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
        let device = Device::new(connect().await);
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device);
        let address = new_protocol_address();
        let other_key_pair = IdentityKeyPair::generate(&mut OsRng);

        let random_address = new_protocol_address();
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
        let mut key_man = KeyManager::default();
        let device = Device::new(connect().await);
        let mut device_pre_key_store = DevicePreKeyStore::new(device);
        let pre_key_record = key_man
            .generate_pre_key(&mut device_pre_key_store, &mut OsRng)
            .await
            .unwrap();

        device_pre_key_store
            .save_pre_key(pre_key_record.id().unwrap(), &pre_key_record)
            .await
            .unwrap();

        let retrived_pre_key = device_pre_key_store
            .get_pre_key(pre_key_record.id().unwrap())
            .await
            .unwrap();

        assert_eq!(retrived_pre_key.id().unwrap(), pre_key_record.id().unwrap());

        assert_eq!(
            retrived_pre_key.public_key().unwrap(),
            pre_key_record.key_pair().unwrap().public_key
        );

        assert_eq!(
            retrived_pre_key.private_key().unwrap().serialize(),
            pre_key_record.key_pair().unwrap().private_key.serialize()
        );
    }
    #[tokio::test]
    async fn remove_pre_key_test() {
        let mut key_man = KeyManager::default();
        let device = Device::new(connect().await);
        let mut device_pre_key_store = DevicePreKeyStore::new(device);
        let pre_key_record = key_man
            .generate_pre_key(&mut device_pre_key_store, &mut OsRng)
            .await
            .unwrap();

        device_pre_key_store
            .save_pre_key(pre_key_record.id().unwrap(), &pre_key_record)
            .await
            .unwrap();

        let _ = device_pre_key_store
            .get_pre_key(pre_key_record.id().unwrap())
            .await
            .unwrap();

        device_pre_key_store
            .remove_pre_key(pre_key_record.id().unwrap())
            .await
            .unwrap();

        device_pre_key_store
            .get_pre_key(pre_key_record.id().unwrap())
            .await
            .expect_err("We should not be able to retrive the key after deletion");
    }

    #[tokio::test]
    async fn get_and_save_signed_pre_key_test() {
        let pool = connect().await;

        let device = Device::new(pool.clone());

        device
            .insert_account_key_information(
                IdentityKeyPair::generate(&mut OsRng),
                new_rand_number(),
            )
            .await
            .unwrap();

        let mut key_man = KeyManager::default();
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device.clone());
        let mut device_signed_pre_key_store = DeviceSignedPreKeyStore::new(device);
        let signed_pre_key_record = key_man
            .generate_signed_pre_key(
                &mut device_identity_key_store,
                &mut device_signed_pre_key_store,
                &mut OsRng,
            )
            .await
            .unwrap();
        device_signed_pre_key_store
            .save_signed_pre_key(signed_pre_key_record.id().unwrap(), &signed_pre_key_record)
            .await
            .unwrap();

        let retrived_record = device_signed_pre_key_store
            .get_signed_pre_key(signed_pre_key_record.id().unwrap())
            .await
            .unwrap();

        assert_eq!(
            retrived_record.id().unwrap(),
            signed_pre_key_record.id().unwrap()
        );
        assert_eq!(
            retrived_record.public_key().unwrap(),
            signed_pre_key_record.key_pair().unwrap().public_key
        );
        assert_eq!(
            retrived_record.private_key().unwrap().serialize(),
            signed_pre_key_record
                .key_pair()
                .unwrap()
                .private_key
                .serialize()
        );
    }

    #[tokio::test]
    async fn get_and_save_kyber_pre_key_test() {
        let pool = connect().await;

        let device = Device::new(pool.clone());

        device
            .insert_account_key_information(
                IdentityKeyPair::generate(&mut OsRng),
                new_rand_number(),
            )
            .await
            .unwrap();

        let mut key_man = KeyManager::default();
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device.clone());
        let mut device_kyber_pre_key_store = DeviceKyberPreKeyStore::new(device);
        let kyber_pre_key_record = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();

        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record.id().unwrap(), &kyber_pre_key_record)
            .await
            .unwrap();

        let retrived_record = device_kyber_pre_key_store
            .get_kyber_pre_key(kyber_pre_key_record.id().unwrap())
            .await
            .unwrap();

        assert_eq!(
            retrived_record.id().unwrap(),
            kyber_pre_key_record.id().unwrap()
        );

        assert_eq!(
            retrived_record.public_key().unwrap().serialize(),
            kyber_pre_key_record
                .key_pair()
                .unwrap()
                .public_key
                .serialize()
        );

        assert_eq!(
            retrived_record.secret_key().unwrap().serialize(),
            kyber_pre_key_record
                .key_pair()
                .unwrap()
                .secret_key
                .serialize()
        );
    }

    #[tokio::test]
    async fn load_and_store_session_test() {
        let device = Device::new(connect().await);
        let mut device_session_store = DeviceSessionStore::new(device);
        let address = new_protocol_address();
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

    #[tokio::test]
    async fn insert_and_get_key_ids() {
        let pool = connect().await;

        let device = Device::new(pool.clone());

        device
            .insert_account_key_information(
                IdentityKeyPair::generate(&mut OsRng),
                new_rand_number(),
            )
            .await
            .unwrap();

        let mut key_man = KeyManager::default();
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device.clone());
        let mut device_pre_key_store = DevicePreKeyStore::new(device.clone());
        let mut device_signed_pre_key_store = DeviceSignedPreKeyStore::new(device.clone());
        let mut device_kyber_pre_key_store = DeviceKyberPreKeyStore::new(device.clone());
        let pre_key_record = key_man
            .generate_pre_key(&mut device_pre_key_store, &mut OsRng)
            .await
            .unwrap();
        let signed_pre_key_record1 = key_man
            .generate_signed_pre_key(
                &mut device_identity_key_store,
                &mut device_signed_pre_key_store,
                &mut OsRng,
            )
            .await
            .unwrap();
        let signed_pre_key_record2 = key_man
            .generate_signed_pre_key(
                &mut device_identity_key_store,
                &mut device_signed_pre_key_store,
                &mut OsRng,
            )
            .await
            .unwrap();
        let kyber_pre_key_record1 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();
        let kyber_pre_key_record2 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();
        let kyber_pre_key_record3 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();

        device_pre_key_store
            .save_pre_key(pre_key_record.id().unwrap(), &pre_key_record)
            .await
            .unwrap();

        device_signed_pre_key_store
            .save_signed_pre_key(
                signed_pre_key_record1.id().unwrap(),
                &signed_pre_key_record1,
            )
            .await
            .unwrap();
        device_signed_pre_key_store
            .save_signed_pre_key(
                signed_pre_key_record2.id().unwrap(),
                &signed_pre_key_record2,
            )
            .await
            .unwrap();

        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record1.id().unwrap(), &kyber_pre_key_record1)
            .await
            .unwrap();
        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record2.id().unwrap(), &kyber_pre_key_record2)
            .await
            .unwrap();
        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record3.id().unwrap(), &kyber_pre_key_record3)
            .await
            .unwrap();

        let (pkidmax, spkidmax, kpkidmax) = device.get_key_ids().await.unwrap();

        assert_eq!(pkidmax, 0);
        assert_eq!(spkidmax, 1);
        assert_eq!(kpkidmax, 2);
    }

    #[tokio::test]
    async fn remove_key_and_get_ids_test() {
        let pool = connect().await;

        let device = Device::new(pool.clone());

        device
            .insert_account_key_information(
                IdentityKeyPair::generate(&mut OsRng),
                new_rand_number(),
            )
            .await
            .unwrap();

        let mut key_man = KeyManager::default();
        let mut device_identity_key_store = DeviceIdentityKeyStore::new(device.clone());
        let mut device_pre_key_store = DevicePreKeyStore::new(device.clone());
        let mut device_signed_pre_key_store = DeviceSignedPreKeyStore::new(device.clone());
        let mut device_kyber_pre_key_store = DeviceKyberPreKeyStore::new(device.clone());
        let pre_key_record1 = key_man
            .generate_pre_key(&mut device_pre_key_store, &mut OsRng)
            .await
            .unwrap();
        let pre_key_record2 = key_man
            .generate_pre_key(&mut device_pre_key_store, &mut OsRng)
            .await
            .unwrap();
        let signed_pre_key_record1 = key_man
            .generate_signed_pre_key(
                &mut device_identity_key_store,
                &mut device_signed_pre_key_store,
                &mut OsRng,
            )
            .await
            .unwrap();
        let signed_pre_key_record2 = key_man
            .generate_signed_pre_key(
                &mut device_identity_key_store,
                &mut device_signed_pre_key_store,
                &mut OsRng,
            )
            .await
            .unwrap();
        let kyber_pre_key_record1 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();
        let kyber_pre_key_record2 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();
        let kyber_pre_key_record3 = key_man
            .generate_kyber_pre_key(
                &mut device_identity_key_store,
                &mut device_kyber_pre_key_store,
            )
            .await
            .unwrap();

        device_pre_key_store
            .save_pre_key(pre_key_record1.id().unwrap(), &pre_key_record1)
            .await
            .unwrap();
        device_pre_key_store
            .remove_pre_key(pre_key_record1.id().unwrap())
            .await
            .unwrap();
        device_pre_key_store
            .save_pre_key(pre_key_record2.id().unwrap(), &pre_key_record2)
            .await
            .unwrap();

        device_signed_pre_key_store
            .save_signed_pre_key(
                signed_pre_key_record1.id().unwrap(),
                &signed_pre_key_record1,
            )
            .await
            .unwrap();
        device_signed_pre_key_store
            .save_signed_pre_key(
                signed_pre_key_record2.id().unwrap(),
                &signed_pre_key_record2,
            )
            .await
            .unwrap();

        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record1.id().unwrap(), &kyber_pre_key_record1)
            .await
            .unwrap();
        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record2.id().unwrap(), &kyber_pre_key_record2)
            .await
            .unwrap();
        device_kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_record3.id().unwrap(), &kyber_pre_key_record3)
            .await
            .unwrap();

        let (pkidmax, spkidmax, kpkidmax) = device.get_key_ids().await.unwrap();

        assert_eq!(pkidmax, 1);
        assert_eq!(spkidmax, 1);
        assert_eq!(kpkidmax, 2);
    }

    #[tokio::test]
    async fn store_and_load_contact() {
        // store_contact
        // load_contact
        let device = Device::new(connect().await);

        let contacts = vec![new_contact(), new_contact(), new_contact()];

        device.store_contact(&contacts[0]).await.unwrap();
        device.store_contact(&contacts[1]).await.unwrap();
        device.store_contact(&contacts[2]).await.unwrap();

        let retrived_contacts = device.load_contacts().await.unwrap();

        assert_eq!(contacts, retrived_contacts);
    }

    #[tokio::test]
    async fn insert_and_get_address_by_nickname() {
        // insert_address_for_nickname
        // get_address_by_nickname
        let device = Device::new(connect().await);

        let nicknames = vec!["Alice", "Bob", "Charlie"];

        let nickname_map = HashMap::from([
            (nicknames[0], new_service_id()),
            (nicknames[1], new_service_id()),
            (nicknames[2], new_service_id()),
        ]);

        device
            .insert_service_id_for_nickname(nicknames[0], &nickname_map[nicknames[0]])
            .await
            .unwrap();
        device
            .insert_service_id_for_nickname(nicknames[1], &nickname_map[nicknames[1]])
            .await
            .unwrap();
        device
            .insert_service_id_for_nickname(nicknames[2], &nickname_map[nicknames[2]])
            .await
            .unwrap();

        assert_eq!(
            device
                .get_service_id_by_nickname(nicknames[0])
                .await
                .unwrap(),
            nickname_map[nicknames[0]]
        );
        assert_eq!(
            device
                .get_service_id_by_nickname(nicknames[1])
                .await
                .unwrap(),
            nickname_map[nicknames[1]]
        );
        assert_eq!(
            device
                .get_service_id_by_nickname(nicknames[2])
                .await
                .unwrap(),
            nickname_map[nicknames[2]]
        );
    }
}
