use crate::{
    account::{Account, Device},
    database::SignalDatabase,
};
use anyhow::{anyhow, bail, Result};
use axum::async_trait;
use common::{
    signal_protobuf::Envelope,
    web_api::{DevicePreKeyBundle, UploadPreKey, UploadSignedPreKey},
};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::{IdentityKey, PublicKey};
use sqlx::{postgres::PgPoolOptions, Acquire, PgConnection, Pool, Postgres, Transaction};

#[derive(Clone)]
pub struct PostgresDatabase {
    pool: Pool<Postgres>,
}

impl PostgresDatabase {
    pub async fn connect() -> Result<Self> {
        dotenv::dotenv().expect("Unable to load environment variables from .env file");
        let db_url = std::env::var("DATABASE_URL").expect("Unable to read DATABASE_URL env var");
        let pool = PgPoolOptions::new()
            .max_connections(100)
            .connect(&db_url)
            .await
            .map_err(|err| anyhow!(err))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl SignalDatabase for PostgresDatabase {
    async fn add_account(&self, account: &Account) -> Result<()> {
        let data = bincode::serialize(account.account_attr())?;
        sqlx::query!(
            r#"
            INSERT INTO
                accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number, account_attr)
            VALUES
                ($1, $2, $3, $4, $5, $6)
            "#,
            account.aci().service_id_string(),
            account.pni().service_id_string(),
            &*account.aci_identity_key().serialize(),
            &*account.pni_identity_key().serialize(),
            account.phone_number(),
            data
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        let devices = self.get_all_devices(service_id).await?;

        sqlx::query!(
            r#"
            SELECT 
                aci, pni, aci_identity_key, pni_identity_key, phone_number, account_attr
            FROM
                accounts
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            service_id.service_id_string(),
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| {
            Account::from_db(
                Pni::parse_from_service_id_string(&row.pni).unwrap(),
                Aci::parse_from_service_id_string(&row.aci).unwrap(),
                IdentityKey::new(PublicKey::deserialize(row.aci_identity_key.as_slice()).unwrap()),
                IdentityKey::new(PublicKey::deserialize(row.pni_identity_key.as_slice()).unwrap()),
                devices,
                row.phone_number,
                bincode::deserialize(&row.account_attr).unwrap(),
            )
        })
        .map_err(|err| err.into())
    }

    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE
                accounts
            SET
                aci = $2
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            service_id.service_id_string(),
            new_aci.service_id_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE
                accounts
            SET
                pni = $2
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            service_id.service_id_string(),
            new_pni.service_id_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM
                accounts
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            service_id.service_id_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn add_device(&self, service_id: &ServiceId, device: &Device) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO
                devices (owner, device_id, name, auth_token, salt)
            SELECT
                id, $2, $3, $4, $5
            FROM
                accounts
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            service_id.service_id_string(),
            device.device_id().to_string(),
            device.name().as_bytes(),
            device.auth_token(),
            device.salt(),
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn get_all_devices(&self, service_id: &ServiceId) -> Result<Vec<Device>> {
        sqlx::query!(
            r#"
            SELECT
                devices.device_id,
                devices.name,
                devices.auth_token,
                devices.salt,
                aspks.key_id AS aspk_key_id, aspks.public_key AS aspk_public_key, aspks.signature AS aspk_signature,
                pspks.key_id AS pspk_key_id, pspks.public_key AS pspk_public_key, pspks.signature AS pspk_signature,
                apqlrpks.key_id AS apqlrpk_key_id, apqlrpks.public_key AS apqlrpk_public_key, apqlrpks.signature AS apqlrpk_signature,
                ppqlrpks.key_id AS ppqlrpk_key_id, ppqlrpks.public_key AS ppqlrpk_public_key, ppqlrpks.signature AS ppqlrpk_signature
            FROM
                devices
                INNER JOIN device_keys ON device_keys.owner = devices.id
                INNER JOIN aci_signed_pre_key_store AS aspks ON aspks.key_id = device_keys.aci_signed_pre_key
                INNER JOIN pni_signed_pre_key_store AS pspks ON pspks.key_id = device_keys.pni_signed_pre_key
                INNER JOIN aci_pq_last_resort_pre_key_store AS apqlrpks ON apqlrpks.key_id = device_keys.aci_pq_last_resort_pre_key
                INNER JOIN pni_pq_last_resort_pre_key_store AS ppqlrpks ON ppqlrpks.key_id = device_keys.pni_pq_last_resort_pre_key
            WHERE
                devices.owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                )
            "#,
            service_id.service_id_string()
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    Device::new(
                        row.device_id.parse::<u32>().unwrap().into(),
                        std::str::from_utf8(&row.name).unwrap().to_string(),
                        0,
                        0,
                        row.auth_token,
                        row.salt,
                        UploadSignedPreKey { key_id: row.aspk_key_id.parse().expect("Database table is corrupt"), public_key: row.aspk_public_key.into(), signature: row.aspk_signature.into() },
                        UploadSignedPreKey { key_id: row.pspk_key_id.parse().expect("Database table is corrupt"), public_key: row.pspk_public_key.into(), signature: row.pspk_signature.into() },
                        UploadSignedPreKey { key_id: row.apqlrpk_key_id.parse().expect("Database table is corrupt"), public_key: row.apqlrpk_public_key.into(), signature: row.apqlrpk_signature.into() }, 
                        UploadSignedPreKey { key_id: row.ppqlrpk_key_id.parse().expect("Database table is corrupt"), public_key: row.ppqlrpk_public_key.into(), signature: row.ppqlrpk_signature.into() },
                    )
                })
                .collect()
        })
        .map_err(|err| err.into())
    }

    async fn get_device(&self, service_id: &ServiceId, device_id: u32) -> Result<Device> {
        sqlx::query!(
            r#"
            SELECT
                devices.device_id,
                devices.name,
                devices.auth_token,
                devices.salt,
                aspks.key_id AS aspk_key_id, aspks.public_key AS aspk_public_key, aspks.signature AS aspk_signature,
                pspks.key_id AS pspk_key_id, pspks.public_key AS pspk_public_key, pspks.signature AS pspk_signature,
                apqlrpks.key_id AS apqlrpk_key_id, apqlrpks.public_key AS apqlrpk_public_key, apqlrpks.signature AS apqlrpk_signature,
                ppqlrpks.key_id AS ppqlrpk_key_id, ppqlrpks.public_key AS ppqlrpk_public_key, ppqlrpks.signature AS ppqlrpk_signature
            FROM
                devices
                INNER JOIN device_keys ON device_keys.owner = devices.id
                INNER JOIN aci_signed_pre_key_store AS aspks ON aspks.key_id = device_keys.aci_signed_pre_key
                INNER JOIN pni_signed_pre_key_store AS pspks ON pspks.key_id = device_keys.pni_signed_pre_key
                INNER JOIN aci_pq_last_resort_pre_key_store AS apqlrpks ON apqlrpks.key_id = device_keys.aci_pq_last_resort_pre_key
                INNER JOIN pni_pq_last_resort_pre_key_store AS ppqlrpks ON ppqlrpks.key_id = device_keys.pni_pq_last_resort_pre_key
            WHERE
                devices.owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                )
                AND devices.device_id = $2
            "#,
            service_id.service_id_string(),
            device_id.to_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| {
            Device::new(
                row.device_id.parse::<u32>().unwrap().into(),
                std::str::from_utf8(&row.name).unwrap().to_string(),
                0,
                0,
                row.auth_token,
                row.salt,
                UploadSignedPreKey { key_id: row.aspk_key_id.parse().expect("Database table is corrupt"), public_key: row.aspk_public_key.into(), signature: row.aspk_signature.into() },
                UploadSignedPreKey { key_id: row.pspk_key_id.parse().expect("Database table is corrupt"), public_key: row.pspk_public_key.into(), signature: row.pspk_signature.into() },
                UploadSignedPreKey { key_id: row.apqlrpk_key_id.parse().expect("Database table is corrupt"), public_key: row.apqlrpk_public_key.into(), signature: row.apqlrpk_signature.into() }, 
                UploadSignedPreKey { key_id: row.ppqlrpk_key_id.parse().expect("Database table is corrupt"), public_key: row.ppqlrpk_public_key.into(), signature: row.ppqlrpk_signature.into() },
            )
        })
        .map_err(|err| err.into())
    }

    async fn delete_device(&self, service_id: &ServiceId, device_id: u32) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM
                devices
            WHERE
                owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                )
                AND device_id = $2
            "#,
            service_id.service_id_string(),
            device_id.to_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn push_message_queue(
        &self,
        address: ProtocolAddress,
        messages: Vec<Envelope>,
    ) -> Result<()> {
        for msg in messages {
            let data = bincode::serialize(&msg)?;
            sqlx::query!(
                r#"
                INSERT INTO
                    msq_queue (receiver, msg)
                SELECT
                    id, $1
                FROM
                    devices
                WHERE
                    owner = (
                        SELECT
                            id
                        FROM
                            accounts
                        WHERE
                            aci = $2 OR
                            pni = $2
                    )
                    AND device_id = $3
                "#,
                data,
                address.name(),
                address.device_id().to_string()
            )
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|err| anyhow!("{}", err))?;
        }
        Ok(())
    }

    async fn pop_msg_queue(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        sqlx::query!(
            r#"
            SELECT
                msq_queue.msg
            FROM
                msq_queue
                INNER JOIN devices on devices.id = msq_queue.receiver
            WHERE
                devices.owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                )
                AND devices.device_id = $2
            "#,
            address.name(),
            address.device_id().to_string()
        )
        .fetch_all(&self.pool)
        .await?
        .iter()
        .try_fold(vec![], |mut acc, msg| -> Result<Vec<Envelope>> {
            acc.push(bincode::deserialize(&msg.msg)?);
            Ok(acc)
        })
    }

    async fn store_aci_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_aci_signed_pre_key(pool, spk).await
    }

    async fn store_pni_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pni_signed_pre_key(pool, spk).await
    }

    async fn store_pq_aci_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pq_aci_signed_pre_key(pool, pq_spk).await
    }

    async fn store_pq_pni_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pq_pni_signed_pre_key(pool, pq_spk).await
    }

    async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        store_aci_signed_pre_key(&mut tx, &data.aci_signed_pre_key).await?;
        store_pni_signed_pre_key(&mut tx, &data.pni_signed_pre_key).await?;
        store_pq_aci_signed_pre_key(&mut tx, &data.aci_pq_pre_key).await?;
        store_pq_pni_signed_pre_key(&mut tx, &data.pni_pq_pre_key).await?;

        sqlx::query!(
            r#"
            INSERT INTO
                device_keys (owner, aci_signed_pre_key, pni_signed_pre_key, aci_pq_last_resort_pre_key, pni_pq_last_resort_pre_key)
            SELECT
                id, $2, $3, $4, $5
            FROM
                devices
            WHERE
                owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                )
            "#,
            address.name(),
            data.aci_signed_pre_key.key_id.to_string(),
            data.pni_signed_pre_key.key_id.to_string(),
            data.aci_pq_pre_key.key_id.to_string(),
            data.pni_pq_pre_key.key_id.to_string()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await.map(|_| ()).map_err(|err| err.into())
    }

    async fn get_key_bundle(&self, address: &ProtocolAddress) -> Result<DevicePreKeyBundle> {
        sqlx::query!(
            r#"
            SELECT
                aci_signed_pre_key_store.key_id AS aspk_id,
                aci_signed_pre_key_store.public_key AS aspk,
                aci_signed_pre_key_store.signature AS aspk_sig,
                pni_signed_pre_key_store.key_id AS pspk_id,
                pni_signed_pre_key_store.public_key AS pspk,
                pni_signed_pre_key_store.signature AS pspk_sig,
                aci_pq_last_resort_pre_key_store.key_id AS apqlrpk_id,
                aci_pq_last_resort_pre_key_store.public_key AS apqlrpk,
                aci_pq_last_resort_pre_key_store.signature AS apqlrpk_sig,
                pni_pq_last_resort_pre_key_store.key_id AS ppqlrpk_id,
                pni_pq_last_resort_pre_key_store.public_key AS ppqlrpk,
                pni_pq_last_resort_pre_key_store.signature AS ppqlrpk_sig
            FROM
                device_keys
                INNER JOIN aci_signed_pre_key_store ON aci_signed_pre_key_store.key_id = device_keys.aci_signed_pre_key
                INNER JOIN pni_signed_pre_key_store ON pni_signed_pre_key_store.key_id = device_keys.pni_signed_pre_key
                INNER JOIN aci_pq_last_resort_pre_key_store ON aci_pq_last_resort_pre_key_store.key_id = device_keys.aci_pq_last_resort_pre_key
                INNER JOIN pni_pq_last_resort_pre_key_store ON pni_pq_last_resort_pre_key_store.key_id = device_keys.pni_pq_last_resort_pre_key
                INNER JOIN accounts ON accounts.id = device_keys.owner
            WHERE
                aci = $1 OR
                pni = $1
            "#,
            address.name()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| {
            DevicePreKeyBundle {
                aci_signed_pre_key: UploadSignedPreKey {
                    key_id: row.aspk_id.parse().unwrap(),
                    public_key: row.aspk.into(),
                    signature: row.aspk_sig.into()
                },
                pni_signed_pre_key: UploadSignedPreKey {
                    key_id: row.pspk_id.parse().unwrap(),
                    public_key: row.pspk.into(),
                    signature: row.pspk_sig.into()
                },
                aci_pq_pre_key: UploadSignedPreKey {
                    key_id: row.apqlrpk_id.parse().unwrap(),
                    public_key: row.apqlrpk.into(),
                    signature: row.apqlrpk_sig.into()
                },
                pni_pq_pre_key: UploadSignedPreKey {
                    key_id: row.ppqlrpk_id.parse().unwrap(),
                    public_key: row.ppqlrpk.into(),
                    signature: row.ppqlrpk_sig.into()
                }
            }
        })
        .map_err(|err| err.into())
    }

    async fn get_one_time_ec_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn get_one_time_pq_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn store_one_time_ec_pre_keys(
        &self,
        otpks: Vec<UploadPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        for otpk in otpks {
            match sqlx::query!(
                r#"
                INSERT INTO
                    one_time_ec_pre_key_store (owner, key_id, public_key)
                SELECT
                    id, $3, $4
                FROM
                    devices
                WHERE
                    owner = (
                        SELECT
                            id
                        FROM
                            accounts
                        WHERE
                            aci = $1 OR
                            pni = $1
                    )
                    AND devices.device_id = $2
                "#,
                owner.name(),
                owner.device_id().to_string(),
                otpk.key_id.to_string(),
                &*otpk.public_key,
            )
            .execute(&self.pool)
            .await
            {
                Ok(_) => (),
                Err(err) => bail!("{}", err),
            }
        }

        Ok(())
    }

    async fn store_one_time_pq_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        for otpk in otpks {
            match sqlx::query!(
                r#"
                INSERT INTO
                    one_time_pq_pre_key_store (owner, key_id, public_key, signature)
                SELECT
                    id, $3, $4, $5
                FROM
                    devices
                WHERE
                    owner = (
                        SELECT
                            id
                        FROM
                            accounts
                        WHERE
                            aci = $1 OR
                            pni = $1
                    )
                    AND devices.device_id = $2
                "#,
                owner.name(),
                owner.device_id().to_string(),
                otpk.key_id.to_string(),
                &*otpk.public_key,
                &*otpk.signature
            )
            .execute(&self.pool)
            .await
            {
                Ok(_) => (),
                Err(err) => bail!("{}", err),
            }
        }

        Ok(())
    }

    async fn get_one_time_ec_pre_key(&self, owner: &ProtocolAddress) -> Result<UploadPreKey> {
        sqlx::query!(
            r#"
            WITH key AS (
                DELETE FROM
                    one_time_ec_pre_key_store
                WHERE id IN (
                    SELECT
                        one_time_ec_pre_key_store.id
                    FROM
                        one_time_ec_pre_key_store
                        INNER JOIN devices on devices.id = one_time_ec_pre_key_store.owner
                    WHERE
                        devices.owner = (
                            SELECT
                                id
                            FROM
                                accounts
                            WHERE
                                aci = $1 OR
                                pni = $1
                        )
                        AND devices.device_id = $2
                    LIMIT 1
                )
                RETURNING
                    key_id, public_key
            )
            SELECT
                key_id, public_key
            FROM
                key
            "#,
            owner.name(),
            owner.device_id().to_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| UploadPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
        })
        .map_err(|err| err.into())
    }

    async fn get_one_time_pq_pre_key(&self, owner: &ProtocolAddress) -> Result<UploadSignedPreKey> {
        sqlx::query!(
            r#"
            WITH key AS (
                DELETE FROM
                    one_time_pq_pre_key_store
                WHERE id IN (
                    SELECT
                        one_time_pq_pre_key_store.id
                    FROM
                        one_time_pq_pre_key_store
                        INNER JOIN devices on devices.id = one_time_pq_pre_key_store.owner
                    WHERE
                        devices.owner = (
                            SELECT
                                id
                            FROM
                                accounts
                            WHERE
                                aci = $1 OR
                                pni = $1
                        )
                        AND devices.device_id = $2
                    LIMIT 1
                )
                RETURNING
                    key_id, public_key, signature
            )
            SELECT
                key_id, public_key, signature
            FROM
                key
            "#,
            owner.name(),
            owner.device_id().to_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.unwrap().into(),
        })
        .map_err(|err| err.into())
    }
}

async fn store_aci_signed_pre_key(tx: &mut PgConnection, spk: &UploadSignedPreKey) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            aci_signed_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        ON CONFLICT (key_id)
            DO UPDATE SET key_id = $1, public_key = $2, signature = $3;
        "#,
        spk.key_id.to_string(),
        &*spk.public_key,
        &*spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

async fn store_pni_signed_pre_key(tx: &mut PgConnection, spk: &UploadSignedPreKey) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            pni_signed_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        ON CONFLICT (key_id)
            DO UPDATE SET key_id = $1, public_key = $2, signature = $3;
        "#,
        spk.key_id.to_string(),
        &*spk.public_key,
        &*spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

async fn store_pq_aci_signed_pre_key(
    tx: &mut PgConnection,
    pq_spk: &UploadSignedPreKey,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            aci_pq_last_resort_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        ON CONFLICT (key_id)
            DO UPDATE SET key_id = $1, public_key = $2, signature = $3;
        "#,
        pq_spk.key_id.to_string(),
        &*pq_spk.public_key,
        &*pq_spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

async fn store_pq_pni_signed_pre_key(
    tx: &mut PgConnection,
    pq_spk: &UploadSignedPreKey,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            pni_pq_last_resort_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        ON CONFLICT (key_id)
            DO UPDATE SET key_id = $1, public_key = $2, signature = $3;
        "#,
        pq_spk.key_id.to_string(),
        &*pq_spk.public_key,
        &*pq_spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}
