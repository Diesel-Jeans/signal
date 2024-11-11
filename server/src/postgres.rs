use crate::{
    account::{self, Account, Device},
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
    pub async fn connect(database_url: String) -> Self {
        dotenv::dotenv();
        let db_url = std::env::var(database_url).expect("Unable to read database url env var");
        Self {
            pool: PgPoolOptions::new()
                .max_connections(100)
                .connect(&db_url)
                .await
                .expect("Failed to connect to the database."),
        }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    async fn store_aci_signed_pre_key(
        &self,
        spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_aci_signed_pre_key(pool, spk, address).await
    }

    async fn store_pni_signed_pre_key(
        &self,
        spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pni_signed_pre_key(pool, spk, address).await
    }

    async fn store_pq_aci_signed_pre_key(
        &self,
        pq_spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pq_aci_signed_pre_key(pool, pq_spk, address).await
    }

    async fn store_pq_pni_signed_pre_key(
        &self,
        pq_spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let pool = &mut self.pool.acquire().await?;
        store_pq_pni_signed_pre_key(pool, pq_spk, address).await
    }
}

#[async_trait]
impl SignalDatabase for PostgresDatabase {
    async fn add_account(&self, account: &Account) -> Result<()> {
        let data = bincode::serialize(account.account_attr())?;
        match sqlx::query!(
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
        {
            Ok(_) => {
                self.add_device(&ServiceId::Aci(account.aci()), &account.devices()[0])
                    .await
            }
            Err(err) => bail!(err),
        }
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
                devices (owner, device_id, name, auth_token, salt, registration_id)
            SELECT
                id, $2, $3, $4, $5, $6
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
            device.registration_id().to_string(),
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
                device_id,
                name,
                auth_token,
                salt,
                registration_id
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
                        row.registration_id.parse().unwrap(),
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
                device_id,
                name,
                auth_token,
                salt,
                registration_id
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
                AND device_id = $2
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
                row.registration_id.parse().unwrap(),
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
        address: &ProtocolAddress,
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

    async fn store_signed_pre_key(
        &self,
        spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let service_id = ServiceId::parse_from_service_id_string(address.name())
            .ok_or_else(|| anyhow!("Invalid service id"))?;
        match service_id {
            ServiceId::Aci(_) => self.store_aci_signed_pre_key(spk, address).await?,
            ServiceId::Pni(_) => self.store_pni_signed_pre_key(spk, address).await?,
        }
        Ok(())
    }
    async fn store_pq_signed_pre_key(
        &self,
        spk: &UploadSignedPreKey,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let service_id = ServiceId::parse_from_service_id_string(address.name())
            .ok_or_else(|| anyhow!("Invalid service id"))?;
        match service_id {
            ServiceId::Aci(_) => self.store_pq_aci_signed_pre_key(spk, address).await?,
            ServiceId::Pni(_) => self.store_pq_pni_signed_pre_key(spk, address).await?,
        }
        Ok(())
    }

    async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        store_aci_signed_pre_key(&mut tx, &data.aci_signed_pre_key, address).await?;
        store_pni_signed_pre_key(&mut tx, &data.pni_signed_pre_key, address).await?;
        store_pq_aci_signed_pre_key(&mut tx, &data.aci_pq_pre_key, address).await?;
        store_pq_pni_signed_pre_key(&mut tx, &data.pni_pq_pre_key, address).await?;

        sqlx::query!(
            r#"
            INSERT INTO
                device_keys (owner, aci_signed_pre_key, pni_signed_pre_key, aci_pq_last_resort_pre_key, pni_pq_last_resort_pre_key)
            SELECT
                devices.id, 
                aci_signed_pre_key_store.id, 
                pni_signed_pre_key_store.id, 
                aci_pq_last_resort_pre_key_store.id, 
                pni_pq_last_resort_pre_key_store.id
            FROM
                devices 
                INNER JOIN aci_signed_pre_key_store ON aci_signed_pre_key_store.owner = devices.id
                INNER JOIN pni_signed_pre_key_store ON pni_signed_pre_key_store.owner = devices.id
                INNER JOIN aci_pq_last_resort_pre_key_store ON aci_pq_last_resort_pre_key_store.owner = devices.id
                INNER JOIN pni_pq_last_resort_pre_key_store ON pni_pq_last_resort_pre_key_store.owner = devices.id
            WHERE
                devices.owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR
                        pni = $1
                ) AND devices.device_id = $2
            "#,
            address.name(),
            address.device_id().to_string(),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await.map_err(|err| err.into())
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
                INNER JOIN aci_signed_pre_key_store ON aci_signed_pre_key_store.id = device_keys.aci_signed_pre_key
                INNER JOIN pni_signed_pre_key_store ON pni_signed_pre_key_store.id = device_keys.pni_signed_pre_key
                INNER JOIN aci_pq_last_resort_pre_key_store ON aci_pq_last_resort_pre_key_store.id = device_keys.aci_pq_last_resort_pre_key
                INNER JOIN pni_pq_last_resort_pre_key_store ON pni_pq_last_resort_pre_key_store.id = device_keys.pni_pq_last_resort_pre_key
                INNER JOIN devices ON devices.id = device_keys.owner
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
            address.device_id().to_string(),
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
        sqlx::query!(
            r#"
            SELECT
                COUNT(*) AS pre_key_count
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
            "#,
            service_id.service_id_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| row.pre_key_count.unwrap_or_default() as u32)
        .map_err(|err| err.into())
    }

    async fn get_one_time_pq_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        sqlx::query!(
            r#"
            SELECT
                COUNT(*) AS pre_key_count
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
            "#,
            service_id.service_id_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| row.pre_key_count.unwrap_or_default() as u32)
        .map_err(|err| err.into())
    }

    async fn store_one_time_ec_pre_keys(
        &self,
        otpks: Vec<UploadPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"
            DELETE FROM 
                one_time_ec_pre_key_store
            WHERE 
                owner = (
                    SELECT
                        id
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
                )
            "#,
            owner.name(),
            owner.device_id().to_string(),
        )
        .execute(&mut *tx)
        .await?;

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
            .execute(&mut *tx)
            .await
            {
                Ok(_) => (),
                Err(err) => bail!("{}", err),
            }
        }

        tx.commit().await?;

        Ok(())
    }

    async fn store_one_time_pq_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"
            DELETE FROM 
                one_time_pq_pre_key_store
            WHERE 
                owner = (
                    SELECT
                        id
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
                )
            "#,
            owner.name(),
            owner.device_id().to_string(),
        )
        .execute(&mut *tx)
        .await?;

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
                &*otpk.signature,
            )
            .execute(&mut *tx)
            .await
            {
                Ok(_) => (),
                Err(err) => bail!("{}", err),
            }
        }

        tx.commit().await?;

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

    async fn count_messages(&self, address: &ProtocolAddress) -> Result<u32> {
        let result = sqlx::query!(
            r#"
            SELECT
                COUNT(*)
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
        .fetch_one(&self.pool)
        .await?;

        Ok(result.count.unwrap_or_default() as u32)
    }

    async fn get_messages(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
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

    async fn delete_messages(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        sqlx::query!(
            r#"
            DELETE FROM
                msq_queue
            USING 
                devices
            WHERE 
                devices.id = msq_queue.receiver
            AND
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
                RETURNING msq_queue.msg
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
}

async fn store_aci_signed_pre_key(
    tx: &mut PgConnection,
    spk: &UploadSignedPreKey,
    address: &ProtocolAddress,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            aci_signed_pre_key_store (owner, key_id, public_key, signature)
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
            ) AND 
            device_id = $2
        ON CONFLICT (key_id, owner)
            DO UPDATE SET key_id = $3, public_key = $4, signature = $5;
        "#,
        address.name(),
        address.device_id().to_string(),
        spk.key_id.to_string(),
        &*spk.public_key,
        &*spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

async fn store_pni_signed_pre_key(
    tx: &mut PgConnection,
    spk: &UploadSignedPreKey,
    address: &ProtocolAddress,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            pni_signed_pre_key_store (owner, key_id, public_key, signature)
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
            ) AND 
            device_id = $2
        ON CONFLICT (key_id, owner)
            DO UPDATE SET key_id = $3, public_key = $4, signature = $5;
        "#,
        address.name(),
        address.device_id().to_string(),
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
    address: &ProtocolAddress,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            aci_pq_last_resort_pre_key_store (owner, key_id, public_key, signature)
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
            ) AND 
            device_id = $2
        ON CONFLICT (key_id, owner)
            DO UPDATE SET key_id = $3, public_key = $4, signature = $5;

        "#,
        address.name(),
        address.device_id().to_string(),
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
    address: &ProtocolAddress,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            pni_pq_last_resort_pre_key_store (owner, key_id, public_key, signature)
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
            ) AND 
            device_id = $2
        ON CONFLICT (key_id, owner)
            DO UPDATE SET key_id = $3, public_key = $4, signature = $5;

        "#,
        address.name(),
        address.device_id().to_string(),
        pq_spk.key_id.to_string(),
        &*pq_spk.public_key,
        &*pq_spk.signature
    )
    .execute(tx)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

#[cfg(test)]
mod db_tests {
    use anyhow::Result;
    use common::{
        signal_protobuf::Envelope,
        web_api::{
            AccountAttributes, DeviceCapabilities, DevicePreKeyBundle, UploadPreKey,
            UploadSignedPreKey,
        },
    };
    use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
    use libsignal_protocol::{IdentityKey, PublicKey};
    use uuid::Uuid;

    use crate::{
        account::{self, Account, Device},
        database::SignalDatabase,
        postgres::PostgresDatabase,
    };

    async fn connect() -> PostgresDatabase {
        PostgresDatabase::connect("DATABASE_URL_TEST".to_string()).await
    }

    #[tokio::test]
    async fn test_add_and_get_user() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob1_device".to_string(),
            0,
            0,
            "bob1_token".as_bytes().to_vec(),
            "bob1_salt".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number1".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );

        db.add_account(&account).await.unwrap();
        let retrieved_account = db
            .get_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(account, retrieved_account);
    }

    #[tokio::test]
    async fn test_update_account_aci() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device2".to_string(),
            0,
            0,
            "bob_token2".as_bytes().to_vec(),
            "bob_salt2".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number2".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let new_aci = Aci::from(Uuid::new_v4());

        db.add_account(&account).await.unwrap();
        db.update_account_aci(&ServiceId::Aci(account.aci()), new_aci)
            .await
            .unwrap();
        let retrieved_account = db.get_account(&ServiceId::Aci(new_aci)).await.unwrap();
        db.delete_account(&ServiceId::Aci(retrieved_account.aci()))
            .await
            .unwrap();

        assert_ne!(account.aci(), retrieved_account.aci());
        assert_eq!(retrieved_account.aci(), new_aci);
    }

    #[tokio::test]
    async fn test_update_account_pni() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device3".to_string(),
            0,
            0,
            "bob_token3".as_bytes().to_vec(),
            "bob_salt3".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number3".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let new_pni = Pni::from(Uuid::new_v4());

        db.add_account(&account).await.unwrap();
        db.update_account_pni(&ServiceId::Pni(account.pni()), new_pni)
            .await
            .unwrap();
        let retrieved_account = db.get_account(&ServiceId::Pni(new_pni)).await.unwrap();
        db.delete_account(&ServiceId::Pni(retrieved_account.pni()))
            .await
            .unwrap();

        assert_ne!(account.pni(), retrieved_account.pni());
        assert_eq!(retrieved_account.pni(), new_pni);
    }

    #[tokio::test]
    async fn test_delete_account() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device4".to_string(),
            0,
            0,
            "bob_token4".as_bytes().to_vec(),
            "bob_salt4".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number4".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );

        db.add_account(&account).await.unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();
        db.get_account(&ServiceId::Aci(account.aci()))
            .await
            .expect_err("The account should have been deleted");
    }

    #[tokio::test]
    async fn test_add_and_get_device() {
        let db = connect().await;
        let primary_device = Device::new(
            1.into(),
            "bob_device5".to_string(),
            0,
            0,
            "bob_token5".as_bytes().to_vec(),
            "bob_salt5".to_string(),
            0,
        );
        let secondary_device = Device::new(
            0.into(),
            "bob_secondary_device1".to_string(),
            0,
            0,
            "bob_secondary_token1".as_bytes().to_vec(),
            "bob_secondary_salt1".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            primary_device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number5".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );

        db.add_account(&account).await.unwrap();
        db.add_device(&ServiceId::Aci(account.aci()), &secondary_device)
            .await
            .unwrap();
        let retrieved_device = db
            .get_device(
                &ServiceId::Aci(account.aci()),
                secondary_device.device_id().into(),
            )
            .await
            .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap(); // secondary_device is also deleted due to cascading

        assert_eq!(secondary_device, retrieved_device);
    }

    #[tokio::test]
    async fn test_get_all_devices() {
        let db = connect().await;
        let primary_device = Device::new(
            1.into(),
            "bob_device6".to_string(),
            0,
            0,
            "bob_token6".as_bytes().to_vec(),
            "bob_salt6".to_string(),
            0,
        );
        let secondary_device = Device::new(
            0.into(),
            "bob_secondary_device2".to_string(),
            0,
            0,
            "bob_secondary_token2".as_bytes().to_vec(),
            "bob_secondary_salt2".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            primary_device.clone(),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number6".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );

        db.add_account(&account).await.unwrap();
        db.add_device(&ServiceId::Aci(account.aci()), &secondary_device)
            .await
            .unwrap();
        let retrieved_devices = db
            .get_all_devices(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(vec![primary_device, secondary_device], retrieved_devices);
    }

    #[tokio::test]
    async fn test_delete_device() {
        let db = connect().await;
        let primary_device = Device::new(
            1.into(),
            "bob_device7".to_string(),
            0,
            0,
            "bob_token7".as_bytes().to_vec(),
            "bob_salt7".to_string(),
            0,
        );
        let secondary_device = Device::new(
            0.into(),
            "bob_secondary_device3".to_string(),
            0,
            0,
            "bob_secondary_token3".as_bytes().to_vec(),
            "bob_secondary_salt3".to_string(),
            0,
        );
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            primary_device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number7".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );

        db.add_account(&account).await.unwrap();
        db.add_device(&ServiceId::Aci(account.aci()), &secondary_device)
            .await
            .unwrap();
        db.delete_device(
            &ServiceId::Aci(account.aci()),
            secondary_device.device_id().into(),
        )
        .await
        .unwrap();
        db.get_device(
            &ServiceId::Aci(account.aci()),
            secondary_device.device_id().into(),
        )
        .await
        .expect_err("This devices should have been deleted");
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_push_and_pop_message_queue() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device8".to_string(),
            0,
            0,
            "bob_token8".as_bytes().to_vec(),
            "bob_salt8".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number8".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let msg = Envelope {
            r#type: Some(0),
            source_service_id: Some(ServiceId::Aci(Aci::from(Uuid::new_v4())).service_id_string()),
            source_device: Some(1),
            client_timestamp: Some(0),
            content: Some(bincode::serialize("SECRET_TEXT").unwrap()),
            server_guid: Some("server_guid".to_string()),
            server_timestamp: Some(0),
            ephemeral: Some(false),
            destination_service_id: Some(account.aci().service_id_string()),
            urgent: Some(true),
            updated_pni: None,
            story: None,
            report_spam_token: None,
            shared_mrm_key: None,
        };
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.push_message_queue(&address, vec![msg.clone()])
            .await
            .unwrap();
        let retrieved_msg = db.pop_msg_queue(&address).await.unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(retrieved_msg.len(), 1);
        assert_eq!(msg, retrieved_msg[0]);
    }

    async fn get_aci_signed_pre_key(
        db: &PostgresDatabase,
        key_id: u32,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<UploadSignedPreKey> {
        sqlx::query!(
            r#"
            SELECT
                key_id, public_key, signature
            FROM
                aci_signed_pre_key_store
            WHERE
                key_id = $1 AND
                owner = (
                    SELECT
                        id
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
                        ) AND
                        device_id = $3
                )
            "#,
            key_id.to_string(),
            service_id.service_id_string(),
            device_id.to_string()
        )
        .fetch_one(&db.pool)
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.into(),
        })
        .map_err(|err| err.into())
    }

    #[tokio::test]
    async fn test_store_aci_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device9".to_string(),
            0,
            0,
            "bob_token9".as_bytes().to_vec(),
            "bob_salt9".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number9".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_aci_signed_pre_key(&key, &address).await.unwrap();
        let retrieved_key = get_aci_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    #[tokio::test]
    async fn test_update_aci_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device10".to_string(),
            0,
            0,
            "bob_token10".as_bytes().to_vec(),
            "bob_salt10".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number10".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let mut key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_aci_signed_pre_key(&key, &address).await.unwrap();
        key.public_key = Box::new([5, 6, 7, 8]);
        db.store_aci_signed_pre_key(&key, &address).await.unwrap();
        let retrieved_key = get_aci_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    async fn get_pni_signed_pre_key(
        db: &PostgresDatabase,
        key_id: u32,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<UploadSignedPreKey> {
        sqlx::query!(
            r#"
            SELECT
                key_id, public_key, signature
            FROM
                pni_signed_pre_key_store
            WHERE
                key_id = $1 AND
                owner = (
                    SELECT
                        id
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
                        ) AND
                        device_id = $3
                )
            "#,
            key_id.to_string(),
            service_id.service_id_string(),
            device_id.to_string()
        )
        .fetch_one(&db.pool)
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.into(),
        })
        .map_err(|err| err.into())
    }

    #[tokio::test]
    async fn test_store_pni_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device11".to_string(),
            0,
            0,
            "bob_token11".as_bytes().to_vec(),
            "bob_salt11".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number11".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pni_signed_pre_key(&key, &address).await.unwrap();
        let retrieved_key = get_pni_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    #[tokio::test]
    async fn test_update_pni_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device12".to_string(),
            0,
            0,
            "bob_token12".as_bytes().to_vec(),
            "bob_salt12".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number12".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let mut key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pni_signed_pre_key(&key, &address).await.unwrap();
        key.public_key = Box::new([5, 6, 7, 8]);
        db.store_pni_signed_pre_key(&key, &address).await.unwrap();
        let retrieved_key = get_pni_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    async fn get_pq_aci_signed_pre_key(
        db: &PostgresDatabase,
        key_id: u32,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<UploadSignedPreKey> {
        sqlx::query!(
            r#"
            SELECT
                key_id, public_key, signature
            FROM
                aci_pq_last_resort_pre_key_store
            WHERE
                key_id = $1 AND
                owner = (
                    SELECT
                        id
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
                        ) AND
                        device_id = $3
                )
            "#,
            key_id.to_string(),
            service_id.service_id_string(),
            device_id.to_string()
        )
        .fetch_one(db.pool())
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.into(),
        })
        .map_err(|err| err.into())
    }

    #[tokio::test]
    async fn test_store_pq_aci_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device13".to_string(),
            0,
            0,
            "bob_token13".as_bytes().to_vec(),
            "bob_salt13".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number13".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pq_aci_signed_pre_key(&key, &address)
            .await
            .unwrap();
        let retrieved_key = get_pq_aci_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    #[tokio::test]
    async fn test_update_pq_aci_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device14".to_string(),
            0,
            0,
            "bob_token14".as_bytes().to_vec(),
            "bob_salt14".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number14".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let mut key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pq_aci_signed_pre_key(&key, &address)
            .await
            .unwrap();
        key.public_key = Box::new([5, 6, 7, 8]);
        db.store_pq_aci_signed_pre_key(&key, &address)
            .await
            .unwrap();
        let retrieved_key = get_pq_aci_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    async fn get_pq_pni_signed_pre_key(
        db: &PostgresDatabase,
        key_id: u32,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<UploadSignedPreKey> {
        sqlx::query!(
            r#"
            SELECT
                key_id, public_key, signature
            FROM
                pni_pq_last_resort_pre_key_store
            WHERE
                key_id = $1 AND
                owner = (
                    SELECT
                        id
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
                        ) AND
                        device_id = $3
                )
            "#,
            key_id.to_string(),
            service_id.service_id_string(),
            device_id.to_string()
        )
        .fetch_one(&db.pool)
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.into(),
        })
        .map_err(|err| err.into())
    }

    #[tokio::test]
    async fn test_store_pq_pni_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device15".to_string(),
            0,
            0,
            "bob_token15".as_bytes().to_vec(),
            "bob_salt15".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number15".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pq_pni_signed_pre_key(&key, &address)
            .await
            .unwrap();
        let retrieved_key = get_pq_pni_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    #[tokio::test]
    async fn test_update_pq_pni_signed_pre_key() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device16".to_string(),
            0,
            0,
            "bob_token16".as_bytes().to_vec(),
            "bob_salt16".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number16".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);
        let mut key = UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        };

        db.add_account(&account).await.unwrap();
        db.store_pq_pni_signed_pre_key(&key, &address)
            .await
            .unwrap();
        key.public_key = Box::new([5, 6, 7, 8]);
        db.store_pq_pni_signed_pre_key(&key, &address)
            .await
            .unwrap();
        let retrieved_key = get_pq_pni_signed_pre_key(
            &db,
            key.key_id,
            &ServiceId::Aci(account.aci()),
            device_id.into(),
        )
        .await
        .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key, retrieved_key);
    }

    #[tokio::test]
    async fn test_store_and_get_key_bundle() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device17".to_string(),
            0,
            0,
            "bob_token17".as_bytes().to_vec(),
            "bob_salt17".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number17".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let key_bundle = DevicePreKeyBundle {
            aci_signed_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            pni_signed_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            aci_pq_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            pni_pq_pre_key: UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
        };
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.store_key_bundle(&key_bundle, &address).await.unwrap();
        let retrieved_key_bundle = db.get_key_bundle(&address).await.unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(key_bundle, retrieved_key_bundle);
    }

    #[tokio::test]
    async fn test_get_one_time_ec_pre_key_count() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device18".to_string(),
            0,
            0,
            "bob_token18".as_bytes().to_vec(),
            "bob_salt18".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number18".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let otpks = vec![
            UploadPreKey {
                key_id: 0,
                public_key: Box::new([1, 2, 3, 4]),
            },
            UploadPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
            },
            UploadPreKey {
                key_id: 2,
                public_key: Box::new([1, 2, 3, 4]),
            },
            UploadPreKey {
                key_id: 3,
                public_key: Box::new([1, 2, 3, 4]),
            },
        ];
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.store_one_time_ec_pre_keys(otpks.clone(), &address)
            .await
            .unwrap();
        let count = db
            .get_one_time_ec_pre_key_count(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(count, otpks.len() as u32);
    }

    #[tokio::test]
    async fn test_get_one_time_pq_pre_key_count() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device19".to_string(),
            0,
            0,
            "bob_token19".as_bytes().to_vec(),
            "bob_salt19".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number19".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let otpks = vec![
            UploadSignedPreKey {
                key_id: 0,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            UploadSignedPreKey {
                key_id: 1,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            UploadSignedPreKey {
                key_id: 2,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
            UploadSignedPreKey {
                key_id: 3,
                public_key: Box::new([1, 2, 3, 4]),
                signature: Box::new([1, 2, 3, 4]),
            },
        ];
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.store_one_time_pq_pre_keys(otpks.clone(), &address)
            .await
            .unwrap();
        let count = db
            .get_one_time_pq_pre_key_count(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(count, otpks.len() as u32);
    }

    #[tokio::test]
    async fn test_store_and_get_one_time_ec_pre_keys() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device20".to_string(),
            0,
            0,
            "bob_token20".as_bytes().to_vec(),
            "bob_salt20".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number20".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let otpks = vec![UploadPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
        }];
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.store_one_time_ec_pre_keys(otpks.clone(), &address)
            .await
            .unwrap();
        let retrieved_key = db.get_one_time_ec_pre_key(&address).await.unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(otpks, vec![retrieved_key])
    }

    #[tokio::test]
    async fn test_store_one_time_pq_pre_keys() {
        let db = connect().await;
        let device = Device::new(
            0.into(),
            "bob_device21".to_string(),
            0,
            0,
            "bob_token21".as_bytes().to_vec(),
            "bob_salt21".to_string(),
            0,
        );
        let device_id = device.device_id();
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            device,
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap()),
            "test_number21".to_string(),
            AccountAttributes {
                fetches_messages: true,
                registration_id: 0,
                pni_registration_id: 0,
                capabilities: DeviceCapabilities {
                    storage: true,
                    transfer: true,
                    payment_activation: true,
                    delete_sync: true,
                    versioned_expiration_timer: true,
                },
                unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
            },
        );
        let otpks = vec![UploadSignedPreKey {
            key_id: 0,
            public_key: Box::new([1, 2, 3, 4]),
            signature: Box::new([1, 2, 3, 4]),
        }];
        let address = ProtocolAddress::new(account.aci().service_id_string(), device_id);

        db.add_account(&account).await.unwrap();
        db.store_one_time_pq_pre_keys(otpks.clone(), &address)
            .await
            .unwrap();
        let retrieved_key = db.get_one_time_pq_pre_key(&address).await.unwrap();
        db.delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(otpks, vec![retrieved_key])
    }
}
