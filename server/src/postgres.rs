use core::str;
use std::option;

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
    async fn add_account(&self, account: Account) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO
                accounts (aci, pni, aci_identity_key, pni_identity_key)
            VALUES
                ($1, $2, $3, $4)
            "#,
            account.aci().service_id_string(),
            account.pni().service_id_string(),
            &*account.aci_identity_key().serialize(),
            &*account.pni_identity_key().serialize()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        let (id_str, id) = parse_to_specific_service_id(service_id);
        let devices = self.get_all_devices(service_id).await?;

        sqlx::query!(
            r#"
            SELECT 
                aci, pni, aci_identity_key, pni_identity_key
            FROM
                accounts
            WHERE
                aci = $1 OR pni = $1
            "#,
            id,
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
            )
        })
        .map_err(|err| err.into())
    }

    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            UPDATE
                accounts
            SET
                aci = $3
            WHERE
                $1 = $2
            "#,
            id_str,
            id,
            new_aci.service_id_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            UPDATE
                accounts
            SET
                pni = $3
            WHERE
                $1 = $2
            "#,
            id_str,
            id,
            new_pni.service_id_string()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            DELETE FROM
                accounts
            WHERE
                $1 = $2
            "#,
            id_str,
            id
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn add_device(&self, service_id: &ServiceId, device: Device) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            INSERT INTO
                devices (owner, device_id, name, auth_token, salt)
            SELECT
                id, $3, $4, $5, $6
            FROM
                accounts
            WHERE
                $1 = $2
            "#,
            id_str,
            id,
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
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            SELECT
                device_id, name, auth_token, salt 
            FROM
                devices
            WHERE
                owner in (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        aci = $1 OR pni = $1
                )
            "#,
            id
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    Device::new(
                        row.device_id.parse::<u32>().unwrap().into(),
                        str::from_utf8(&row.name).unwrap().to_string(),
                        0,
                        0,
                        row.auth_token,
                        row.salt,
                    )
                })
                .collect()
        })
        .map_err(|err| err.into())
    }

    async fn get_device(&self, service_id: &ServiceId, device_id: u32) -> Result<Device> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

        sqlx::query!(
            r#"
            SELECT
                device_id, name, auth_token, salt 
            FROM
                devices
            WHERE
                owner = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        $1 = $2
                )
                AND device_id = $3
            "#,
            id_str,
            id,
            device_id.to_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| {
            Device::new(
                row.device_id.parse::<u32>().unwrap().into(),
                str::from_utf8(&row.name).unwrap().to_string(),
                0,
                0,
                row.auth_token,
                row.salt,
            )
        })
        .map_err(|err| err.into())
    }

    async fn delete_device(&self, service_id: &ServiceId, device_id: u32) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id(service_id);

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
                        $1 = $2
                )
                AND device_id = $3
            "#,
            id_str,
            id,
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
            let (id_str, id) = parse_to_specific_service_id_from_protocol_address(&address)?;

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
                            $2 = $3
                    )
                    AND device_id = $4
                "#,
                data,
                id_str,
                id,
                address.device_id().to_string()
            )
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|err| anyhow!("{}", err))?;
        }
        Ok(())
    }

    async fn pop_msg_queue(&self, address: ProtocolAddress) -> Result<Vec<Envelope>> {
        let (id_str, id) = parse_to_specific_service_id_from_protocol_address(&address)?;

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
                        $1 = $2
                )
                AND devices.device_id = $3
            "#,
            id_str,
            id,
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
        data: DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id_from_protocol_address(address)?;
        let mut tx = self.pool.begin().await?;
        let aspk = data.aci_signed_pre_key;
        let pspk = data.pni_signed_pre_key;
        let apqlrpk = data.aci_pq_pre_key;
        let ppqlrpk = data.pni_pq_pre_key;

        store_aci_signed_pre_key(&mut tx, &aspk).await?;
        store_pni_signed_pre_key(&mut tx, &pspk).await?;
        store_pq_aci_signed_pre_key(&mut tx, &apqlrpk).await?;
        store_pq_pni_signed_pre_key(&mut tx, &ppqlrpk).await?;

        sqlx::query!(
            r#"
            INSERT INTO
                device_keys (owner, aci_signed_pre_key, pni_signed_pre_key, aci_pq_last_resort_pre_key, pni_pq_last_resort_pre_key)
            SELECT
                id, $3, $4, $5, $6
            FROM
                accounts
            WHERE
                $1 = $2
            "#,
            id_str,
            id,
            aspk.key_id.to_string(),
            pspk.key_id.to_string(),
            apqlrpk.key_id.to_string(),
            ppqlrpk.key_id.to_string()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await.map(|_| ()).map_err(|err| err.into())
    }

    async fn get_key_bundle(&self, address: &ProtocolAddress) -> Result<DevicePreKeyBundle> {
        let (id_str, id) = parse_to_specific_service_id_from_protocol_address(address)?;

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
            $1 = $2
        "#,
        id_str,
        id
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

    async fn get_one_time_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadPreKey>,
        owner: ProtocolAddress,
    ) -> Result<()> {
        let (id_str, id) = parse_to_specific_service_id_from_protocol_address(&owner)?;

        for otpk in otpks {
            match sqlx::query!(
                r#"
                INSERT INTO
                    one_time_pre_key_store (owner, key_id, public_key)
                SELECT
                    id, $4, $5
                FROM
                    devices
                WHERE
                    owner = (
                        SELECT
                            id
                        FROM
                            accounts
                        WHERE
                            $1 = $2
                    )
                    AND devices.device_id = $3
                "#,
                id_str,
                id,
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

    async fn get_one_time_pre_key(&self, owner: &ProtocolAddress) -> Result<UploadPreKey> {
        let (id_str, id) = parse_to_specific_service_id_from_protocol_address(owner)?;

        sqlx::query!(
            r#"
            WITH key AS (
                DELETE FROM
                    one_time_pre_key_store
                WHERE id IN (
                    SELECT
                        one_time_pre_key_store.id
                    FROM
                        one_time_pre_key_store
                        INNER JOIN devices on devices.id = one_time_pre_key_store.owner
                    WHERE
                        devices.owner = (
                            SELECT
                                id
                            FROM
                                accounts
                            WHERE
                                $1 = $2
                        )
                        AND devices.device_id = $3
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
            "accounts.".to_string() + &id_str,
            id,
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
}

fn parse_service_id(service_id: &ServiceId) -> (Option<String>, Option<String>) {
    match service_id {
        ServiceId::Aci(_) => (Some(service_id.service_id_string()), None),
        ServiceId::Pni(_) => (None, Some(service_id.service_id_string())),
    }
}

fn parse_to_specific_service_id(service_id: &ServiceId) -> (String, String) {
    match parse_service_id(service_id) {
        (None, Some(id)) => ("pni".into(), id),
        (Some(id), None) => ("aci".into(), id),
        _ => panic!("NOT POSSIBLE!"),
    }
}

fn parse_to_specific_service_id_from_protocol_address(
    protocol_address: &ProtocolAddress,
) -> Result<(String, String)> {
    Ok(parse_to_specific_service_id(
        &ServiceId::parse_from_service_id_string(protocol_address.name()).ok_or(anyhow!(
            "Could not parse protocol address name to service id"
        ))?,
    ))
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
