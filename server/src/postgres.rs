use crate::{database::SignalDatabase, account::Account};
use anyhow::{anyhow, bail, Result};
use axum::{async_trait, extract};
use common::{
    signal_protobuf::Envelope,
    web_api::{Device, DevicePreKeyBundle, UploadSignedPreKey},
};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::{IdentityKey, PublicKey};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

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
                accounts (aci, pni, auth_token, identity_key)
            VALUES
                ($1, $2, $3, $4)
            "#,
            account.aci,
            account.pni,
            account.auth_token,
            &*account.identity_key.serialize()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        let (aci, pni) = parse_service_id(service_id);
        
        sqlx::query!(
            r#"
            SELECT 
                aci, pni, auth_token, identity_key
            FROM
                accounts
            WHERE
                COALESCE(aci, '') = COALESCE($1, '')
                OR COALESCE(pni, '') = COALESCE($2, '')
            "#,
            aci,
            pni,
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| Account {
            aci: row.aci,
            pni: row.pni,
            auth_token: row.auth_token,
            identity_key: IdentityKey::new(
                PublicKey::deserialize(row.identity_key.as_slice()).unwrap(),
            ),
        })
        .map_err(|err| err.into())
    }

    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        let (id_str, id) = pasrse_to_specific_service_id(service_id);

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
            Some(new_aci.service_id_string())
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        let (id_str, id) = pasrse_to_specific_service_id(service_id);

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
            Some(new_pni.service_id_string())
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        let (id_str, id) = pasrse_to_specific_service_id(service_id);

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

    async fn push_msg_queue(&self, address: ProtocolAddress, msgs: Vec<&Envelope>) -> Result<()> {
        for msg in msgs {
            let data = bincode::serialize(msg)?;
            let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&address)?;

            sqlx::query!(
                r#"
                INSERT INTO
                    msq_queue (a_receiver, d_receiver, msg)
                SELECT
                   id, $1, $2
                FROM
                    accounts
                WHERE
                    $3 = $4
                "#,
                address.device_id().to_string(),
                data,
                id_str,
                id
            )
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|err| anyhow!("{}", err))?;
        }
        Ok(())
    }

    async fn pop_msg_queue(&self, address: ProtocolAddress) -> Result<Vec<Envelope>> {
        let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&address)?;

        sqlx::query!(
            r#"
            SELECT
                msg
            FROM
                msq_queue
            WHERE
                a_receiver = (
                    SELECT
                        id
                    FROM
                        accounts
                    WHERE
                        $1 = $2
                )
                AND d_receiver = $3
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

    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        address: ProtocolAddress,
    ) -> Result<()> {
        let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&address)?;
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            r#"
            INSERT INTO
                aci_signed_pre_key_store (key_id, public_key, signature)
            VALUES
                ($1, $2, $3)
            "#,
            data.aci_signed_pre_key.key_id.to_string(),
            &*data.aci_signed_pre_key.public_key,
            &*data.aci_signed_pre_key.signature
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO
                pni_signed_pre_key_store (key_id, public_key, signature)
            VALUES
                ($1, $2, $3)
            "#,
            data.pni_signed_pre_key.key_id.to_string(),
            &*data.pni_signed_pre_key.public_key,
            &*data.pni_signed_pre_key.signature
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO
                aci_pq_last_resort_pre_key_store (key_id, public_key, signature)
            VALUES
                ($1, $2, $3)
            "#,
            data.aci_pq_last_resort_pre_key.key_id.to_string(),
            &*data.aci_pq_last_resort_pre_key.public_key,
            &*data.aci_pq_last_resort_pre_key.signature
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO
                pni_pq_last_resort_pre_key_store (key_id, public_key, signature)
            VALUES
                ($1, $2, $3)
            "#,
            data.pni_pq_last_resort_pre_key.key_id.to_string(),
            &*data.pni_pq_last_resort_pre_key.public_key,
            &*data.pni_pq_last_resort_pre_key.signature
        )
        .execute(&mut *tx)
        .await?;

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
            data.aci_signed_pre_key.key_id.to_string(),
            data.pni_signed_pre_key.key_id.to_string(),
            data.aci_pq_last_resort_pre_key.key_id.to_string(),
            data.pni_pq_last_resort_pre_key.key_id.to_string()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await.map(|_| ()).map_err(|err| err.into())
    }

    async fn get_key_bundle(&self, address: ProtocolAddress) -> Result<DevicePreKeyBundle> {
        let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&address)?;

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
            aci_pq_last_resort_pre_key: UploadSignedPreKey {
                key_id: row.apqlrpk_id.parse().unwrap(),
                public_key: row.apqlrpk.into(),
                signature: row.apqlrpk_sig.into()
            },
            pni_pq_last_resort_pre_key: UploadSignedPreKey {
                key_id: row.ppqlrpk_id.parse().unwrap(),
                public_key: row.ppqlrpk.into(),
                signature: row.ppqlrpk_sig.into()
            }
        }
    })
    .map_err(|err| err.into())
    }

    async fn get_one_time_pre_key_count(&self, account: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: ProtocolAddress,
    ) -> Result<()> {
        let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&owner)?;

        for otpk in otpks {
            match sqlx::query!(
                r#"
                INSERT INTO
                    one_time_pre_key_store (a_owner, d_owner, key_id, public_key, signature)
                SELECT
                    id, $3, $4, $5, $6
                FROM
                    accounts
                WHERE
                    $1 = $2
                "#,
                id_str,
                id,
                owner.name().to_string(),
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

    async fn get_one_time_pre_key(
        &self,
        owner: ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        let (id_str, id) = pasrse_to_specific_service_id_from_protocol_address(&owner)?;

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
                        INNER JOIN accounts ON accounts.id = one_time_pre_key_store.a_owner
                    WHERE
                        $1 = $2
                        AND one_time_pre_key_store.d_owner = $3
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
            "accounts.".to_string() + &id_str,
            id,
            owner.device_id().to_string()
        )
        .fetch_one(&self.pool)
        .await
        .map(|row| UploadSignedPreKey {
            key_id: row.key_id.parse().unwrap(),
            public_key: row.public_key.into(),
            signature: row.signature.into(),
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

fn pasrse_to_specific_service_id(service_id: &ServiceId) -> (String, String) {
    match parse_service_id(service_id) {
        (None, Some(id)) => ("pni".into(), id),
        (Some(id), None) => ("aci".into(), id),
        _ => panic!("NOT POSSINLBE!")
    }
}

fn pasrse_to_specific_service_id_from_protocol_address(protocol_address: &ProtocolAddress) -> Result<(String, String)> {
    Ok(pasrse_to_specific_service_id(&ServiceId::parse_from_service_id_string(protocol_address.name()).ok_or(anyhow!("Could not parse protocal address name to service id"))?))
}