use crate::server::ServerState;
use anyhow::{bail, Result};
use axum::extract::State;
use common::{
    signal_protobuf::Envelope,
    web_api::Account,
    web_api::{Device, DevicePreKeyBundle, UploadSignedPreKey},
};

pub async fn add_account(State(state): State<ServerState>, account: Account) -> Result<()> {
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
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn get_account(
    State(state): State<ServerState>,
    aci: Option<String>,
    pni: Option<String>,
) -> Result<Account> {
    sqlx::query!(
        r#"
        SELECT 
            aci, pni, auth_token, identity_key
        FROM
            accounts
        WHERE
            aci = $1
            AND pni = $2
        "#,
        aci,
        pni
    )
    .fetch_one(&state.pool)
    .await
    .map(|row| Account {
        aci: row.aci,
        pni: row.pni,
        auth_token: row.auth_token,
        identity_key: row.identity_key.as_slice().try_into().unwrap(),
    })
    .map_err(|err| err.into())
}

pub async fn update_account_aci(
    State(state): State<ServerState>,
    old_aci: Option<String>,
    new_aci: Option<String>,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE
            accounts
        SET
            aci = $2
        WHERE
            aci = $1
        "#,
        old_aci,
        new_aci
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn update_account_pni(
    State(state): State<ServerState>,
    old_pni: Option<String>,
    new_pni: Option<String>,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE
            accounts
        SET
            pni = $2
        WHERE
            pni = $1
        "#,
        old_pni,
        new_pni
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn delete_account(
    State(state): State<ServerState>,
    aci: Option<String>,
    pni: Option<String>,
) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM
            accounts
        WHERE
            aci = $1
            AND pni = $2
        "#,
        aci,
        pni
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn add_device(
    State(state): State<ServerState>,
    owner: &Account,
    device: Device,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            devices (device_id, owner)
        SELECT
            $3, id
        FROM
            accounts
        WHERE
            aci = $1
            AND pni = $2
        "#,
        owner.aci,
        owner.pni,
        device.device_id.to_string()
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn get_device(
    State(state): State<ServerState>,
    owner: &Account,
    device_id: u32,
) -> Result<Device> {
    sqlx::query!(
        r#"
        SELECT
            device_id
        FROM
            devices
        WHERE
            owner = (
                SELECT
                    id
                FROM
                    accounts
                WHERE
                    aci = $1
                    AND pni = $2
            )
            AND device_id = $3
        "#,
        owner.aci,
        owner.pni,
        device_id.to_string()
    )
    .fetch_one(&state.pool)
    .await
    .map(|row| Device {
        device_id: row.device_id.parse().unwrap(),
        name: "".to_string(),
        last_seen: 0,
        created: 0,
    })
    .map_err(|err| err.into())
}

pub async fn get_devices(State(state): State<ServerState>, owner: &Account) -> Result<Vec<Device>> {
    sqlx::query!(
        r#"
        SELECT
            device_id, owner
        FROM
            devices
        WHERE
            owner = (
                SELECT
                    id
                FROM
                    accounts
                WHERE
                    aci = $1
                    AND pni = $2
            )
        "#,
        owner.aci,
        owner.pni
    )
    .fetch_all(&state.pool)
    .await
    .map(|rows| {
        rows.iter()
            .map(|row| Device {
                device_id: row.device_id.parse().unwrap(),
                name: row.owner.to_string(),
                last_seen: 0,
                created: 0,
            })
            .collect()
    })
    .map_err(|err| err.into())
}

pub async fn delete_device(
    State(state): State<ServerState>,
    owner: &Account,
    device_id: u32,
) -> Result<()> {
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
                    aci = $1
                    AND pni = $2
            )
            AND device_id = $3
        "#,
        owner.aci,
        owner.pni,
        device_id.to_string()
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn push_msg_queue(
    State(state): State<ServerState>,
    d_receiver: &Device,
    a_receiver: &Account,
    msg: &Envelope,
) -> Result<()> {
    let data = bincode::serialize(msg)?;

    sqlx::query!(
        r#"
        INSERT INTO
            msq_queue (a_receiver, d_receiver, msg)
        SELECT
           owner, id, $4
        FROM
            devices
        WHERE
            device_id = $1
            AND owner = (
                SELECT
                    id
                FROM
                    accounts
                WHERE
                    aci = $2
                    AND pni = $3
            )
        "#,
        d_receiver.device_id.to_string(),
        a_receiver.aci,
        a_receiver.pni,
        data
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn pop_msg_queue(
    State(state): State<ServerState>,
    d_receiever: &Device,
    a_receiver: &Account,
) -> Result<Vec<Envelope>> {
    sqlx::query!(
        r#"
        SELECT
            msg
        FROM
            msq_queue
            INNER JOIN devices on devices.id = msq_queue.d_receiver
        WHERE
            msq_queue.a_receiver = (
                SELECT
                    id
                FROM
                    accounts
                WHERE
                    aci = $1
                    AND pni = $2
            )
            AND devices.device_id = $3
        "#,
        a_receiver.aci,
        a_receiver.pni,
        d_receiever.device_id.to_string()
    )
    .fetch_all(&state.pool)
    .await?
    .iter()
    .try_fold(vec![], |mut acc, msg| -> Result<Vec<Envelope>> {
        acc.push(bincode::deserialize(&msg.msg)?);
        Ok(acc)
    })
}

pub async fn store_key_bundle(
    State(state): State<ServerState>,
    data: DevicePreKeyBundle,
    owner: &Device,
    account: &Account,
) -> Result<()> {
    let mut tx = state.pool.begin().await?;

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
            aci = $1
            AND pni = $2
        "#,
        account.aci,
        account.pni,
        data.aci_signed_pre_key.key_id.to_string(),
        data.pni_signed_pre_key.key_id.to_string(),
        data.aci_pq_last_resort_pre_key.key_id.to_string(),
        data.pni_pq_last_resort_pre_key.key_id.to_string()
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await.map(|_| ()).map_err(|err| err.into())
}

pub async fn get_key_bundle(
    State(state): State<ServerState>,
    d_owner: &Device,
    a_owner: &Account,
) -> Result<DevicePreKeyBundle> {
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
            INNER JOIN devices ON devices.id = device_keys.owner
        WHERE
            devices.owner = (
                SELECT
                    id
                FROM
                    accounts
                WHERE
                    aci = $1
                    AND pni = $2
            )
            AND devices.device_id = $3
        "#,
        a_owner.aci,
        a_owner.pni,
        d_owner.device_id.to_string()
    )
    .fetch_one(&state.pool)
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

pub async fn store_one_time_pre_keys(
    State(state): State<ServerState>,
    otpks: Vec<UploadSignedPreKey>,
    d_owner: &Device,
    a_owner: &Account,
) -> Result<()> {
    for otpk in otpks {
        match sqlx::query!(
            r#"
                INSERT INTO
                    one_time_pre_key_store (owner, key_id, public_key, signature)
                SELECT
                    devices.id, $4, $5, $6
                FROM
                    devices
                    INNER JOIN accounts ON accounts.id = devices.owner
                WHERE
                    accounts.aci = $1
                    AND accounts.pni = $2
                    AND devices.device_id = $3
                "#,
            a_owner.aci,
            a_owner.pni,
            d_owner.device_id.to_string(),
            otpk.key_id.to_string(),
            &*otpk.public_key,
            &*otpk.signature
        )
        .execute(&state.pool)
        .await
        {
            Ok(_) => (),
            Err(err) => bail!("{}", err),
        }
    }

    Ok(())
}

pub async fn get_one_time_pre_key(
    State(state): State<ServerState>,
    d_owner: &Device,
    a_owner: &Account,
) -> Result<UploadSignedPreKey> {
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
                    INNER JOIN devices ON devices.id = one_time_pre_key_store.owner
                    INNER JOIN accounts ON accounts.id = devices.owner
                WHERE
                    accounts.aci = $1
                    AND accounts.pni = $2
                    AND devices.device_id= $3
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
        a_owner.aci,
        a_owner.pni,
        d_owner.device_id.to_string()
    )
    .fetch_one(&state.pool)
    .await
    .map(|row| UploadSignedPreKey {
        key_id: row.key_id.parse().unwrap(),
        public_key: row.public_key.into(),
        signature: row.signature.into(),
    })
    .map_err(|err| err.into())
}
