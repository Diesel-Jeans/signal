use crate::server::ServerState;
use anyhow::{bail, Result};
use axum::extract::State;
use common::{
    device::Device,
    key_bundle::{PreKey, PreKeyBundle},
    signal_protobuf::Envelope,
    user::User,
};

pub async fn add_user(
    State(state): State<ServerState>,
    username: &str,
    password: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            users (username, password)
        VALUES
            ($1, $2)
        "#,
        username,
        password
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn get_user(State(state): State<ServerState>, username: &str) -> Result<User> {
    sqlx::query_as!(
        User,
        r#"
        SELECT 
            id, username, password
        FROM
            users
        WHERE
            username = $1
        "#,
        username
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|err| err.into())
}

pub async fn update_user_username(
    State(state): State<ServerState>,
    old_username: &str,
    new_username: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE
            users
        SET
            username = $2
        WHERE
            username = $1
        "#,
        old_username,
        new_username
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn update_user_password(
    State(state): State<ServerState>,
    username: &str,
    new_password: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE
            users
        SET
            password = $2
        WHERE
            username = $1
        "#,
        username,
        new_password
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn delete_user(State(state): State<ServerState>, username: &str) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM
            users
        WHERE
            username = $1
        "#,
        username
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn add_device(State(state): State<ServerState>, owner: &User) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO
            devices (owner)
        VALUES
            ($1)
        "#,
        owner.id
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn get_devices(State(state): State<ServerState>, owner: &User) -> Result<Vec<Device>> {
    sqlx::query_as!(
        Device,
        r#"
        SELECT
            id, owner
        FROM
            devices
        WHERE
            owner = $1
        "#,
        owner.id
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|err| err.into())
}

pub async fn delete_device(State(state): State<ServerState>, owner: &User, id: i32) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM
            devices
        WHERE
            owner = $1
            AND id = $2
        "#,
        owner.id,
        id
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn push_msg_queue(
    State(state): State<ServerState>,
    reciver: &Device,
    msg: &Envelope,
) -> Result<()> {
    let data = bincode::serialize(msg)?;

    sqlx::query!(
        r#"
        INSERT INTO
            msq_queue (reciver, msg)
        VALUES
            ($1, $2)
        "#,
        reciver.id,
        data
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn pop_msg_queue(
    State(state): State<ServerState>,
    reciver: &Device,
) -> Result<Vec<Envelope>> {
    sqlx::query!(
        r#"
        SELECT
            msg
        FROM
            msq_queue
        WHERE
            reciver = $1
        "#,
        reciver.id
    )
    .fetch_all(&state.pool)
    .await?
    .iter()
    .try_fold(vec![], |mut acc, msg| -> Result<Vec<Envelope>> {
        acc.push(bincode::deserialize(&msg.msg)?);
        Ok(acc)
    })
}

pub async fn store_key_bundle(State(state): State<ServerState>, json: &str) -> Result<()> {
    let data: PreKeyBundle = serde_json::from_str(json)?;
    let mut tx = state.pool.begin().await?;

    match sqlx::query!(
        r#"
        INSERT INTO
            aci_signed_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        "#,
        data.aci_signed_pre_key.key_id,
        data.aci_signed_pre_key.public_key,
        data.aci_signed_pre_key.signature
    )
    .execute(&mut *tx)
    .await
    {
        Ok(_) => (),
        Err(err) => bail!(err),
    };

    match sqlx::query!(
        r#"
        INSERT INTO
            pni_signed_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        "#,
        data.pni_signed_pre_key.key_id,
        data.pni_signed_pre_key.public_key,
        data.pni_signed_pre_key.signature
    )
    .execute(&mut *tx)
    .await
    {
        Ok(_) => (),
        Err(err) => bail!(err),
    };

    match sqlx::query!(
        r#"
        INSERT INTO
            aci_pq_last_resort_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        "#,
        data.aci_pq_last_resort_pre_key.key_id,
        data.aci_pq_last_resort_pre_key.public_key,
        data.aci_pq_last_resort_pre_key.signature
    )
    .execute(&mut *tx)
    .await
    {
        Ok(_) => (),
        Err(err) => bail!(err),
    };

    match sqlx::query!(
        r#"
        INSERT INTO
            pni_pq_last_resort_pre_key_store (key_id, public_key, signature)
        VALUES
            ($1, $2, $3)
        "#,
        data.pni_pq_last_resort_pre_key.key_id,
        data.pni_pq_last_resort_pre_key.public_key,
        data.pni_pq_last_resort_pre_key.signature
    )
    .execute(&mut *tx)
    .await
    {
        Ok(_) => (),
        Err(err) => bail!(err),
    };

    tx.commit().await.map(|_| ()).map_err(|err| err.into())
}

pub async fn get_key_bundle(
    State(state): State<ServerState>,
    owner: &Device,
) -> Result<PreKeyBundle> {
    let aspk = sqlx::query_as!(
        PreKey,
        r#"
        SELECT
            aci_signed_pre_key_store.key_id,
            aci_signed_pre_key_store.public_key,
            aci_signed_pre_key_store.signature
        FROM
            device_keys INNER JOIN aci_signed_pre_key_store ON aci_signed_pre_key_store.id = device_keys.aci_signed_pre_key
        WHERE
            device_keys.owner = $1
        "#,
        owner.id)
    .fetch_one(&state.pool)
    .await?;

    let pspk = sqlx::query_as!(
        PreKey,
        r#"
        SELECT
            pni_signed_pre_key_store.key_id,
            pni_signed_pre_key_store.public_key,
            pni_signed_pre_key_store.signature
        FROM
            device_keys INNER JOIN pni_signed_pre_key_store ON pni_signed_pre_key_store.id = device_keys.pni_signed_pre_key
        WHERE
            device_keys.owner = $1
        "#,
        owner.id)
    .fetch_one(&state.pool)
    .await?;

    let apqlrpk = sqlx::query_as!(
        PreKey,
        r#"
        SELECT
            aci_pq_last_resort_pre_key_store.key_id,
            aci_pq_last_resort_pre_key_store.public_key,
            aci_pq_last_resort_pre_key_store.signature
        FROM
            device_keys INNER JOIN aci_pq_last_resort_pre_key_store ON aci_pq_last_resort_pre_key_store.id = device_keys.aci_pq_last_resort_pre_key
        WHERE
            device_keys.owner = $1
        "#,
        owner.id)
    .fetch_one(&state.pool)
    .await?;

    let ppqlrpk = sqlx::query_as!(
        PreKey,
        r#"
        SELECT
            pni_pq_last_resort_pre_key_store.key_id,
            pni_pq_last_resort_pre_key_store.public_key,
            pni_pq_last_resort_pre_key_store.signature
        FROM
            device_keys INNER JOIN pni_pq_last_resort_pre_key_store ON pni_pq_last_resort_pre_key_store.id = device_keys.pni_pq_last_resort_pre_key
        WHERE
            device_keys.owner = $1
        "#,
        owner.id)
    .fetch_one(&state.pool)
    .await?;

    Ok(PreKeyBundle {
        aci_signed_pre_key: aspk,
        pni_signed_pre_key: pspk,
        aci_pq_last_resort_pre_key: apqlrpk,
        pni_pq_last_resort_pre_key: ppqlrpk,
    })
}

pub async fn store_one_time_pre_keys(State(state): State<ServerState>) {}

pub async fn get_one_time_pre_key(State(state): State<ServerState>) {}
