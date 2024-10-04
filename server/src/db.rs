use crate::server::ServerState;
use anyhow::Result;
use axum::extract::State;
use common::{device::Device, signal_protobuf::Envelope, user::User};

pub async fn add_user(
    State(state): State<ServerState>,
    username: &str,
    password: &str,
) -> Result<()> {
    sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
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
        "SELECT id, username, password FROM users WHERE username = $1",
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
        "UPDATE users SET username = $2 WHERE username = $1",
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
        "UPDATE users SET password = $2 WHERE username = $1",
        username,
        new_password
    )
    .execute(&state.pool)
    .await
    .map(|_| ())
    .map_err(|err| err.into())
}

pub async fn delete_user(State(state): State<ServerState>, username: &str) -> Result<()> {
    sqlx::query!("DELETE FROM users WHERE username = $1", username)
        .execute(&state.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
}

pub async fn add_device(State(state): State<ServerState>, owner: &User) -> Result<()> {
    sqlx::query!("INSERT INTO devices (owner) VALUES ($1)", owner.id)
        .execute(&state.pool)
        .await
        .map(|_| ())
        .map_err(|err| err.into())
}

pub async fn get_devices(State(state): State<ServerState>, owner: &User) -> Result<Vec<Device>> {
    sqlx::query_as!(
        Device,
        "SELECT id, owner FROM devices WHERE owner = $1",
        owner.id
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|err| err.into())
}

pub async fn delete_device(State(state): State<ServerState>, owner: &User, id: i32) -> Result<()> {
    sqlx::query!(
        "DELETE FROM devices WHERE owner = $1 AND id = $2",
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
        "INSERT INTO msq_queue (reciver, msg) VALUES ($1, $2)",
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
    sqlx::query!("SELECT msg FROM msq_queue WHERE reciver = $1", reciver.id)
        .fetch_all(&state.pool)
        .await?
        .iter()
        .try_fold(vec![], |mut acc, msg| -> Result<Vec<Envelope>> {
            acc.push(bincode::deserialize(&msg.msg)?);
            Ok(acc)
        })
}

pub fn store_key_bundle() {}

pub fn get_key_bundle() {}
