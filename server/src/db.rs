use crate::ServerState;
use anyhow::{bail, Result};
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

pub async fn push_msg_queue(State(state): State<ServerState>, reciver: &Device, msg: &Envelope) -> Result<()> {
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

pub async fn pop_msg_queue(State(state): State<ServerState>, reciver: &Device) -> Result<Vec<Envelope>> {
    sqlx::query!(
        "SELECT msg FROM msq_queue WHERE reciver = $1",
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

pub fn store_key_bundle() {}

pub fn get_key_bundle() {}

// #[cfg(test)]
// mod tests {
//     use anyhow::{bail, Result};
//     use common::user::User;
//     use sqlx::postgres::PgPoolOptions;

//     use super::{add_user, get_user, update_user_username, update_user_password, delete_user};

//     async fn init_db() {
// 	    dotenv::dotenv().expect("Unable to load environment variables from .env file");
// 	    let db_url = std::env::var("DATABASE_URL").expect("Unable to read DATABASE_URL env var");

// 	    let pool = PgPoolOptions::new()
// 		    .max_connections(100)
// 		    .connect(&db_url)
// 		    .await.expect("Unable to connect to Postgres");
//     }

//     async fn truncate_table(client: &Client, table_name: &str) -> Result<()> {
//     	let query_str = format!("TRUNCATE TABLE {} CASCADE", table_name);
//     	match client.execute(&query_str, &[]).await {
//     	    Ok(_) => Ok(()),
//     	    Err(err) => bail!(err),
//     	}
//     }

//     async fn count_rows(client: &Client, table_name: &str) -> Result<Box<str>> {
//     	let query_str = format!("SELECT count(*) FROM {}", table_name);
//     	match client.query_one(&query_str, &[]).await {
//     	    Ok(rows) => Ok(rows.get(0)),
//     	    Err(err) => bail!(err),
//     	}
//     }

// 	#[tokio::test]
// 	async fn test_add_and_get_user() {
// 		let client = init_db().await.unwrap();
// 		let expected_user = User { username: "bob".to_string(), password: "secret_password".to_string() };

// 		add_user(&client, &expected_user.username, &expected_user.password).await.unwrap();

// 		let actual_user = get_user(&client, &expected_user.username).await.unwrap();

// 		assert_eq!(expected_user, actual_user);

// 		truncate_table(&client, "test_users").await.unwrap();
// 	}

// 	#[tokio::test]
// 	async fn test_update_user_username() {
// 		let client = init_db().await.unwrap();
// 		let old_user = User { username: "bob".to_string(), password: "secret_password".to_string() };
// 		let new_user = User { username: "bab".to_string(), password: "secret_password".to_string() };

// 		add_user(&client, &old_user.username, &old_user.password).await.unwrap();
// 		update_user_username(&client, &old_user.username,& new_user.username);

// 		let actual_user = get_user(&client, &new_user.username).await.unwrap();

// 		assert_eq!(new_user, actual_user);
// 		assert_eq!(old_user.username, "bob");

// 		truncate_table(&client, "test_users").await.unwrap();
// 	}

// 	#[tokio::test]
// 	async fn test_update_user_password() {
// 		let client = init_db().await.unwrap();
// 		let old_user = User { username: "bob".to_string(), password: "secret_password".to_string() };
// 		let new_user = User { username: "bob".to_string(), password: "more_secret_password".to_string() };

// 		add_user(&client, &old_user.username, &old_user.password).await.unwrap();
// 		update_user_password(&client, &old_user.username,& new_user.password);

// 		let actual_user = get_user(&client, &new_user.username).await.unwrap();

// 		assert_eq!(new_user, actual_user);
// 		assert_eq!(old_user.password, "secret_password");

// 		truncate_table(&client, "test_users").await.unwrap();
// 	}

// 	#[tokio::test]
// 	async fn test_delete_user() {
// 		let table_name = "test_users";
// 		let client = init_db().await.unwrap();
// 		let user = User { username: "bob".to_string(), password: "secret_password".to_string() };

// 		let rows_before_add: u32 = count_rows(&client, table_name).await.unwrap().as_ref().parse().unwrap();
// 		add_user(&client, &user.username, &user.password).await.unwrap();
// 		let rows_after_add: u32 = count_rows(&client, table_name).await.unwrap().as_ref().parse().unwrap();

// 		assert_eq!(rows_before_add + 1, rows_after_add);

// 		delete_user(&client, &user.username).await.unwrap();
// 		let rows_after_deletion: u32 = count_rows(&client, table_name).await.unwrap().as_ref().parse().unwrap();

// 		assert_eq!(rows_before_add, rows_after_deletion);

// 		truncate_table(&client, table_name).await.unwrap();
// 	}

// 	#[tokio::test]
// 	async fn test_add_device() {
// 		// let client = init_db().await.unwrap();
// 	}

// 	#[tokio::test]
// 	async fn test_get_device() {

// 	}

// 	#[tokio::test]
// 	async fn test_delete_device() {

// 	}

// 	#[tokio::test]
// 	async fn test_push_msg_queue() {

// 	}

// 	#[tokio::test]
// 	async fn test_pop_msg_queue() {

// 	}

// 	#[tokio::test]
// 	async fn test_store_key_bundle() {

// 	}

// 	#[tokio::test]
// 	async fn test_get_key_bundle() {

// 	}
// }
