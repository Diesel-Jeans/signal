use crate::message_cache::MessageCache;
use anyhow::{bail, Result};
use axum::extract::{Path, State};
use axum::handler::Handler;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use axum::http::Method;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use common::pre_key::PreKey;
use common::web_api::{CreateAccountOptions, UploadKeys, UploadSignedPreKey};
use deadpool_redis::{
    redis::{cmd, FromRedisValue},
    Config, Connection, Runtime,
};
use libsignal_protocol::{kem, PreKeyBundleContent, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
type Username = String;
type DeviceID = u32;
type UserID = u32;
type Message = String;
type ErrorMessage = String;

enum PublicKeyType {
    Kem(kem::PublicKey),
    Ec(PublicKey),
}

impl PublicKeyType {
    fn expect_kem(self) -> kem::PublicKey {
        if let PublicKeyType::Kem(key) = self {
            key
        } else {
            panic!("dev_err: expected a kem key, got an ec key")
        }
    }
    fn expect_ec(self) -> PublicKey {
        if let PublicKeyType::Ec(key) = self {
            key
        } else {
            panic!("dev_err: expected an ec key, got a kem key")
        }
    }
}

pub struct InMemorySignalDatabase {
    mail_queues: HashMap<UserID, VecDeque<Message>>,
    usernames: HashMap<UserID, Username>,
    devices: HashMap<UserID, HashSet<DeviceID>>,
    keys: HashMap<UserID, HashMap<DeviceID, HashMap<PreKey, Vec<UploadSignedPreKey>>>>,
}

impl InMemorySignalDatabase {
    pub fn new() -> Self {
        Self {
            mail_queues: HashMap::new(),
            usernames: HashMap::new(),
            devices: HashMap::new(),
            keys: HashMap::new(),
        }
    }
}

async fn store_message_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
    message: Message,
) -> Result<(), ErrorMessage> {
    let mut database = database.lock().await;
    if let Some(queue) = database.mail_queues.get_mut(&id) {
        queue.push_back(message);
        Ok(())
    } else {
        Err("The person that you messaged does not exist".into())
    }
}
async fn get_messages_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
) -> Result<Vec<Message>, ErrorMessage> {
    let mut database = database.lock().await;
    if let Some(queue) = database.mail_queues.get_mut(&id) {
        Ok(queue.drain(..).collect())
    } else {
        Err("There is no mail queue for the specified user".into())
    }
}

async fn store_prekeys_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
    keys: PreKeyBundleContent,
) -> Result<(), ErrorMessage> {
    todo!()
}

async fn get_onetime_prekey_count(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    usr_id: UserID,
    device_id: DeviceID,
) -> Result<usize> {
    database
        .lock()
        .await
        .keys
        .get(&usr_id)
        .and_then(|device_map| device_map.get(&device_id))
        .and_then(|key_map| key_map.get(&PreKey::OneTime))
        .and_then(|key_list| Some(key_list.len()))
        .ok_or_else(|| anyhow::anyhow!("Could not get one time pre key count"))
}

async fn store_username_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
    username: &Username,
) -> Result<(), ErrorMessage> {
    let mut database = database.lock().await;
    database.usernames.insert(id, username.clone());
    Ok(())
}

async fn store_user_id_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    username: &Username,
    id: UserID,
) -> Result<(), ErrorMessage> {
    todo!()
}

async fn create_user_id_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    username: &Username,
) -> Result<UserID, ErrorMessage> {
    let mut database = database.lock().await;
    if !database
        .usernames
        .iter()
        .any(|(_, existing)| *username == **existing)
    {
        use rand::distributions::{Alphanumeric, DistString};

        let id: UserID = Alphanumeric
            .sample_string(&mut rand::thread_rng(), 16)
            .parse()
            .unwrap();
        database.usernames.insert(id.clone(), username.clone());
        Ok(id)
    } else {
        Err("Username already exists".into())
    }
}

async fn get_user_id_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    username: &Username,
) -> Result<UserID, ErrorMessage> {
    let mut database = database.lock().await;
    if let Some(id) = database
        .usernames
        .iter()
        .find(|(_, existing)| **existing == *username)
    {
        Ok(id.0.clone())
    } else {
        Err("Username not found".into())
    }
}

async fn create_new_device_id(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: &UserID,
) -> Result<DeviceID, ErrorMessage> {
    let mut database = database.lock().await;
    if let Some(devices) = database.devices.get_mut(id) {
        let max = *devices.iter().max().unwrap_or(&0u32);
        for i in 0u32.into()..max {
            if !devices.contains(&i) {
                devices.insert(i.to_owned());
                return Ok(i.to_owned());
            }
        }
        let new_device = max + 1;
        devices.insert(new_device);
        Ok(new_device)
    } else {
        Err("Device could not be created because user did not exist".into())
    }
}

async fn delete_device(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
    device: DeviceID,
) -> Result<(), ErrorMessage> {
    todo!()
}

async fn delete_client(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
) -> Result<(), ErrorMessage> {
    todo!()
}

// The Signal endpoint /v2/keys/check says that a u64 id is needed, however their ids, such as
// KyperPreKeyID only supports u32. Here only a u32 is used and therefore only a 4 byte size
// instead of the sugested u64.
async fn keys_check(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    usr_id: UserID,
    device_id: DeviceID,
    usr_digest: [u8; 32],
) -> Result<bool> {
    let database = database.lock().await;
    if let Some(keys) = database
        .keys
        .get(&usr_id)
        .and_then(|usr_map| usr_map.get(&device_id))
    {
        fn get_pre_key<'a>(
            key_type: &PreKey,
            table: &'a HashMap<PreKey, Vec<UploadSignedPreKey>>,
        ) -> Result<&'a UploadSignedPreKey> {
            if let Some(key) = table.get(key_type) {
                if key.len() <= 1 {
                    Ok(&key[0])
                } else {
                    bail!("There are too many keys of type: {:?}.", key_type)
                }
            } else {
                bail!("There is no {:?} key for user", key_type)
            }
        }

        let identity_key_upload = get_pre_key(&PreKey::Identity, keys)?;
        let signed_key_upload = get_pre_key(&PreKey::Signed, keys)?;
        let kyper_key_update = get_pre_key(&PreKey::Kyber, keys)?;

        let mut digest = Sha256::new();
        digest.update(&identity_key_upload.public_key);
        digest.update(&signed_key_upload.key_id.to_be_bytes());
        digest.update(signed_key_upload.public_key.to_owned());
        digest.update(&kyper_key_update.key_id.to_be_bytes());
        digest.update(kyper_key_update.public_key.to_owned());

        let server_digest: [u8; 32] = digest.finalize().into();

        Ok(server_digest == usr_digest)
    } else {
        bail!("Client has no keys")
    }
}

#[derive(Clone)]
pub(crate) struct ServerState {
    pub(crate) redis: deadpool_redis::Pool,
    pub db: Arc<Mutex<InMemorySignalDatabase>>,
    pub pool: Pool<Postgres>,
}

impl ServerState {
    async fn new() -> Result<ServerState> {
        dotenv::dotenv().expect("Unable to load environment variables from ..env file");
        let redis_url = std::env::var("REDIS_URL").expect("Unable to read REDIS_URL .env var");
        let mut redis_config = Config::from_url(redis_url);
        let redis_pool: deadpool_redis::Pool = redis_config.create_pool(Some(Runtime::Tokio1))?;

        let db_url = std::env::var("DATABASE_URL").expect("Unable to read DATABASE_URL .env var");
        let pool = PgPoolOptions::new()
            .max_connections(100)
            .connect(&db_url)
            .await
            .expect("Unable to connect to Postgres");

        Ok(ServerState {
            db: Arc::new(Mutex::new(InMemorySignalDatabase::new())),
            redis: redis_pool,
            pool,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Msg {
    message: String,
}

async fn handle_send_message(
    State(state): State<ServerState>,
    Path(address): Path<String>,
    Json(payload): Json<Msg>,
) {
    let mut connection = state.redis.get().await.unwrap();
    let addr = address.as_str();

    MessageCache::insert(
        &mut connection,
        "b0231ab5-4c7e-40ea-a544-f925c5054323".to_string(),
        2,
        "Hello this is a test of the insert() function".to_string(),
        "1337".to_string(),
    )
    .await;
}

async fn handle_publish_bundle(
    State(state): State<ServerState>,
    Path(address): Path<String>,
    Json(payload): Json<UploadKeys>,
) {
    println!("Publish bundle");
}

async fn handle_fetch_bundle() {
    println!("Fetch bundle");
}

async fn handle_register_client(
    State(state): State<ServerState>,
    Path(address): Path<String>,
    Json(options): Json<CreateAccountOptions>,
) {
    println!("Register client");
}

async fn handle_register_device() {
    println!("Register device");
}

async fn handle_update_client() {
    println!("Update client");
}

async fn handle_delete_client() {
    println!("Update");
}

async fn handle_delete_device() {
    println!("Delete device");
}

async fn set_redis_config(conn: &mut Connection) {
    cmd("CONFIG")
        .arg("SET")
        .arg("notify-keyspace-events")
        .arg("Ex")
        .query_async::<()>(conn)
        .await
        .unwrap()
}

pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .max_age(Duration::from_secs(5184000))
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, CONTENT_LENGTH, ACCEPT, ORIGIN]);
    let server = ServerState::new().await?;
    let redis_client = redis::Client::open(std::env::var("REDIS_URL")?)?;
    let conn = redis_client.get_connection()?;
    tokio::spawn(MessageCache::listen_for_expirations(conn));
    let mut conn = server.redis.get().await.unwrap();
    set_redis_config(&mut conn).await;
    let app = Router::new()
        .route("/message/:address", put(handle_send_message))
        .route("/bundle/:address", post(handle_publish_bundle))
        .route("/bundle/:address", get(handle_fetch_bundle))
        .route("/client", post(handle_register_client))
        .route("/client", put(handle_update_client))
        .route("/client/:address", delete(handle_delete_client))
        .route("/device/:address", post(handle_register_device))
        .route("/device/:address", delete(handle_delete_device))
        .with_state(server)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:1234").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn keys_check_test() {
        let database = Arc::new(Mutex::new(InMemorySignalDatabase::new()));
        let usr_id: UserID = 0u32;
        let device_id: DeviceID = 0u32;
        let mut rng = OsRng;

        let kyper_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
        let kyper_key_id = 0u32;
        let signed_pre_key_pair = KeyPair::generate(&mut rng);
        let signed_key_id = 0u32;
        let identity_key_pair = KeyPair::generate(&mut rng);

        let mut database_lock = database.lock().await;
        database_lock.keys.insert(usr_id, HashMap::new());
        database_lock
            .keys
            .get_mut(&usr_id)
            .unwrap()
            .insert(device_id, HashMap::new());

        let key_map = database_lock
            .keys
            .get_mut(&usr_id)
            .unwrap()
            .get_mut(&device_id)
            .unwrap();

        key_map
            .entry(PreKey::Identity)
            .or_insert_with(Vec::new)
            .push(UploadSignedPreKey {
                key_id: 0,
                public_key: identity_key_pair.public_key.serialize(),
                signature: Box::new([0]),
            });
        key_map
            .entry(PreKey::Signed)
            .or_insert_with(Vec::new)
            .push(UploadSignedPreKey {
                key_id: signed_key_id,
                public_key: signed_pre_key_pair.public_key.serialize(),
                signature: Box::new([0]),
            });
        key_map
            .entry(PreKey::Kyber)
            .or_insert_with(Vec::new)
            .push(UploadSignedPreKey {
                key_id: kyper_key_id,
                public_key: kyper_pre_key_pair.public_key.serialize(),
                signature: Box::new([0]),
            });

        drop(database_lock);

        let mut usr_digest = Sha256::new();
        usr_digest.update(&identity_key_pair.public_key.serialize());
        usr_digest.update(&signed_key_id.to_be_bytes());
        usr_digest.update(signed_pre_key_pair.public_key.serialize().to_owned());
        usr_digest.update(&kyper_key_id.to_be_bytes());
        usr_digest.update(kyper_pre_key_pair.public_key.serialize().to_owned());

        let usr_digest: [u8; 32] = usr_digest.finalize().into();

        assert!(keys_check(database, usr_id, device_id, usr_digest)
            .await
            .unwrap());
        assert_ne!(vec![0; 32].as_slice(), usr_digest);
    }
    #[tokio::test]
    async fn get_keys_test() {
        let database = Arc::new(Mutex::new(InMemorySignalDatabase::new()));
        let usr_id: UserID = 0u32;
        let device_id: DeviceID = 0u32;

        let mut database_lock = database.lock().await;
        database_lock.keys.insert(usr_id, HashMap::new());
        database_lock
            .keys
            .get_mut(&usr_id)
            .unwrap()
            .insert(device_id, HashMap::new());

        let key_map = database_lock
            .keys
            .get_mut(&usr_id)
            .unwrap()
            .get_mut(&device_id)
            .unwrap();

        let j = 10;
        let mut i = 0;
        while j > i {
            key_map
                .entry(PreKey::OneTime)
                .or_insert_with(Vec::new)
                .push(UploadSignedPreKey {
                    key_id: 0,
                    public_key: Box::new([0]),
                    signature: Box::new([0]),
                });
            i = i + 1;
        }

        drop(database_lock);

        assert_eq!(
            get_onetime_prekey_count(database, usr_id, device_id)
                .await
                .unwrap(),
            j
        );
    }
}
