use crate::database::{Device, SignalDatabase};
use crate::in_memory_db::InMemorySignalDatabase;
use anyhow::{bail, Result};
use axum::extract::{FromRef, FromRequestParts, Path, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use axum::http::request::Parts;
use axum::http::Method;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{async_trait, debug_handler, Json, Router};
use common::pre_key::PreKey;
use common::signal_protobuf::Envelope;
use common::web_api::{CreateAccountOptions, UploadKeys, UploadSignedPreKey};
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

// The Signal endpoint /v2/keys/check says that a u64 id is needed, however their ids, such as
// KyperPreKeyID only supports u32. Here only a u32 is used and therefore only a 4 byte size
// instead of the sugested u64.
async fn handle_post_keycheck<T: SignalDatabase>(
    database: T,
    usr_id: UserID,
    device_id: DeviceID,
    usr_digest: [u8; 32],
) -> Result<bool> {
    todo!()
    /*
    if let Some(keys) = database
        .lock()
        .await
        .keys
        .lock()
        .await
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
    */
}

#[derive(Clone)]
pub struct ServerState {
    pub db: Arc<Mutex<InMemorySignalDatabase>>,

    pub pool: Pool<Postgres>,
}

impl ServerState {
    async fn new() -> Result<ServerState> {
        dotenv::dotenv().expect("Unable to load environment variables from .env file");
        let db_url = std::env::var("DATABASE_URL").expect("Unable to read DATABASE_URL env var");

        let pool = PgPoolOptions::new()
            .max_connections(100)
            .connect(&db_url)
            .await
            .expect("Unable to connect to Postgres");

        Ok(ServerState {
            db: Arc::new(Mutex::new(InMemorySignalDatabase::new())),
            pool,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Msg {
    message: String,
}

#[derive(Clone, Debug)]
struct SignalServerState<T: SignalDatabase> {
    db: T,
}

impl<T: SignalDatabase> SignalServerState<T> {
    #[allow(dead_code)]
    fn database(&self) -> T {
        self.db.clone()
    }
}

impl SignalServerState<InMemorySignalDatabase> {
    fn new() -> Self {
        Self {
            db: InMemorySignalDatabase::new(),
        }
    }
}

async fn handle_put_messages<T: SignalDatabase>(
    state: SignalServerState<T>,
    address: Device,
    payload: Envelope,
) -> impl IntoResponse {
    println!("Received message");
    if let Err(result) = state.database().push_msg_queue(&address, payload).await {
        println!(
            "An error occurred while trying to push message to database: {}",
            result
        )
    }
    Response::new("Message sent!".to_string())
}

async fn handle_get_messages<T: SignalDatabase>(
    State(state): State<SignalServerState<InMemorySignalDatabase>>,
    Path(address): Path<String>,
    Json(payload): Json<Envelope>,
) {
}

async fn handle_register_account<T: SignalDatabase>(
    State(state): State<SignalServerState<T>>,
    Path(address): Path<String>,
    Json(payload): Json<UploadKeys>,
) {
    println!("Publish bundle");
}

async fn handle_put_registration<T: SignalDatabase>(
    State(state): State<SignalServerState<T>>,
    Path(address): Path<String>,
    Json(options): Json<CreateAccountOptions>,
) {
    println!("Register client");
}

/// Handler for the PUT v1/messages/{address} endpoint.
#[debug_handler]
async fn put_messages_endpoint(
    State(state): State<SignalServerState<InMemorySignalDatabase>>,
    Path(address): Path<String>,
    Json(payload): Json<Envelope>, // TODO: Multiple messages could be sent at one time
) -> impl IntoResponse {
    let device = address
        .try_into()
        .expect("A user shurely would never send an invalid address :)");
    handle_put_messages(state, device, payload).await
}

/// Handler for the GET v1/messages endpoint.
#[debug_handler]
async fn get_messages_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_get_messages`
}

/// Handler for the PUT v1/registration endpoint.
#[debug_handler]
async fn put_registration_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_put_registration`
}

/// Handler for the GET v2/keys endpoint.
#[debug_handler]
async fn get_keys_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_get_keys`
}

/// Handler for the POST v2/keys/check endpoint.
#[debug_handler]
async fn post_keycheck_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_post_keycheck`
}

/// Handler for the PUT v2/keys endpoint.
#[debug_handler]
async fn put_keys_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_put_keys`
}

/// Handler for the DELETE v1/accounts/me endpoint.
#[debug_handler]
async fn delete_account_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_delete_account`
}

/// Handler for the DELETE v1/devices/{device_id} endpoint.
#[debug_handler]
async fn delete_device_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_delete_device`
}

/// Handler for the POST v1/devices/link endpoint.
#[debug_handler]
async fn post_link_device_endpoint(State(state): State<SignalServerState<InMemorySignalDatabase>>) {
    // TODO: Call `handle_post_link_device`
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
    let server = SignalServerState::new();
    let app = Router::new()
        .route("/v1/messages", get(get_messages_endpoint))
        .route("/v1/messages/:destination", put(put_messages_endpoint))
        .route("/v1/registration/", post(handle_register_account))
        .route("/v2/keys", get(get_keys_endpoint))
        .route("/v2/keys/check", post(post_keycheck_endpoint))
        .route("/v2/keys", put(put_keys_endpoint))
        .route("/v1/accounts/me", delete(delete_account_endpoint))
        .route("/v1/devices/link", post(post_link_device_endpoint))
        .route("/v1/devices/:device_id", delete(delete_device_endpoint))
        .with_state(server)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:50051").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use super::{handle_put_messages, SignalServerState};
    use crate::database::{Device, SignalDatabase, User, UserID};
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /*
    #[tokio::test]
    async fn handle_post_keycheck_test() {
        let database = InMemorySignalDatabase::new();
        let usr_id: UserID = 0u32;
        let device_id: DeviceID = 0u32;
        let mut rng = OsRng;

        let kyper_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
        let kyper_key_id = 0u32;
        let signed_pre_key_pair = KeyPair::generate(&mut rng);
        let signed_key_id = 0u32;
        let identity_key_pair = KeyPair::generate(&mut rng);

        database.keys.lock().await.insert(usr_id, HashMap::new());
        database
            .keys
            .lock()
            .await
            .get_mut(&usr_id)
            .unwrap()
            .insert(device_id, HashMap::new());

        let key_map = database
            .keys
            .lock()
            .await
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

        drop(database);

        let mut usr_digest = Sha256::new();
        usr_digest.update(&identity_key_pair.public_key.serialize());
        usr_digest.update(&signed_key_id.to_be_bytes());
        usr_digest.update(signed_pre_key_pair.public_key.serialize().to_owned());
        usr_digest.update(&kyper_key_id.to_be_bytes());
        usr_digest.update(kyper_pre_key_pair.public_key.serialize().to_owned());

        let usr_digest: [u8; 32] = usr_digest.finalize().into();

        assert!(
            handle_post_keycheck(database, usr_id, device_id, usr_digest)
                .await
                .unwrap()
        );
        assert_ne!(vec![0; 32].as_slice(), usr_digest);
    }
    */
    // TODO: This should test GET keys endpoint.
    /*#[tokio::test]
    async fn get_keys_test() {
        let database = Arc::new(Mutex::new(InMemorySignalDatabase::new()));
        let usr_id: UserID = 0u32;
        let device_id: DeviceID = 0u32;

        let mut database_lock = database.lock().await;
        database_lock
            .keys
            .lock()
            .await
            .insert(usr_id, HashMap::new());
        database_lock
            .keys
            .lock()
            .await
            .get_mut(&usr_id)
            .unwrap()
            .insert(device_id, HashMap::new());

        let mut key_map = database_lock
            .keys
            .lock()
            .await
            .get_mut(&usr_id)
            .unwrap()
            .get_mut(&device_id)
            .unwrap()
            .clone();

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
    }*/

    #[tokio::test]
    async fn send_messages_adds_message_to_queue() {
        let destination = Device { id: 0, owner: 0 };
        let other = Device { id: 1, owner: 0 };
        let state = SignalServerState::new();
        state.database().add_user("bob", "1234").await;
        state
            .database()
            .add_device(&destination.owner, destination.clone())
            .await
            .unwrap();
        state
            .database()
            .add_device(&other.owner, other.clone())
            .await
            .unwrap();
        let message = common::signal_protobuf::Envelope {
            r#type: None,
            source_service_id: None,
            source_device: None,
            client_timestamp: None,
            content: None,
            server_guid: None,
            server_timestamp: None,
            ephemeral: None,
            destination_service_id: None,
            urgent: None,
            updated_pni: None,
            story: None,
            report_spam_token: None,
            shared_mrm_key: None,
        };
        handle_put_messages(state.clone(), destination.clone(), message.clone()).await;

        assert!(
            message
                == state
                    .database()
                    .mail_queues
                    .lock()
                    .await
                    .get_mut(&destination)
                    .unwrap()
                    .pop_front()
                    .unwrap()
        );
    }
}
