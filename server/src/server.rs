use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use common::web_api::{CreateAccountOptions, UploadKeys, UploadSignedPreKey};
use libsignal_protocol::PreKeyBundleContent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use axum::http::{HeaderValue, Method};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

type Username = String;
type DeviceID = u32;
type UserID = u32;
type Message = String;
type ErrorMessage = String;

pub struct InMemorySignalDatabase {
    mail_queues: HashMap<UserID, VecDeque<Message>>,
    usernames: HashMap<UserID, Username>,
    devices: HashMap<UserID, HashSet<DeviceID>>,
}

impl InMemorySignalDatabase {
    pub fn new() -> Self {
        Self {
            mail_queues: HashMap::new(),
            usernames: HashMap::new(),
            devices: HashMap::new(),
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

async fn get_prekeys_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    id: UserID,
) -> Result<PreKeyBundleContent, ErrorMessage> {
    todo!()
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

#[derive(Clone)]
struct ServerState {
    db: Arc<Mutex<InMemorySignalDatabase>>,
}

impl ServerState {
    fn new() -> ServerState {
        ServerState {
            db: Arc::new(Mutex::new(InMemorySignalDatabase::new())),
        }
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
    println!("Received message: {:?}", payload);
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

pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .max_age(Duration::from_secs(5184000))
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, CONTENT_TYPE, CONTENT_LENGTH, ACCEPT, ORIGIN]);
    let server = ServerState::new();
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:50051").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
