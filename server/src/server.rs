use crate::api_error::ApiError;
use crate::database::SignalDatabase;
use crate::in_memory_db::InMemorySignalDatabase;
use crate::postgres::PostgresDatabase;
use anyhow::Result;
use axum::extract::{connect_info::ConnectInfo, Host, Path, State};
use axum::handler::HandlerWithoutStateExt;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, delete, get, post, put};
use axum::BoxError;
use axum::{debug_handler, Json, Router};
use common::signal_protobuf::Envelope;
use common::web_api::{CreateAccountOptions, SignalMessages};
use libsignal_core::{DeviceId, ProtocolAddress, ServiceId};
use libsignal_protocol::{kem, PublicKey};
use std::env;
use std::fmt::format;
use std::time::Duration;
use tower_http::cors::CorsLayer;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum_extra::{headers, TypedHeader};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::socket::{SocketManager, ToEnvelope};

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

#[derive(Clone, Debug)]
struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: SocketManager,
}

impl<T: SignalDatabase> SignalServerState<T> {
    #[allow(dead_code)]
    fn database(&self) -> T {
        self.db.clone()
    }
}

impl SignalServerState<InMemorySignalDatabase> {
    async fn new() -> Self {
        Self {
            db: InMemorySignalDatabase::new(),
            socket_manager: SocketManager::new(),
        }
    }
}

impl SignalServerState<PostgresDatabase> {
    async fn new() -> Self {
        Self {
            db: PostgresDatabase::connect().await.unwrap(),
            socket_manager: SocketManager::new(),
        }
    }
}

async fn handle_put_messages<T: SignalDatabase>(
    state: SignalServerState<T>,
    address: ProtocolAddress,
    payload: SignalMessages,
) -> Result<(), ApiError> {
    println!("Received message");
    todo!()
    //let mut envelopes = Vec::new();
    //for msg in payload.messages{
    //    envelopes.push(msg.to_envelope());
    //    
    //}
    //state
    //    .database()
    //    .push_message_queue(address, vec![payload])
    //    .await
    //    .map_err(|_| ApiError {
    //        message: "Could not push the message to message queue.".to_owned(),
    //        status_code: StatusCode::INTERNAL_SERVER_ERROR,
    //    })
}

async fn handle_get_messages<T: SignalDatabase>(
    state: SignalServerState<T>,
    address: ProtocolAddress,
) {
    println!("Get messages")
}

async fn handle_put_registration<T: SignalDatabase>(
    State(state): State<SignalServerState<T>>,
    Path(address): Path<String>,
    Json(options): Json<CreateAccountOptions>,
) {
    println!("Register client");
}

// redirect from http to https. this is temporary
async fn redirect_http_to_https(addr: SocketAddr, http: u16, https: u16) -> Result<(), BoxError> {
    fn make_https(host: String, uri: Uri, http: u16, https: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse()?);
        }

        let https_host = host.replace(&http.to_string(), &https.to_string());
        parts.authority = Some(https_host.parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(host, uri, http, https) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, redirect.into_make_service()).await?;
    Ok(())
}

// The Signal endpoint /v2/keys/check says that a u64 id is needed, however their ids, such as
// KyperPreKeyID only supports u32. Here only a u32 is used and therefore only a 4 byte size
// instead of the sugested u64.
async fn handle_post_keycheck<T: SignalDatabase>(
    database: T,
    usr_id: ServiceId,
    device_id: DeviceId,
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

/// A protocol address is represented in string form as
/// <user_id>.<device_id>. This function takes this string and
/// produces a [ProtocolAddress].
fn parse_protocol_address(string: String) -> Result<ProtocolAddress, ApiError> {
    let (user_id, dev_id) = string
        .find(".")
        .ok_or(ApiError {
            message: "Could not parse address. Address did not contain '.'".to_owned(),
            status_code: StatusCode::BAD_REQUEST,
        })
        .map(|pos| string.split_at(pos))?;
    let device_id: DeviceId = dev_id[1..]
        .parse::<u32>()
        .map_err(|e| ApiError {
            message: format!("Could not parse device_id: {}.", e),
            status_code: StatusCode::BAD_REQUEST,
        })?
        .into();

    Ok(ProtocolAddress::new(user_id.to_owned(), device_id))
}

fn parse_service_id(string: String) -> Result<ServiceId, ApiError> {
    ServiceId::parse_from_service_id_string(&string).ok_or_else(|| ApiError {
        message: "Could not parse service id".to_owned(),
        status_code: StatusCode::BAD_REQUEST,
    })
}

/// Handler for the PUT v1/messages/{address} endpoint.
#[debug_handler]
async fn put_messages_endpoint(
    State(state): State<SignalServerState<PostgresDatabase>>,
    Path(address): Path<String>,
    Json(payload): Json<SignalMessages>, // TODO: Multiple messages could be sent at one time
) -> Result<(), ApiError> {
    let address = parse_protocol_address(address)?;
    handle_put_messages(state, address, payload).await
}

/// Handler for the GET v1/messages endpoint.
#[debug_handler]
async fn get_messages_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_get_messages`
}

/// Handler for the PUT v1/registration endpoint.
#[debug_handler]
async fn put_registration_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_put_registration`
}

/// Handler for the GET v2/keys endpoint.
#[debug_handler]
async fn get_keys_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_get_keys`
}

/// Handler for the POST v2/keys/check endpoint.
#[debug_handler]
async fn post_keycheck_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_post_keycheck`
}

/// Handler for the PUT v2/keys endpoint.
#[debug_handler]
async fn put_keys_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_put_keys`
}

/// Handler for the DELETE v1/accounts/me endpoint.
#[debug_handler]
async fn delete_account_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_delete_account`
}

/// Handler for the DELETE v1/devices/{device_id} endpoint.
#[debug_handler]
async fn delete_device_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_delete_device`
}

/// Handler for the POST v1/devices/link endpoint.
#[debug_handler]
async fn post_link_device_endpoint(State(state): State<SignalServerState<PostgresDatabase>>) {
    // TODO: Call `handle_post_link_device`
}

// Websocket upgrade handler '/v1/websocket'
#[debug_handler]
async fn create_websocket_endpoint(
    State(mut state): State<SignalServerState<PostgresDatabase>>,
    /*authenticated_device: ???, */
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown browser")
    };
    println!("`{user_agent}` at {addr} connected.");
    ws.on_upgrade(move |socket| {
        let mut socket_manager = state.socket_manager.clone();
        async move {
            socket_manager
                .handle_socket(/*authenticated_device,*/ socket, addr)
                .await;
        }
    })
}

/// To add a new endpoint:
///  * create an async router function: `<method>_<endpoint_name>_endpoint`.
///  * create an async handler function: `handle_<method>_<endpoint_name>`
///  * add the router function to the axum router below.
///  * call the handler function from the router function to handle the request.
pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    let config = RustlsConfig::from_pem_file("cert/server.crt", "cert/server.key").await?;

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

    let state = SignalServerState::<PostgresDatabase>::new().await;

    let app = Router::new()
        .route("/", get(|| async { "Hello from Signal Server" }))
        .route("/v1/messages", get(get_messages_endpoint))
        .route("/v1/messages/:destination", put(put_messages_endpoint))
        .route("/v1/registration/", post(put_registration_endpoint))
        .route("/v2/keys", get(get_keys_endpoint))
        .route("/v2/keys/check", post(post_keycheck_endpoint))
        .route("/v2/keys", put(put_keys_endpoint))
        .route("/v1/accounts/me", delete(delete_account_endpoint))
        .route("/v1/devices/link", post(post_link_device_endpoint))
        .route("/v1/devices/:device_id", delete(delete_device_endpoint))
        .route("/v1/websocket", any(create_websocket_endpoint))
        .with_state(state)
        .layer(cors);

    let address = env::var("SERVER_ADDRESS")?;
    let https_port = env::var("HTTPS_PORT")?;
    let http_port = env::var("HTTP_PORT")?;

    let http_addr = SocketAddr::from_str(format!("{}:{}", address, http_port).as_str())?;
    let https_addr = SocketAddr::from_str(format!("{}:{}", address, https_port).as_str())?;

    // we should probably sometime in future a proxy or something to redirect instead
    tokio::spawn(redirect_http_to_https(
        http_addr,
        http_port.parse()?,
        https_port.parse()?,
    ));

    axum_server::bind_rustls(https_addr, config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use super::{handle_put_messages, SignalServerState};
    use crate::account::Account;
    use crate::database::SignalDatabase;
    use common::web_api::Device;
    use libsignal_protocol::*;
    use uuid::Uuid;

    fn create_bob() -> Account {
        let id_key = IdentityKeyPair::generate(&mut rand::thread_rng());
        Account {
            aci: Some(Uuid::new_v4().to_string()),
            pni: None,
            auth_token: "1236854bff0ad5aa206f924c9c2ff800681f69df4f6963976f144c1842c2ff1b"
                .to_owned(),
            identity_key: id_key.identity_key().clone(),
        }
    }

    fn create_alice() -> Account {
        let id_key = IdentityKeyPair::generate(&mut rand::thread_rng());
        Account {
            aci: Some(Uuid::new_v4().to_string()),
            pni: None,
            auth_token: "1236854bff0ad5aa206f924c9c2ff800681f69df4f6963976f144c1842c2ff1b"
                .to_owned(),
            identity_key: id_key.identity_key().clone(),
        }
    }

    #[tokio::test]
    async fn handle_put_messages_adds_message_to_queue() {
        let state = SignalServerState::<InMemorySignalDatabase>::new().await;
        let bob = create_bob();
        let bob_device = Device {
            device_id: 0,
            name: "bob_device".to_owned(),
            last_seen: 0,
            created: 0,
        };
        let bob_address =
            ProtocolAddress::new(bob.service_id().service_id_string(), bob_device.device_id());

        let alice = create_alice();
        let alice_device = Device {
            device_id: 0,
            name: "alice_device".to_owned(),
            last_seen: 0,
            created: 0,
        };
        let alice_address = ProtocolAddress::new(
            alice.service_id().service_id_string(),
            alice_device.device_id(),
        );
        state.database().add_account(bob.clone()).await.unwrap();

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
        handle_put_messages(state.clone(), bob_address.clone(), message.clone())
            .await
            .unwrap();

        assert_eq!(
            message,
            state
                .database()
                .mail_queues
                .lock()
                .await
                .get_mut(&bob_address)
                .unwrap()
                .pop_front()
                .unwrap()
        );
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_get_messages_pops_message_queue() {
        todo!()
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_register_account_registers_account() {
        todo!()
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_get_keys_gets_keys() {
        todo!()
        /*
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
         */
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_post_keycheck_test() {
        todo!()
        /*
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
         */
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_() {
        todo!()
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_delete_account_deletes_account() {
        todo!()
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_post_link_device_registers_new_device() {
        todo!()
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_delete_device_deletes_device() {
        todo!()
    }
}
