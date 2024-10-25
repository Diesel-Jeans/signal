use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use crate::error::ApiError;
use crate::in_memory_db::InMemorySignalDatabase;
use crate::postgres::PostgresDatabase;
use anyhow::Result;
use axum::extract::{connect_info::ConnectInfo, Host, Path, State};
use axum::handler::HandlerWithoutStateExt;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{any, delete, get, post, put};
use axum::BoxError;
use axum::{debug_handler, Json, Router};
use common::web_api::{AuthorizationHeader, RegistrationRequest, SignalMessages};
use libsignal_core::{DeviceId, ProtocolAddress, ServiceId};
use std::env;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::message_cache::MessageCache;
use crate::socket::{SocketManager, ToEnvelope};
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum_extra::{headers, TypedHeader};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Clone, Debug)]
struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: SocketManager<WebSocket>,
    message_cache: MessageCache,
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
            message_cache: MessageCache::connect()
                .await
                .expect("Could not connect to Redis"),
        }
    }
}

impl SignalServerState<PostgresDatabase> {
    async fn new() -> Self {
        Self {
            db: PostgresDatabase::connect().await.unwrap(),
            socket_manager: SocketManager::new(),
            message_cache: MessageCache::connect()
                .await
                .expect("Could not connect to Redis"),
        }
    }
}

async fn handle_put_messages<T: SignalDatabase>(
    state: SignalServerState<T>,
    address: ProtocolAddress,
    payload: SignalMessages,
) -> Result<(), ApiError> {
    println!("Received message");
    /* TODO: handle_put_message
       this depends on ToEnvelope trait being implemented for SignalMessage which depends on Account
    */
    todo!()
}

async fn handle_get_messages<T: SignalDatabase>(
    state: SignalServerState<T>,
    address: ProtocolAddress,
) {
    println!("Get messages")
}

async fn handle_put_registration<T: SignalDatabase>(
    state: SignalServerState<T>,
    auth_header: AuthorizationHeader,
    registration: RegistrationRequest,
) -> Result<(), ApiError> {
    println!("Register client");
    let uuid = Uuid::parse_str(auth_header.username()).map_err(|err| ApiError {
        message: format!("Could not parse uuid '{}'", { auth_header.username() }),
        status_code: StatusCode::BAD_REQUEST,
    })?;

    let account = Account::new(
        uuid.into(),
        Device::new(
            0u32.into(),
            "bob_device".into(),
            0u32,
            0u32,
            "".into(),
            "".into(),
        ),
        *registration.pni_identity_key(),
        *registration.aci_identity_key(),
    );
    state
        .database()
        .add_account(account)
        .await
        .map_err(|err| ApiError {
            message: format!("Could not store user in database: {}", err),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    Ok(())
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
async fn put_registration_endpoint(
    State(state): State<SignalServerState<PostgresDatabase>>,
    headers: HeaderMap,
    Json(registration): Json<RegistrationRequest>,
) -> Result<(), ApiError> {
    let auth_header = headers
        .get("Authorization")
        .ok_or_else(|| ApiError {
            message: "Missing authorization header".to_owned(),
            status_code: StatusCode::UNAUTHORIZED,
        })?
        .to_str()
        .map_err(|err| ApiError {
            message: format!(
                "Authorization header could not be parsed as string: {}",
                err
            ),
            status_code: StatusCode::UNAUTHORIZED,
        })?
        .parse()
        .map_err(|err| ApiError {
            message: format!("Authorization header could not be parsed: {}", err),
            status_code: StatusCode::UNAUTHORIZED,
        })?;

    handle_put_registration(state, auth_header, registration).await
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
        todo!();
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn handle_post_keycheck_test() {
        todo!()
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
