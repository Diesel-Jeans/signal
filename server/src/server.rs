use crate::{
    account::{Account, AuthenticatedDevice, Device},
    account_authenticator::SaltedTokenHash,
    database::SignalDatabase,
    destination_device_validator::DestinationDeviceValidator,
    envelope::ToEnvelope,
    error::ApiError,
    managers::{
        message_persister::MessagePersister,
        state::SignalServerState,
        websocket::{
            connection::{UserIdentity, WebSocketConnection},
            wsstream::WSStream,
        },
    },
    postgres::PostgresDatabase,
    response::SendMessageResponse,
};
use anyhow::Result;
use axum::{
    debug_handler,
    extract::{
        connect_info::ConnectInfo,
        ws::{WebSocket, WebSocketUpgrade},
        Host, Path, State,
    },
    handler::HandlerWithoutStateExt,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN},
        HeaderMap, Method, StatusCode, Uri,
    },
    response::{IntoResponse, Redirect},
    routing::{any, delete, get, post, put},
    BoxError, Json, Router,
};
use axum_extra::{headers, TypedHeader};
use axum_server::tls_rustls::RustlsConfig;
use common::web_api::{
    authorization::BasicAuthorizationHeader, DevicePreKeyBundle, RegistrationRequest,
    RegistrationResponse, SignalMessages,
};
use futures_util::StreamExt;
use libsignal_core::{DeviceId, ProtocolAddress, ServiceId, ServiceIdKind};
use std::{
    env,
    fmt::Debug,
    net::SocketAddr,
    str::FromStr,
    time::{Duration, SystemTime},
};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::{self, TraceLayer},
};
use tracing::Level;

pub async fn handle_put_messages<T: SignalDatabase, U: WSStream + Debug>(
    state: &SignalServerState<T, U>,
    authenticated_device: &AuthenticatedDevice,
    destination_identifier: &ServiceId,
    payload: SignalMessages,
) -> Result<SendMessageResponse, ApiError> {
    if *destination_identifier == authenticated_device.account().pni() {
        return Err(ApiError {
            status_code: StatusCode::FORBIDDEN,
            message: "".to_owned(),
        });
    }

    let is_sync_message = *destination_identifier == authenticated_device.account().aci();
    let destination: Account = if is_sync_message {
        authenticated_device.account().clone()
    } else {
        state
            .account_manager
            .get_account(destination_identifier)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::NOT_FOUND,
                message: "Destination account not found".to_owned(),
            })?
    };
    let exclude_device_ids: Vec<u32> = if is_sync_message {
        vec![authenticated_device.device().device_id().into()]
    } else {
        Vec::new()
    };

    let message_device_ids: Vec<u32> = payload
        .messages
        .iter()
        .map(|message| message.destination_device_id)
        .collect();
    DestinationDeviceValidator::validate_complete_device_list(
        &destination,
        &message_device_ids,
        &exclude_device_ids,
    )
    .map_err(|_| ApiError {
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        message: "".to_owned(),
    })?;
    DestinationDeviceValidator::validate_registration_id_from_messages(
        &destination,
        &payload.messages,
        destination_identifier.kind() == ServiceIdKind::Pni,
    )
    .map_err(|_| ApiError {
        status_code: StatusCode::INTERNAL_SERVER_ERROR,
        message: "".to_owned(),
    })?;

    for message in payload.messages {
        let mut envelope = message.to_envelope(
            destination_identifier,
            authenticated_device.account(),
            u32::from(authenticated_device.device().device_id()) as u8,
            payload.timestamp,
            false,
        );
        let address = ProtocolAddress::new(
            destination.aci().service_id_string(),
            message.destination_device_id.into(),
        );
        state
            .message_manager
            .insert(&address, &mut envelope)
            .await
            .map_err(|_| ApiError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Could not insert message".to_owned(),
            })?;
    }

    let needs_sync = !is_sync_message && authenticated_device.account().devices().len() > 1;
    Ok(SendMessageResponse { needs_sync })
}

async fn handle_get_messages<T: SignalDatabase, U: WSStream + Debug>(
    state: SignalServerState<T, U>,
    address: ProtocolAddress,
) {
    todo!("Get messages")
}

async fn handle_post_registration<T: SignalDatabase, U: WSStream + Debug>(
    state: SignalServerState<T, U>,
    auth_header: BasicAuthorizationHeader,
    registration: RegistrationRequest,
) -> Result<RegistrationResponse, ApiError> {
    let time_now = time_now()?;
    let phone_number = auth_header.username();
    let hash = SaltedTokenHash::generate_for(auth_header.password())?;
    let device = Device::builder()
        .device_id(1.into())
        .name(registration.account_attributes().name.clone())
        .last_seen(time_now)
        .created(time_now)
        .auth_token(hash.hash())
        .salt(hash.salt())
        .registration_id(registration.account_attributes().registration_id)
        .pni_registration_id(registration.account_attributes().pni_registration_id)
        .build();

    let device_pre_key_bundle = DevicePreKeyBundle {
        aci_signed_pre_key: registration.aci_signed_pre_key().to_owned(),
        pni_signed_pre_key: registration.pni_signed_pre_key().to_owned(),
        aci_pq_pre_key: registration.aci_pq_last_resort_pre_key().to_owned(),
        pni_pq_pre_key: registration.pni_pq_last_resort_pre_key().to_owned(),
    };

    let account = state
        .account_manager
        .create_account(
            phone_number.to_owned(),
            registration.account_attributes().to_owned(),
            registration.aci_identity_key().to_owned(),
            registration.pni_identity_key().to_owned(),
            device.clone(),
        )
        .await?;

    let aci = account.aci();
    let address = ProtocolAddress::new(aci.service_id_string(), device.device_id());

    // Store key bunde for new account
    state
        .account_manager
        .store_key_bundle(&device_pre_key_bundle, &address)
        .await
        .map_err(|err| ApiError {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        })?;

    Ok(RegistrationResponse {
        uuid: aci.into(),
        pni: account.pni().into(),
        number: phone_number.to_owned(),
        username_hash: None,
        storage_capable: true,
    })
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
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
    authenticated_device: AuthenticatedDevice,
    Path(destination_identifier): Path<String>,
    Json(payload): Json<SignalMessages>,
) -> Result<SendMessageResponse, ApiError> {
    let destination_identifier = parse_service_id(destination_identifier)?;
    handle_put_messages(
        &state,
        &authenticated_device,
        &destination_identifier,
        payload,
    )
    .await
}

/// Handler for the GET v1/messages endpoint.
#[debug_handler]
async fn get_messages_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
) {
    // TODO: Call `handle_get_messages`
}

/// Handler for the POST v1/registration endpoint.
#[debug_handler]
async fn post_registration_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
    headers: HeaderMap,
    Json(registration): Json<RegistrationRequest>,
) -> Result<Json<RegistrationResponse>, ApiError> {
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

    handle_post_registration(state, auth_header, registration)
        .await
        .map(Json)
}

/// Handler for the GET v2/keys endpoint.
#[debug_handler]
async fn get_keys_endpoint(State(state): State<SignalServerState<PostgresDatabase, WebSocket>>) {
    // TODO: Call `handle_get_keys`
}

/// Handler for the POST v2/keys/check endpoint.
#[debug_handler]
async fn post_keycheck_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
) {
    // TODO: Call `handle_post_keycheck`
}

/// Handler for the PUT v2/keys endpoint.
#[debug_handler]
async fn put_keys_endpoint(State(state): State<SignalServerState<PostgresDatabase, WebSocket>>) {
    // TODO: Call `handle_put_keys`
}

/// Handler for the DELETE v1/accounts/me endpoint.
#[debug_handler]
async fn delete_account_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
) {
    // TODO: Call `handle_delete_account`
}

/// Handler for the DELETE v1/devices/{device_id} endpoint.
#[debug_handler]
async fn delete_device_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
) {
    // TODO: Call `handle_delete_device`
}

/// Handler for the POST v1/devices/link endpoint.
#[debug_handler]
async fn post_link_device_endpoint(
    State(state): State<SignalServerState<PostgresDatabase, WebSocket>>,
) {
    // TODO: Call `handle_post_link_device`
}

// Websocket upgrade handler '/v1/websocket'
#[debug_handler]
async fn create_websocket_endpoint(
    State(mut state): State<SignalServerState<PostgresDatabase, WebSocket>>,
    authenticated_device: AuthenticatedDevice,
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
        let mut wmgr = state.websocket_manager.clone();
        async move {
            let (sender, receiver) = socket.split();
            let ws = WebSocketConnection::new(
                UserIdentity::AuthenticatedDevice(authenticated_device.into()),
                addr,
                sender,
                state.clone(),
            );
            let addr = ws.protocol_address();
            wmgr.insert(ws, receiver).await;
            let Some(ws) = wmgr.get(&addr).await else {
                println!("ws.on_upgrade: WebSocket does not exist in WebSocketManager");
                return;
            };
            ws.lock().await.send_messages(false).await;
            state
                .message_manager
                .add_message_availability_listener(&addr, ws.clone())
                .await;
            state.client_presence_manager.set_present(&addr, ws).await;
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

    let state = SignalServerState::<PostgresDatabase, WebSocket>::new().await;

    let message_persister = MessagePersister::start(
        state.message_manager.clone(),
        state.message_cache.clone(),
        state.db.clone(),
        state.account_manager.clone(),
    );

    let app = Router::new()
        .route("/", get(|| async { "Hello from Signal Server" }))
        .route("/v1/messages", get(get_messages_endpoint))
        .route("/v1/messages/:destination", put(put_messages_endpoint))
        .route("/v1/registration", post(post_registration_endpoint))
        .route("/v2/keys", get(get_keys_endpoint))
        .route("/v2/keys/check", post(post_keycheck_endpoint))
        .route("/v2/keys", put(put_keys_endpoint))
        .route("/v1/accounts/me", delete(delete_account_endpoint))
        .route("/v1/devices/link", post(post_link_device_endpoint))
        .route("/v1/devices/:device_id", delete(delete_device_endpoint))
        .route("/v1/websocket", any(create_websocket_endpoint))
        .with_state(state)
        /*.layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(trace::DefaultMakeSpan::new().level(Level::DEBUG)), // .on_request(trace::DefaultOnRequest::new().level(Level::TRACE))
                                                                                            // .on_response(trace::DefaultOnResponse::new().level(Level::TRACE))
                                                                                            // .on_body_chunk(trace::DefaultOnBodyChunk::new()),
                )
                .layer(TraceLayer::new_for_grpc()),
        )*/
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

    message_persister.stop().await;

    Ok(())
}

fn time_now() -> Result<u64, ApiError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| ApiError {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            message: "".into(),
        })?
        .as_secs())
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
