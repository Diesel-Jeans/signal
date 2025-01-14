use crate::errors::SendMessageError;
use crate::socket_manager::{SignalStream, SocketManager};
use crate::{
    errors::{RegistrationError, SignalClientError},
    persistent_receiver::PersistentReceiver,
    socket_manager::signal_ws_connect,
};
use async_native_tls::{Certificate, TlsConnector};
use common::signalservice::{web_socket_message, WebSocketMessage, WebSocketRequestMessage};
use common::web_api::{
    authorization::BasicAuthorizationHeader, PreKeyResponse, RegistrationRequest,
    RegistrationResponse,
};
use common::web_api::{SetKeyRequest, SignalMessages};
use common::websocket::net_helper::{create_request, create_response};
use http_client::h1::H1Client;
use libsignal_core::{Aci, DeviceId, ServiceId};
use libsignal_protocol::PreKeyBundle;
use serde_json::{from_slice, to_vec};
use std::error::Error;
use std::fmt::Display;
use std::{fmt::Debug, fs, sync::Arc, time::Duration};
use surf::{http::convert::json, Client, Config, Url};
use surf::{Response, StatusCode};

const REGISTER_URI: &str = "v1/registration";
const MSG_URI: &str = "/v1/messages";
const KEY_BUNDLE_URI: &str = "/v2/keys";

#[allow(unused)]
pub struct VerifiedSession {
    session_id: String,
}

#[allow(unused)]
impl VerifiedSession {
    pub fn session_id(&self) -> &String {
        &self.session_id
    }
}

pub trait SignalServerAPI {
    /// Connect with Websockets to the backend.
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), SignalClientError>;

    /// Publish a sigle [PreKeyBundle] for this device.
    async fn publish_pre_key_bundle(
        &mut self,
        pre_key_bundle: SetKeyRequest,
    ) -> Result<(), SignalClientError>;

    /// Fetch [PreKeyBundle] for all of a users devices.
    async fn fetch_pre_key_bundles(
        &self,
        service_id: &ServiceId,
    ) -> Result<Vec<PreKeyBundle>, SignalClientError>;

    /// Send a [RegistrationRequest] to the server.
    /// Verifying the session is not implemented.
    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
    ) -> Result<RegistrationResponse, SignalClientError>;

    /// Send a message to another user.
    async fn send_msg(
        &mut self,
        messages: &SignalMessages,
        service_id: &ServiceId,
    ) -> Result<(), SignalClientError>;

    async fn get_message(&mut self) -> Option<WebSocketRequestMessage>;

    async fn send_response(
        &mut self,
        request: WebSocketRequestMessage,
        status_code: axum::http::StatusCode,
    ) -> Result<(), SignalClientError>;

    fn create_auth_header(&mut self, aci: Aci, password: String, device_id: DeviceId) -> ();
}

pub struct SignalServer {
    auth_header: Option<BasicAuthorizationHeader>,
    http_client: Client,
    socket_manager: SocketManager<SignalStream>,
    message_queue: PersistentReceiver<WebSocketMessage>,
}

enum ReqType {
    Get,
    Post(serde_json::Value),
    Put(serde_json::Value),
    Delete(serde_json::Value),
}

impl Display for ReqType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ReqType::Get => "GET",
                ReqType::Post(_) => "POST",
                ReqType::Put(_) => "PUT",
                ReqType::Delete(_) => "DELETE",
            }
        )
    }
}

impl SignalServerAPI for SignalServer {
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), SignalClientError> {
        if self.socket_manager.is_active().await {
            return Ok(());
        }
        let ws = signal_ws_connect(tls_path, url, username, password)
            .await
            .map_err(SignalClientError::WebSocketError)?;
        let ws = SignalStream::new(ws);
        self.socket_manager
            .set_stream(ws)
            .await
            .map_err(SignalClientError::WebSocketError)?;
        Ok(())
    }

    async fn publish_pre_key_bundle(
        &mut self,
        pre_key_bundle: SetKeyRequest,
    ) -> Result<(), SignalClientError> {
        let uri = format!("{}?identity=aci", KEY_BUNDLE_URI);
        self.make_request(ReqType::Put(json!(pre_key_bundle)), uri)
            .await
            .map_err(|err| SignalClientError::KeyError(err.to_string()))?;
        Ok(())
    }

    async fn fetch_pre_key_bundles(
        &self,
        service_id: &ServiceId,
    ) -> Result<Vec<PreKeyBundle>, SignalClientError> {
        let uri = format!("{}/{}/*", KEY_BUNDLE_URI, service_id.service_id_string());

        let mut res = self
            .make_request(ReqType::Get, uri)
            .await
            .map_err(|err| SignalClientError::KeyError(err.to_string()))?;

        let pre_key_res: PreKeyResponse = res
            .body_json()
            .await
            .map_err(|err| SignalClientError::KeyError(err.to_string()))?;

        let bundle: Vec<PreKeyBundle> = Vec::<PreKeyBundle>::try_from(pre_key_res)
            .map_err(|err| SignalClientError::KeyError(err.to_string()))?;

        Ok(bundle)
    }

    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        _session: Option<&VerifiedSession>,
    ) -> Result<RegistrationResponse, SignalClientError> {
        let payload = json!(registration_request);
        let auth_header = BasicAuthorizationHeader::new(phone_number, 1, password);
        let mut res = self
            .http_client
            .post(REGISTER_URI)
            .body(payload)
            .header("Authorization", auth_header.encode())
            .await
            .map_err(|_| RegistrationError::NoResponse)?;
        println!("Sent POST request to /{}", REGISTER_URI);
        if res.status().is_success() {
            Ok(from_slice(
                res.body_bytes()
                    .await
                    .map_err(|err| RegistrationError::BadResponse(format!("{err}")))?
                    .as_ref(),
            )
            .map_err(|err| RegistrationError::BadResponse(format!("{err}")))?)
        } else {
            Err(SignalClientError::RegistrationError(
                RegistrationError::BadResponse(format!(
                    "Received {}: {:?}",
                    res.status(),
                    res.body_string().await
                )),
            ))
        }
    }

    async fn send_msg(
        &mut self,
        messages: &SignalMessages,
        recipient: &ServiceId,
    ) -> Result<(), SignalClientError> {
        let payload = to_vec(&messages).unwrap();
        let uri = format!("{}/{}", MSG_URI, recipient.service_id_string());
        println!("Sending message to: {}", uri);

        let id = self.socket_manager.next_id();
        let response = self
            .socket_manager
            .send(id, create_request(id, "PUT", &uri, vec![], Some(payload)))
            .await
            .map_err(SendMessageError::WebSocketError)?;

        Ok(())
    }

    // FIX:
    async fn send_response(
        &mut self,
        request: WebSocketRequestMessage,
        status_code: axum::http::StatusCode,
    ) -> Result<(), SignalClientError> {
        let id = request.id.expect("This is always some");
        self.socket_manager
            .send_response(
                create_response(id, status_code, vec![], None).expect("This always goes well"),
            )
            .await
            .map_err(SendMessageError::WebSocketError)?;

        Ok(())
    }

    async fn get_message(&mut self) -> Option<WebSocketRequestMessage> {
        self.message_queue.recv().await?.request
    }

    fn create_auth_header(&mut self, aci: Aci, password: String, device_id: DeviceId) -> () {
        self.auth_header = Some(BasicAuthorizationHeader::new(
            aci.service_id_string(),
            device_id.into(),
            password.to_string(),
        ));
    }
}

impl SignalServer {
    pub fn new(cert_path: &str, server_url: &str) -> Self {
        let cert_bytes = fs::read(cert_path).expect("Could not read certificate.");

        let crt = Certificate::from_pem(&cert_bytes).expect("Could not parse certificate.");

        let tls_config = Arc::new(TlsConnector::new().add_root_certificate(crt));
        let http_client: H1Client = http_client::Config::new()
            .set_timeout(Some(Duration::from_secs(5)))
            .set_tls_config(Some(tls_config))
            .try_into()
            .expect("Could not create HTTP client");
        let http_client = Config::new()
            .set_http_client(http_client)
            .set_base_url(Url::parse(server_url).expect("Could not parse URL for server"))
            .try_into()
            .expect("Could not connect to server.");

        let socket_mgr = SocketManager::new(16);

        let filter = |x: &WebSocketMessage| -> Option<WebSocketMessage> {
            if x.r#type() != web_socket_message::Type::Request || x.request.is_none() {
                None
            } else if x.request.as_ref().unwrap().path() == "/api/v1/message"
                && x.request.as_ref().unwrap().verb() == "PUT"
            {
                Some(x.clone())
            } else {
                None
            }
        };

        let msg_queue = PersistentReceiver::new(socket_mgr.subscribe(), Some(filter));

        Self {
            auth_header: None,
            http_client,
            socket_manager: socket_mgr,
            message_queue: msg_queue,
        }
    }

    fn create_auth_header(&mut self, aci: Aci, password: &str, device_id: DeviceId) -> () {
        self.auth_header = Some(BasicAuthorizationHeader::new(
            aci.service_id_string(),
            device_id.into(),
            password.to_string(),
        ));
    }
}

#[derive(Debug)]
enum ServerRequestError {
    /// The status code was not 200 - OK
    StatusCodeError(StatusCode, String),
    BodyDecodeError(String),
    TransmissionError(String),
    NoAuthDevice,
}
impl Display for ServerRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusCodeError(code, body) => write!(f, "Response was {}: {}", code, body),
            Self::BodyDecodeError(err) => {
                write!(f, "Could not decode response body: {err}")
            }
            Self::TransmissionError(err) => {
                write!(f, "HTTP communication with server failed: {err}")
            }
            Self::NoAuthDevice => {
                write!(
                    f,
                    "You cannot make requests without an authentication device."
                )
            }
        }
    }
}

impl Error for ServerRequestError {}

impl SignalServer {
    async fn make_request(
        &self,
        req_type: ReqType,
        uri: String,
    ) -> Result<Response, ServerRequestError> {
        println!("Sent {} request to {}", req_type, uri);
        let header = match &self.auth_header {
            Some(header) => header,
            None => Err(ServerRequestError::NoAuthDevice)?,
        };
        let mut res = match req_type {
            ReqType::Get => self
                .http_client
                .get(uri)
                .header("Authorization", header.encode()),
            ReqType::Post(payload) => self
                .http_client
                .post(uri)
                .body(
                    surf::Body::from_json(&payload)
                        .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
                )
                .header("Authorization", header.encode()),
            ReqType::Put(payload) => self
                .http_client
                .put(uri)
                .body(
                    surf::Body::from_json(&payload)
                        .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
                )
                .header("Authorization", header.encode()),
            ReqType::Delete(payload) => self
                .http_client
                .delete(uri)
                .body(
                    surf::Body::from_json(&payload)
                        .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
                )
                .header("Authorization", header.encode()),
        }
        .await
        .map_err(|err| ServerRequestError::TransmissionError(format!("{err}")))?;

        match res.status() {
            StatusCode::Ok => Ok(res),
            _ => {
                println!(
                    "Response code {}: {:?}",
                    res.status(),
                    res.body_string().await.unwrap().to_string()
                );
                Err(ServerRequestError::StatusCodeError(
                    res.status(),
                    res.body_string().await.unwrap_or("".to_owned()),
                ))
            }
        }
    }
}
