use crate::{
    errors::{RegistrationError, SignalClientError},
    persistent_receiver::PersistentReceiver,
    socket_manager::{signal_ws_connect, SignalStream, SocketManager},
};
use async_native_tls::{Certificate, TlsConnector};
use common::web_api::SignalMessages;
use common::{
    signalservice::{web_socket_message, Envelope, WebSocketMessage},
    web_api::{authorization::BasicAuthorizationHeader, RegistrationRequest, RegistrationResponse},
};
use http_client::h1::H1Client;
use libsignal_core::ServiceId;
use libsignal_protocol::PreKeyBundle;
use serde_json::{from_slice, json};
use std::{env, fmt::Debug, fs, sync::Arc, time::Duration};
use surf::{Client, Config};
use url::Url;

const REGISTER_URI: &str = "v1/registration";

pub struct VerifiedSession {
    session_id: String,
}

impl VerifiedSession {
    pub fn session_id(&self) -> &String {
        &self.session_id
    }
}

pub trait Backend {
    /// Connect with Websockets to the backend.
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), SignalClientError>;

    /// Publish a sigle [PreKeyBundle] for this device.
    async fn publish_pre_key_bundle(&mut self, uuid: String) -> Result<(), SignalClientError>;

    /// Fetch [PreKeyBundle] for all of a users devices.
    async fn fetch_pre_key_bundles(&self, uuid: String) -> Result<PreKeyBundle, SignalClientError>;

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
        &self,
        messages: SignalMessages,
        service_id: ServiceId,
    ) -> Result<(), SignalClientError>;

    async fn get_message(&mut self) -> Option<Envelope>;
}

#[derive(Debug)]
pub struct ServerAPI<T: Backend> {
    backend: T,
}

impl<T: Backend> ServerAPI<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }
    pub async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), SignalClientError> {
        self.backend
            .connect(username, password, url, tls_path)
            .await
    }

    pub async fn publish_pre_key_bundle(&mut self, uuid: String) -> Result<(), SignalClientError> {
        todo!()
    }

    pub async fn fetch_pre_key_bundles(
        &self,
        uuid: String,
    ) -> Result<Vec<PreKeyBundle>, SignalClientError> {
        todo!()
    }

    pub async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
    ) -> Result<RegistrationResponse, SignalClientError> {
        self.backend
            .register_client(phone_number, password, registration_request, session)
            .await
    }

    pub async fn send_msg(
        &self,
        messages: SignalMessages,
        user_id: String,
    ) -> Result<(), SignalClientError> {
        todo!()
    }

    pub async fn get_message(&mut self) -> Option<Envelope> {
        todo!()
    }
}

pub struct SignalBackend {
    http_client: Client,
    socket_manager: SocketManager<SignalStream>,
    message_queue: PersistentReceiver<WebSocketMessage>,
}

impl Backend for SignalBackend {
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

    async fn publish_pre_key_bundle(&mut self, uuid: String) -> Result<(), SignalClientError> {
        todo!()
    }

    async fn fetch_pre_key_bundles(&self, uuid: String) -> Result<PreKeyBundle, SignalClientError> {
        todo!()
    }

    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
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
        Ok(from_slice(
            res.body_bytes()
                .await
                .map_err(|_| RegistrationError::BadResponse)?
                .as_ref(),
        )
        .map_err(|_| RegistrationError::BadResponse)?)
    }

    async fn send_msg(
        &self,
        messages: SignalMessages,
        recipient: ServiceId,
    ) -> Result<(), SignalClientError> {
        todo!()
    }

    async fn get_message(&mut self) -> Option<Envelope> {
        todo!()
    }
}

impl SignalBackend {
    pub fn new() -> Self {
        let cert_bytes =
            fs::read("../server/cert/rootCA.crt").expect("Could not read certificate.");

        let crt = Certificate::from_pem(&cert_bytes).expect("Could not parse certificate.");

        let address =
            env::var("SERVER_URL").expect("Could not read SERVER_URL environment variable.");

        let tls_config = Arc::new(TlsConnector::new().add_root_certificate(crt));
        let http_client: H1Client = http_client::Config::new()
            .set_timeout(Some(Duration::from_secs(5)))
            .set_tls_config(Some(tls_config))
            .try_into()
            .expect("Could not create HTTP client");
        let http_client = Config::new()
            .set_http_client(http_client)
            .set_base_url(Url::parse(&address).expect("Could not parse URL for server"))
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
            http_client,
            socket_manager: socket_mgr,
            message_queue: msg_queue,
        }
    }
}
