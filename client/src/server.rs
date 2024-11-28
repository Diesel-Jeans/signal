use crate::errors::SendMessageError;
use crate::socket_manager::{SignalStream, SocketManager};
use crate::{
    errors::{RegistrationError, SignalClientError},
    persistent_receiver::PersistentReceiver,
    socket_manager::signal_ws_connect,
};
use async_native_tls::{Certificate, TlsConnector};
use common::signalservice::{web_socket_message, Envelope, WebSocketMessage};
use common::web_api::{
    authorization::BasicAuthorizationHeader, PreKeyResponse, RegistrationRequest,
    RegistrationResponse,
};
use common::web_api::{SetKeyRequest, SignalMessages};
use common::websocket::net_helper::create_request;
use http_client::h1::H1Client;
use libsignal_core::{Aci, DeviceId, ServiceId};
use libsignal_protocol::PreKeyBundle;
use prost::Message;
use serde_json::{from_slice, to_vec};
use std::error::Error;
use std::fmt::Display;
use std::{env, fmt::Debug, fs, sync::Arc, time::Duration};
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
        messages: SignalMessages,
        service_id: &ServiceId,
    ) -> Result<(), SignalClientError>;

    async fn get_message(&mut self) -> Option<Envelope>;
    fn create_auth_header(&mut self, aci: Aci, password: String, device_id: DeviceId) -> ();
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

    pub async fn publish_pre_key_bundle(
        &mut self,
        pre_key_bundle: SetKeyRequest,
    ) -> Result<(), SignalClientError> {
        self.backend.publish_pre_key_bundle(pre_key_bundle).await
    }

    pub async fn fetch_pre_key_bundles(
        &self,
        service_id: &ServiceId,
    ) -> Result<Vec<PreKeyBundle>, SignalClientError> {
        self.backend.fetch_pre_key_bundles(service_id).await
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
        &mut self,
        messages: SignalMessages,
        service_id: &ServiceId,
    ) -> Result<(), SignalClientError> {
        self.backend.send_msg(messages, service_id).await
    }

    pub async fn get_message(&mut self) -> Option<Envelope> {
        self.backend.get_message().await
    }
    pub fn create_auth_header(&mut self, aci: Aci, password: String, device_id: DeviceId) -> () {
        self.backend.create_auth_header(aci, password, device_id);
    }
}

pub struct SignalBackend {
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

    async fn publish_pre_key_bundle(
        &mut self,
        pre_key_bundle: SetKeyRequest,
    ) -> Result<(), SignalClientError> {
        let uri = format!("{}?identity_type=aci", KEY_BUNDLE_URI);
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
        if res.status().is_success() {
            Ok(from_slice(
                res.body_bytes()
                    .await
                    .map_err(|err| RegistrationError::BadResponse(format!("{err}")))
                    .expect("There")
                    .as_ref(),
            )
            .map_err(|err| RegistrationError::BadResponse(format!("{err}")))
            .expect("Here"))
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
        messages: SignalMessages,
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

        // TODO handle send went wrong.
        Ok(())
    }

    async fn get_message(&mut self) -> Option<Envelope> {
        let x = self.message_queue.recv().await?;

        let req = match x.request {
            Some(x) => x,
            None => return None,
        };

        match Envelope::decode(req.body()) {
            Ok(e) => Some(e),
            Err(e) => {
                println!("Failed to decode envelope: {}", e);
                None
            }
        }
    }

    fn create_auth_header(&mut self, aci: Aci, password: String, device_id: DeviceId) -> () {
        self.auth_header = Some(BasicAuthorizationHeader::new(
            aci.service_id_string(),
            device_id.into(),
            password.to_string(),
        ));
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
/*
#[cfg(test)]
pub mod server_api_test {
    use super::Backend;
    use crate::errors::SignalClientError;
    use common::{
        signalservice::Envelope,
        web_api::{SetKeyRequest, SignalMessages},
    };
    use core::panic;
    use libsignal_core::{ProtocolAddress, ServiceId};
    use libsignal_protocol::PreKeyBundle;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Default)]
    pub struct MockBackendState {
        pre_key_bundles: HashMap<String, Vec<PreKeyBundle>>,
        message_queues: HashMap<ProtocolAddress, Vec<Envelope>>,
    }

    pub struct MockBackend {
        address: ProtocolAddress,
        state: Arc<Mutex<MockBackendState>>,
    }

    impl Backend for MockBackend {
        async fn connect(
            &mut self,
            username: &str,
            password: &str,
            url: &str,
            tls_path: &str,
        ) -> Result<(), SignalClientError> {
            Ok(())
        }

        async fn publish_pre_key_bundle(
            &mut self,
            pre_key_bundle: SetKeyRequest,
        ) -> Result<(), SignalClientError> {
            if !self
                .state
                .lock()
                .await
                .pre_key_bundles
                .entry(self.address.name().to_owned())
                .or_insert(vec![])
                .iter()
                .find(|x| x.device_id().unwrap() == pre_key_bundle.device_id().unwrap())
                .is_none()
            {
                panic!("Cannot publish bundle twice for client. Not supported.")
            }
            self.state
                .lock()
                .await
                .pre_key_bundles
                .get_mut(&self.address.name().to_owned())
                .unwrap()
                .push(pre_key_bundle);
            Ok(())
        }

        async fn fetch_pre_key_bundles(
            &self,
            service_id: &ServiceId,
        ) -> Result<Vec<PreKeyBundle>, SignalClientError> {
            Ok(self
                .state
                .lock()
                .await
                .pre_key_bundles
                .get(&service_id.service_id_string())
                .unwrap()
                .clone())
        }

        async fn register_client(
            &self,
            phone_number: String,
            password: String,
            registration_request: common::web_api::RegistrationRequest,
            session: Option<&super::VerifiedSession>,
        ) -> Result<common::web_api::RegistrationResponse, SignalClientError> {
            todo!()
        }

        async fn send_msg(
            &mut self,
            messages: SignalMessages,
            service_id: &ServiceId,
        ) -> Result<(), SignalClientError> {
            for message in messages.messages {
                let envelope = Envelope::builder()
                    .r#type(message.r#type)
                    .content(message.content.as_bytes().to_vec())
                    .source_service_id(self.address.name().to_owned())
                    .source_device(self.address.device_id().into())
                    .build();
                self.state
                    .lock()
                    .await
                    .message_queues
                    .entry(ProtocolAddress::new(
                        service_id.service_id_string(),
                        message.destination_device_id.into(),
                    ))
                    .or_insert(vec![])
                    .push(envelope);
            }
            Ok(())
        }

        async fn get_message(&mut self) -> Option<common::signalservice::Envelope> {
            self.state
                .lock()
                .await
                .message_queues
                .get_mut(&self.address)
                .unwrap()
                .pop()
        }

        fn create_auth_header(
            &mut self,
            aci: libsignal_core::Aci,
            password: &str,
            device_id: libsignal_core::DeviceId,
        ) -> () {
            todo!()
        }

        fn new() -> Self {
            todo!()
        }
    }

    impl MockBackend {
        pub fn new(address: ProtocolAddress, state: Arc<Mutex<MockBackendState>>) -> Self {
            Self { address, state }
        }
    }
}
*/

impl SignalBackend {
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
