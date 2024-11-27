use crate::persistent_receiver::PersistentReceiver;
use crate::socket_manager::{signal_ws_connect, SignalStream, SocketManager};
use crate::{
    client::VerifiedSession,
    contact_manager::Contact,
    errors::{RegistrationError, SignalClientError},
};
use anyhow::Result;
use async_native_tls::{Certificate, TlsConnector};
use common::signalservice::{web_socket_message, Envelope, WebSocketMessage};
use common::web_api::{
    authorization::BasicAuthorizationHeader, PreKeyResponse, RegistrationRequest,
    RegistrationResponse, SetKeyRequest,
};
use http_client::h1::H1Client;
use libsignal_protocol::PreKeyBundle;
use prost::Message as _;
use serde_json::from_slice;
use std::{env, error::Error, fmt::Display, fs, sync::Arc, time::Duration};
use surf::{http::convert::json, Client, Config, Response, StatusCode, Url};

const CLIENT_URI: &str = "/client";
const MSG_URI: &str = "v1/messages";
const REGISTER_URI: &str = "v1/registration";
const DEVICE_URI: &str = "/device";
const KEY_BUNDLE_URI: &str = "/v2/keys";

pub struct ServerAPI {
    client: Client,
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

pub trait Server {
    type Error;
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), Self::Error>;
    async fn publish_bundle(&self, bundle: SetKeyRequest) -> Result<(), Self::Error>;
    async fn fetch_bundle(
        &self,
        account_id: String,
        device_id: String,
    ) -> Result<Vec<PreKeyBundle>, Self::Error>;
    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
    ) -> Result<RegistrationResponse, Self::Error>;
    async fn register_device(&self, client_info: &Contact) -> Result<(), Self::Error>;
    async fn send_msg(
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<(), Self::Error>;
    async fn update_client(&self, new_client: &Contact) -> Result<(), Self::Error>;
    async fn delete_client(&self, uuid: String) -> Result<(), Self::Error>;
    async fn delete_device(&self, uuid: String) -> Result<(), Self::Error>;
    async fn get_message(&mut self) -> Option<Envelope>;
    fn new() -> Self;
}

impl Server for ServerAPI {
    type Error = SignalClientError;
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_path: &str,
    ) -> Result<(), Self::Error> {
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

    async fn send_msg(
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<(), Self::Error> {
        todo!("Needs Websockets")
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

    async fn publish_bundle(&self, bundle: SetKeyRequest) -> Result<(), Self::Error> {
        self.make_request(ReqType::Put(json!(bundle)), KEY_BUNDLE_URI.to_string())
            .await
            .map_err(|err| SignalClientError::KeyError(err.to_string()))?;
        Ok(())
    }
    async fn fetch_bundle(
        &self,
        account_id: String,
        device_id: String,
    ) -> Result<Vec<PreKeyBundle>, Self::Error> {
        let uri = format!("{}/{}/{}", KEY_BUNDLE_URI, account_id, device_id);

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
    ) -> Result<RegistrationResponse, Self::Error> {
        let payload = json!(registration_request);
        let auth_header = BasicAuthorizationHeader::new(phone_number, 1, password);
        let mut res = self
            .client
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

    async fn register_device(&self, client_info: &Contact) -> Result<(), Self::Error> {
        let payload = json!({
            "uuid": client_info.service_id.service_id_string()
        });
        let uri = format!(
            "{}/{}",
            DEVICE_URI,
            client_info.service_id.service_id_string()
        );

        self.make_request(ReqType::Put(payload), uri).await;
        todo!("Handle the response")
    }

    async fn update_client(&self, client: &Contact) -> Result<(), Self::Error> {
        let payload = json!({
            "uuid": client.service_id.service_id_string()
        });
        self.make_request(ReqType::Put(payload), CLIENT_URI.to_string())
            .await;
        todo!("Handle the response")
    }

    async fn delete_client(&self, uuid: String) -> Result<(), Self::Error> {
        let payload = json!({
            "uuid": uuid
        });
        let uri = format!("{}/{}", CLIENT_URI, uuid);

        self.make_request(ReqType::Delete(payload), uri).await;
        todo!("Handle the response")
    }

    async fn delete_device(&self, uuid: String) -> Result<(), Self::Error> {
        let payload = json!({
            "uuid": uuid
        });
        let uri = format!("{}/{}", DEVICE_URI, uuid);

        self.make_request(ReqType::Delete(payload), uri).await;
        todo!("Handle the response")
    }

    fn new() -> Self {
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
        let client = Config::new()
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

        ServerAPI {
            client,
            socket_manager: socket_mgr,
            message_queue: msg_queue,
        }
    }
}

#[derive(Debug)]
enum ServerRequestError {
    /// The status code was not 200 - OK
    StatusCodeError(StatusCode, String),
    BodyDecodeError(String),
    TransmissionError(String),
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
        }
    }
}

impl Error for ServerRequestError {}

impl ServerAPI {
    async fn make_request(
        &self,
        req_type: ReqType,
        uri: String,
    ) -> Result<Response, ServerRequestError> {
        println!("Sent {} request to {}", req_type, uri);
        let mut res = match req_type {
            ReqType::Get => self.client.get(uri),
            ReqType::Post(payload) => self.client.post(uri).body(
                surf::Body::from_json(&payload)
                    .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
            ),
            ReqType::Put(payload) => self.client.put(uri).body(
                surf::Body::from_json(&payload)
                    .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
            ),
            ReqType::Delete(payload) => self.client.delete(uri).body(
                surf::Body::from_json(&payload)
                    .map_err(|err| ServerRequestError::BodyDecodeError(format!("{err}")))?,
            ),
        }
        .await
        .map_err(|err| ServerRequestError::TransmissionError(format!("{err}")))?;

        match res.status() {
            StatusCode::Ok => Ok(res),
            _ => Err(ServerRequestError::StatusCodeError(
                res.status(),
                res.body_string().await.unwrap_or("".to_owned()),
            )),
        }
    }
}
