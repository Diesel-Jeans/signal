use crate::socket_manager::{signal_ws_connect, SignalStream, SocketManager};
use crate::{client::VerifiedSession, contact_manager::Contact};
use anyhow::{anyhow, Result};
use async_native_tls::{Certificate, TlsConnector};
use common::signalservice::{web_socket_message, WebSocketMessage};
use common::web_api::PreKeyResponse;
use common::websocket::net_helper::create_request;
use common::{
    signalservice::{Envelope, WebSocketRequestMessage, WebSocketResponseMessage},
    web_api::{authorization::BasicAuthorizationHeader, RegistrationRequest, SignalMessages},
};
use http_client::h1::H1Client;
use libsignal_core::{DeviceId, ServiceId};
use prost::Message;
use serde_json::{from_str, to_vec};
use std::collections::HashMap;
use std::{
    env,
    fmt::Display,
    fs,
    io::{Error, ErrorKind},
    sync::Arc,
    time::Duration,
};
use surf::{http::convert::json, Client, Config, Response, StatusCode, Url};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const CLIENT_URI: &str = "/client";
const MSG_URI: &str = "/v1/messages";
const REGISTER_URI: &str = "v1/registration";
const DEVICE_URI: &str = "/device";
const BUNDLE_URI: &str = "/bundle";

pub struct ServerAPI {
    client: Client,
    socket_manager: SocketManager<SignalStream>,
    message_queue: Arc<Mutex<Vec<Result<WebSocketMessage, RecvError>>>>,
    recv_handle: Option<JoinHandle<()>>,
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
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_cert: &str,
    ) -> Result<()>;
    async fn publish_bundle(
        &self,
        uuid: String, //registration_id: u32,
                      //bundle: &PreKeyBundle,
    ) -> Result<Response, Box<dyn std::error::Error>>; // should take keys as parameter or struct
    async fn fetch_bundle(
        &self,
        uuid: String,
    ) -> Result<PreKeyResponse, Box<dyn std::error::Error>>;
    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn register_device(
        &self,
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn send_msg(
        &mut self,
        msg: SignalMessages,
        destination: ServiceId,
    ) -> Result<WebSocketMessage>;
    async fn update_client(
        &self,
        new_client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_client(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_device(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
}

impl Server for ServerAPI {
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        tls_cert: &str,
    ) -> Result<()> {
        if self.socket_manager.is_active().await {
            return Ok(());
        }

        let ws = signal_ws_connect(tls_cert, url, username, password)
            .await
            .expect("Failed to connect");
        let wrap = SignalStream::new(ws);
        self.socket_manager
            .set_stream(wrap)
            .await
            .map_err(|err| anyhow!(err))?;

        let mut receiver = self.socket_manager.subscribe();
        let queue = self.message_queue.clone();
        self.recv_handle = Some(tokio::spawn(async move {
            loop {
                let msg = receiver.recv().await;
                println!("Received message: {:?}", msg);
                queue.lock().await.push(msg);
            }
        }));

        println!("connected!");
        Ok(())
    }
    async fn publish_bundle(
        &self,
        uuid: String, /*, registration_id: u32, bundle: &PreKeyBundle*/
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "key1": "value1"
        });
        let uri = format!("{}/{}", BUNDLE_URI, uuid);
        self.make_request(ReqType::Post(payload), uri).await
    }
    async fn fetch_bundle(
        &self,
        uuid: String,
    ) -> Result<PreKeyResponse, Box<dyn std::error::Error>> {
        let uri = format!("{}/{}/*", BUNDLE_URI, uuid);

        Ok(from_str(
            self.make_request(ReqType::Get, uri)
                .await?
                .body_string()
                .await?
                .as_ref(),
        )?)
    }

    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        _session: Option<&VerifiedSession>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!(registration_request);
        let auth_header = BasicAuthorizationHeader::new(phone_number, 1, password);
        Ok(self
            .client
            .post(REGISTER_URI)
            .body(payload)
            .header("Authorization", auth_header.encode())
            .await?)
    }

    async fn register_device(
        &self,
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client_info.service_id.service_id_string()
        });
        let uri = format!(
            "{}/{}",
            DEVICE_URI,
            client_info.service_id.service_id_string()
        );

        self.make_request(ReqType::Put(payload), uri).await
    }

    async fn send_msg(
        &mut self,
        msg: SignalMessages,
        destination: ServiceId,
    ) -> Result<WebSocketMessage> {
        let payload = to_vec(&msg).unwrap();
        let uri = format!("{}/{}", MSG_URI, destination.service_id_string());
        println!("Sending message to: {}", uri);

        let id = self.socket_manager.next_id();
        Ok(self
            .socket_manager
            .send(id, create_request(id, "PUT", &uri, vec![], Some(payload)))
            .await
            .map_err(|err| anyhow!(err))?)
    }

    async fn update_client(
        &self,
        client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client.service_id.service_id_string()
        });
        self.make_request(ReqType::Put(payload), CLIENT_URI.to_string())
            .await
    }

    async fn delete_client(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": uuid
        });
        let uri = format!("{}/{}", CLIENT_URI, uuid);

        self.make_request(ReqType::Delete(payload), uri).await
    }

    async fn delete_device(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": uuid
        });
        let uri = format!("{}/{}", DEVICE_URI, uuid);

        self.make_request(ReqType::Delete(payload), uri).await
    }
}

impl ServerAPI {
    pub fn new(username: Option<String>, password: String) -> Self {
        let cert_bytes = fs::read("server/cert/rootCA.crt").expect("Could not read certificate.");
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
        Self {
            client,
            socket_manager: SocketManager::new(5),
            message_queue: Arc::default(),
            recv_handle: None,
        }
    }

    async fn make_request(
        &self,
        req_type: ReqType,
        uri: String,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        println!("Sent request {} {}", req_type, uri);
        let mut res = match req_type {
            ReqType::Get => self.client.get(uri),
            ReqType::Post(payload) => self.client.post(uri).body(surf::Body::from_json(&payload)?),
            ReqType::Put(payload) => self.client.put(uri).body(surf::Body::from_json(&payload)?),
            ReqType::Delete(payload) => self
                .client
                .delete(uri)
                .body(surf::Body::from_json(&payload)?),
        }
        .await?;

        match res.status() {
            StatusCode::Ok => Ok(res),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!(
                    "response returned: {:?}\n{}",
                    res.status(),
                    res.body_string().await.unwrap_or("".to_owned())
                ),
            )
            .into()),
        }
    }

    pub async fn get_message(&mut self) -> Option<Envelope> {
        let msg = tokio::time::timeout(Duration::from_secs(1), self.message_queue.lock())
            .await
            .ok()?
            .pop()?;

        println!("Got message");
        if let Ok(msg) = msg {
            match msg.r#type() {
                web_socket_message::Type::Unknown => todo!(),
                web_socket_message::Type::Request => todo!(),
                web_socket_message::Type::Response => Some(
                    Envelope::decode(msg.response.expect("Did not contain promised type.").body())
                        .unwrap(),
                ),
            }
        } else {
            return None;
        }
    }
    async fn get_incoming_messages(&mut self) -> Result<Vec<WebSocketRequestMessage>> {
        todo!()
    }
}
