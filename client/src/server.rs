use crate::{
    client::VerifiedSession,
    contact_manager::Contact,
    errors::{RegistrationError, SignalClientError},
    websockets::{KeepAliveOptions, SendRequestOptions, WebsocketHandler},
};
use anyhow::Result;
use async_native_tls::{Certificate, TlsConnector};
use common::{
    signalservice::{WebSocketRequestMessage, WebSocketResponseMessage},
    web_api::{
        authorization::BasicAuthorizationHeader, AccountAttributes, RegistrationRequest,
        RegistrationResponse, UploadSignedPreKey,
    },
};
use http_client::h1::H1Client;
use libsignal_protocol::PreKeyBundle;
use serde_json::from_slice;
use std::{env, error::Error, fmt::Display, fs, sync::Arc, time::Duration};
use surf::{http::convert::json, Client, Config, Response, StatusCode, Url};

const CLIENT_URI: &str = "/client";
const MSG_URI: &str = "v1/messages";
const REGISTER_URI: &str = "v1/registration";
const DEVICE_URI: &str = "/device";
const BUNDLE_URI: &str = "/bundle";

pub struct ServerAPI {
    client: Client,
    ws: Option<WebsocketHandler>,
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
        port: &str,
    ) -> Result<(), Self::Error>;
    async fn publish_bundle(&self, uuid: String) -> Result<(), Self::Error>;
    async fn fetch_bundle(&self, uuid: String) -> Result<PreKeyBundle, Self::Error>;
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
    fn new() -> Self;
}

impl Server for ServerAPI {
    type Error = SignalClientError;
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        port: &str,
    ) -> Result<(), Self::Error> {
        todo!("Implment when websockets are implemented");
        Ok(())
    }
    async fn publish_bundle(&self, uuid: String) -> Result<(), Self::Error> {
        let payload = json!({
            "key1": "value1"
        });
        let uri = format!("{}/{}", BUNDLE_URI, uuid);
        self.make_request(ReqType::Post(payload), uri).await;
        todo!("Handle response")
    }
    async fn fetch_bundle(&self, uuid: String) -> Result<PreKeyBundle, Self::Error> {
        let uri = format!("{}/{}", BUNDLE_URI, uuid);
        self.make_request(ReqType::Get, uri).await;
        todo!("Handle the response")
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

    async fn send_msg(
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<(), Self::Error> {
        todo!("Needs Websockets")
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
        ServerAPI { client, ws: None }
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

    async fn get_incoming_messages(&mut self) -> Result<Vec<WebSocketRequestMessage>> {
        match &self.ws {
            Some(ws) => Ok(ws.clone().get_messages().await),
            None => Err(anyhow::anyhow!("No websocket connection is active")),
        }
    }
}
