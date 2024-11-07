use crate::client::VerifiedSession;
use crate::contact_manager::Contact;
use async_native_tls::{Certificate, TlsConnector};
use common::web_api::authorization::BasicAuthorizationHeader;
use common::web_api::{AccountAttributes, RegistrationRequest, UploadSignedPreKey};
use http::StatusCode;
use http_client::h1::H1Client;
use libsignal_protocol::IdentityKey;
use std::fmt::Display;
use std::io::{BufReader, Error, ErrorKind, Read};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};
use surf::http::convert::json;
use surf::{http, Client, Config, HttpClient, RequestBuilder, Response, Url};
use tokio_tungstenite::connect_async;

const CLIENT_URI: &str = "/client";
const MSG_URI: &str = "v1/messages";
const REGISTER_URI: &str = "v1/registration";
const DEVICE_URI: &str = "/device";
const BUNDLE_URI: &str = "/bundle";

pub struct ServerAPI {
    client: Client,
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
    async fn connect();
    async fn publish_bundle(
        &self,
        uuid: String, //registration_id: u32,
                      //bundle: &PreKeyBundle,
    ) -> Result<Response, Box<dyn std::error::Error>>; // should take keys as parameter or struct
    async fn fetch_bundle(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
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
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn update_client(
        &self,
        new_client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_client(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_device(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    fn new() -> Self;
}

impl Server for ServerAPI {
    async fn connect() {
        let server_url = "ws://127.0.0.1:4444";
        let (ws, _) = connect_async(server_url).await.expect("Failed to connect");

        println!("connected!");
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
    async fn fetch_bundle(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>> {
        let uri = format!("{}/{}", BUNDLE_URI, uuid);
        self.make_request(ReqType::Get, uri).await
    }

    async fn register_client(
        &self,
        phone_number: String,
        password: String,
        registration_request: RegistrationRequest,
        session: Option<&VerifiedSession>,
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
            "uuid": client_info.uuid
        });
        let uri = format!("{}/{}", DEVICE_URI, client_info.uuid);

        self.make_request(ReqType::Put(payload), uri).await
    }

    async fn send_msg(
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "message": msg
        });
        let uri = format!("{}/{}.{}", MSG_URI, user_id, device_id);

        self.make_request(ReqType::Put(payload), uri).await
    }

    async fn update_client(
        &self,
        client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client.uuid
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
        ServerAPI { client }
    }
}
impl ServerAPI {
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
}
