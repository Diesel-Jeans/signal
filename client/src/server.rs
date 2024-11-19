use crate::{
    client::VerifiedSession,
    contact_manager::Contact,
    websockets::{KeepAliveOptions, SendRequestOptions, WebsocketHandler},
};
use anyhow::Result;
use async_native_tls::{Certificate, TlsConnector};
use common::{
    signal_protobuf::{WebSocketRequestMessage, WebSocketResponseMessage},
    web_api::{authorization::BasicAuthorizationHeader, RegistrationRequest},
};
use http_client::h1::H1Client;
use std::{
    env,
    fmt::Display,
    fs,
    io::{Error, ErrorKind},
    sync::Arc,
    time::Duration,
};
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
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        port: &str,
    ) -> Result<()>;
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
    ) -> Result<WebSocketResponseMessage>;
    async fn update_client(
        &self,
        new_client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_client(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_device(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    fn new() -> Self;
}

impl Server for ServerAPI {
    async fn connect(
        &mut self,
        username: &str,
        password: &str,
        url: &str,
        port: &str,
    ) -> Result<()> {
        let options = KeepAliveOptions {
            path: Some("/v1/keepalive".to_string()),
        };
        let ws = WebsocketHandler::try_new(
            Some(options),
            url.into(),
            port.into(),
            username.into(),
            password.into(),
        )
        .await?;
        self.ws = Some(ws);

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
        &self,
        msg: String,
        user_id: String,
        device_id: u32,
    ) -> Result<WebSocketResponseMessage> {
        let payload = json!({
            "message": msg
        })
        .to_string()
        .as_bytes()
        .to_vec();
        let uri = format!("{}/{}.{}", MSG_URI, user_id, device_id);
        let options = SendRequestOptions::new("PUT", uri, payload);

        match &self.ws {
            Some(ws) => Ok(ws.clone().send_request(options).await?),
            None => Err(anyhow::anyhow!("No websocket connection is active")),
        }
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

    async fn get_incoming_messages(&mut self) -> Result<Vec<WebSocketRequestMessage>> {
        match &self.ws {
            Some(ws) => Ok(ws.clone().get_messages().await),
            None => Err(anyhow::anyhow!("No websocket connection is active")),
        }
    }
}
