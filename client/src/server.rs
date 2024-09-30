use crate::contact_manager::Contact;
use http::StatusCode;
use libsignal_protocol::*;
use std::time::Duration;
use surf::http::convert::json;
use surf::{http, Client, Config, Response, Url};
use tokio_tungstenite::connect_async;

const CLIENT_URI: &str = "/client";
const MSG_URI: &str = "/message";
const DEVICE_URI: &str = "/device";
const BUNDLE_URI: &str = "/bundle";

pub struct ServerAPI {
    pub client: Client,
}

enum ReqType {
    Get,
    Post(serde_json::Value),
    Put(serde_json::Value),
    Delete(serde_json::Value),
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
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn register_device(
        &self,
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn send_msg(
        &self,
        msg: String,
        uuid: String,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn update_client(
        &self,
        new_client: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_client(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    async fn delete_device(&self, uuid: String) -> Result<Response, Box<dyn std::error::Error>>;
    fn new() -> Result<ServerAPI, Box<dyn std::error::Error>>;
}

impl Server for ServerAPI {
    async fn connect() {
        let server_url = "ws://127.0.0.1:12345";
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
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "aci": client_info.uuid // TODO: Change this to username or aci when implemented.
        });

        self.make_request(ReqType::Post(payload), CLIENT_URI.to_string())
            .await
    }

    async fn register_device(
        &self,
        client_info: &Contact,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client_info.uuid
        });
        let uri = format!("{}/{}", DEVICE_URI, client_info.uuid);

        self.make_request(ReqType::Post(payload), uri).await
    }

    async fn send_msg(
        &self,
        msg: String,
        uuid: String,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let payload = json!({
            "message": msg
        });
        let uri = format!("{}/{}", MSG_URI, uuid);

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

    fn new() -> Result<ServerAPI, Box<dyn std::error::Error>> {
        let test_client = Config::new()
            .set_base_url(Url::parse("http://127.0.0.1:12345")?)
            .set_timeout(Some(Duration::from_secs(5)))
            .try_into()?;

        Ok(ServerAPI {
            client: test_client,
        })
    }
}
impl ServerAPI {
    async fn make_request(
        &self,
        req_type: ReqType,
        uri: String,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let res = match req_type {
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
            _ => Err("Failed".into()),
        }
    }
}
