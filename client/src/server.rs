use std::time::Duration;
use libsignal_protocol::*;
use surf::{http, Client, Config, Url};
use surf::http::convert::json;
use common::signal_protobuf::Envelope;
use crate::contact::{Contact, Device};
use tokio_tungstenite::connect_async;
use http::StatusCode;


pub struct ServerAPI {
    pub client: Client,
}

pub trait Server {
    async fn connect();
    async fn publish_bundle(
        &self
        //registration_id: u32,
        //bundle: &PreKeyBundle,
    ) -> Result<(), Box<dyn std::error::Error>>; // should take keys as parameter or struct
    async fn fetch_bundle(&self) -> Result<(), Box<dyn std::error::Error>> ;
    async fn register_client(&self, client_info: &Contact) -> Result<(), Box<dyn std::error::Error>>;
    async fn register_device(&self, client_info: &Contact) -> Result<(), Box<dyn std::error::Error>>;
    async fn send_msg(&self, msg: String) -> Result<(), Box<dyn std::error::Error>>;
    async fn update_client(&self, new_client: &Contact) -> Result<(), Box<dyn std::error::Error>>;
    async fn delete_client(&self, uuid: String) -> Result<(), Box<dyn std::error::Error>>;
    async fn delete_device(&self, uuid: String) -> Result<(), Box<dyn std::error::Error>>;
    fn new() -> Result<ServerAPI, Box<dyn std::error::Error>>;
}

impl Server for ServerAPI {
    fn new() -> Result<ServerAPI, Box<dyn std::error::Error>>{
        let test_client = Config::new()
            .set_base_url(Url::parse("http://127.0.0.1:12345")?)
            .set_timeout(Some(Duration::from_secs(5)))
            .try_into()?;

        Ok(ServerAPI {
            client: test_client
        })
    }
    async fn connect(){
        let server_url = "ws://127.0.0.1:12345";
        let (ws, _) = connect_async(server_url).await.expect("Failed to connect");

        println!("connected!");
    }
    async fn publish_bundle(&self/*, registration_id: u32, bundle: &PreKeyBundle*/) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "key1": "value1"
        });

        let mut res = self.client.post("/bundle")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn fetch_bundle(&self) -> Result<(), Box<dyn std::error::Error>>{
        let mut res = self.client.get("/bundle").await?;
        println!("{}", res.body_string().await?);

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }

    }

    async fn register_client(&self, client_info: &Contact) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client_info.uuid // TODO: Change this to username or aci when implemented.
        });

        let mut res = self.client.post("/client")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn register_device(&self, client_info: &Contact) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client_info.uuid
        });

        let mut res = self.client.post("/device")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn send_msg(&self, msg: String) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "message": msg
        });

        let mut res = self.client.put("/messages")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn update_client(&self, client: &Contact) -> Result<(), Box<dyn std::error::Error>> {
        let payload = json!({
            "uuid": client.uuid
        });

        let mut res = self.client.put("/client")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn delete_client(&self, uuid: String) -> Result<(), Box<dyn std::error::Error>>{
        let payload = json!({
            "uuid": uuid
        });

        let mut res = self.client.delete("/client")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }

    async fn delete_device(&self, uuid: String) -> Result<(), Box<dyn std::error::Error>>{
        let payload = json!({
            "uuid": uuid
        });

        let mut res = self.client.delete("/device")
            .body(surf::Body::from_json(&payload)?)
            .await?;

        match res.status() {
            StatusCode::Ok => Ok(()),
            _ => Err("Failed".into()),
        }
    }
}
