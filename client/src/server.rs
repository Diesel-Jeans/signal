use crate::contact::{Contact, Device};
use libsignal_net::chat::{ChatService, ChatServiceError, Request, Chat, chat_service};
use libsignal_net::env::{Env, Svr3Env};
use libsignal_net::auth::{Auth};
use libsignal_net::infra::{make_ws_config, ConnectionParams, EndpointConnection};
use common::signal_protobuf::Envelope;
use http::StatusCode;
use libsignal_protocol::*;
use std::fmt::format;
use std::sync::Arc;
use std::time::Duration;
use libsignal_net::env::constants::WEB_SOCKET_PATH;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::DirectConnector;
use libsignal_net::utils::ObservableEvent;
use surf::http::convert::json;
use surf::{http, Client, Config, Response, Url};
use surf::utils::async_trait;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::http::uri::PathAndQuery;
use tungstenite::{connect, Message};

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
    async fn connect(&self);
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
    async fn connect(&self) {
        let server_url = "wss://127.0.0.1:8888";
        println!("Trying to connect....");
        let (mut ws, response) = connect(server_url).expect("Can't connect");
        println!("Connected to the server");
        println!("Response HTTP code: {}", response.status());
        println!("Response contains the following headers:");
        for (header, _value) in response.headers() {
            println!("* {header}");
        }

        ws.send(Message::Text("Hello WebSocket".into())).unwrap();

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

















/*



#[async_trait]
pub trait WebsocketChatService: ChatService {
    async fn connect_ext(&self, env: &libsignal_net::env::Env<'static, Svr3Env<'static>>, connection_params: Vec<ConnectionParams>) -> Result<(), ChatServiceError>;

}

impl ChatService for ServerAPI {
    async fn send(&self, msg: Request, timeout: Duration) -> Result<libsignal_net::chat::Response, ChatServiceError> {
        todo!()
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        todo!()
    }

    async fn disconnect(&self) {
        todo!()
    }
}

impl<AuthService, UnauthService> Chat<AuthService, UnauthService>
where
    AuthService: WebsocketChatService + Send + Sync,
    UnauthService: WebsocketChatService + Send + Sync,
{

}

impl WebsocketChatService for ServerAPI {

    async fn connect_ext(&self, env: &Env<'static, Svr3Env<'static>>, connection_params: Vec<ConnectionParams>) -> Result<(), ChatServiceError> {
        let chat = simple_chat_service(env, Auth::default(), connection_params);

        chat.connect
    }
}

pub type AnyChat = Chat<
    Arc<dyn ChatService + Send + Sync>,
    Arc<dyn ChatService + Send + Sync>,
>;
pub fn simple_chat_service(
    env: &Env<'static, Svr3Env<'static>>,
    auth: Auth,
    connection_params: Vec<ConnectionParams>,
) -> AnyChat {
    let one_route_connect_timeout = Duration::from_secs(5);
    let network_change_event = ObservableEvent::default();
    let dns_resolver =
        DnsResolver::new_with_static_fallback(env.static_fallback(), &network_change_event);
    let transport_connector = DirectConnector::new(dns_resolver);
    let chat_endpoint = PathAndQuery::from_static(WEB_SOCKET_PATH);
    let chat_ws_config = make_ws_config(chat_endpoint, one_route_connect_timeout);
    let connection = EndpointConnection::new_multi(
        connection_params,
        one_route_connect_timeout,
        chat_ws_config,
        &network_change_event,
    );

    let (incoming_auth_tx, _incoming_rx) = mpsc::channel(1);
    let (incoming_unauth_tx, _incoming_rx) = mpsc::channel(1);
    chat_service(
        &connection,
        transport_connector,
        incoming_auth_tx,
        incoming_unauth_tx,
        auth,
        false,
    )
        .into_dyn()
}
*/

