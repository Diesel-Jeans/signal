use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::Query;
use axum::http::Uri;
use libsignal_core::{DeviceId, ServiceId};
use serde::de::IntoDeserializer;
use serde::Deserialize;
use serde_json::json;
use sha2::digest::consts::False;
use sha2::digest::typenum::Integer;
use tonic::ConnectError;
use uuid::fmt::Braced;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;

use std::str::FromStr;
use std::thread::current;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock, MutexGuard};

use common::signal_protobuf::{WebSocketMessage, WebSocketRequestMessage, web_socket_message, WebSocketResponseMessage, Envelope, envelope};
use common::web_api::{SignalMessage, SignalMessages};
use prost::{bytes::Bytes, Message as PMessage};
use url::Url;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use rand::rngs::OsRng;

use crate::account::Account;
use crate::connection::WebSocketConnection;
use crate::error::SocketManagerError;
use crate::query::PutV1MessageParams;

/*const WS_ENDPOINTS: [&str; 24] = [
    "v4/attachments/form/upload",
    "v1/config",
    "v1/certificate/delivery",
    "v1/devices",
    "v2/directory/auth",
    "v1/certificate/auth/group",
    "v1/archives/auth",
    "v1/archives/auth/read",
    "v1/archives/upload/form",
    "v1/archives/media/upload/form",
    "v1/devices/link",
    "v1/messages",
    "v1/messages/multi_recipient",
    "v2/accounts/phone_number_discoverability",
    "v1/profile",
    "v1/archives",
    "v1/archives/media",
    "v1/archives/media/batch",
    "v1/archives/media/delete",
    "v1/devices/capabilities",
    "v1/messages/report",
    "v1/archives/backupid",
    "v1/archives/keys",
    "v1/storage/auth",
];*/


pub trait ToEnvelope {
    fn to_envelope(&mut self, destination_id: ServiceId, account: Option<Account>, src_device_id: Option<DeviceId>, timestamp: i64, story: bool, urgent: bool) -> Envelope;
}

impl ToEnvelope for SignalMessage {
    fn to_envelope(&mut self, destination_id: ServiceId, account: Option<Account>, src_device_id: Option<DeviceId>, timestamp: i64, story: bool, urgent: bool) -> Envelope {
        let typex = envelope::Type::try_from(self.r#type as i32).unwrap();
        todo!()
    }
}

#[derive(Debug)]
enum ConnectionState {
    Active(WebSocketConnection),
    Closed
}

type ConnectionMap = Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<ConnectionState>>>>>;

#[derive(Clone, Debug)]
pub struct SocketManager {
    sockets: ConnectionMap,
}

impl SocketManager {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn on_ws_binary(&mut self, connection: &mut WebSocketConnection, bytes: Vec<u8>) {
        let msg = match WebSocketMessage::decode(Bytes::from(bytes)){
            Ok(x) => x,
            Err(y) => {
                println!("handle_socket ws proto ERROR: {}", y);
                return;
            }
        };

        match msg.r#type() {
            web_socket_message::Type::Request => {
                if let Some(req) = msg.request {
                    self.handle_request(connection, req).await
                } else {
                    todo!() // TODO: handle not request when type request
                }
            }
            web_socket_message::Type::Response => {
                if let Some(res) = msg.response{
                    self.handle_response(connection, res).await
                } else {
                    todo!() // TODO: handle not response when type response
                }
            }
            _ => self.close_socket(connection, 1007, "Badly formatted".to_string()).await,
        }
    }

    async fn handle_request(&mut self, connection: &mut WebSocketConnection, req: WebSocketRequestMessage){
        let uri = Uri::from_str(req.path()).unwrap();
        let path = uri.path();

        if path.starts_with("v1/messages"){
            let id = get_path_segment::<String>(path, 2).unwrap();
            let query: Query<PutV1MessageParams> = Query::try_from_uri(&uri).unwrap();
            let json = String::from_utf8(req.body().to_vec()).unwrap();
            let messages = SignalMessages::deserialize(json!(json)).unwrap();
            todo!(); // TODO: call handle_put_messages
            //self.send_response(connection, req, status, reason, headers, body);

        // add more endpoints below as needed
        } else {
            println!("Unkown WS request path '{}'", path)
        }
    }

    async fn handle_response(&mut self, connection: &mut WebSocketConnection, res: WebSocketResponseMessage){
        if let Some(id) = res.id {
            connection.pending_requests.remove(&id);
        } else {
            println!("response to what?")
        }
    }

    async fn send_response(&mut self, connection: &mut WebSocketConnection, req: WebSocketRequestMessage, status: u16, reason: String, headers: Vec<String>, body: Option<Vec<u8>>) {
        todo!()
    }

    pub async fn send_message(&mut self, who: &SocketAddr, message: Envelope){
        let state = if let Ok(x) = self.get_ws(&who).await {
            x
        } else {
            return; // socket does not exist
        };
        let mut state_g = state.lock().await;
        if let ConnectionState::Active(ref mut connection) = *state_g {
            let id = generate_req_id();
            let body = message.encode_to_vec();
            let req = WebSocketRequestMessage {
                verb: Some("PUT".to_string()), 
                path: Some("/api/v1/message".to_string()),
                body: Some(body),
                headers: vec![
                    "X-Signal-Key: false".to_string(),
                    format!("X-Signal-Timestamp: {}", current_millis()),
                ],
                id: Some(id)
            };
            connection.pending_requests.insert(id);
            connection.ws.send(Message::Binary(req.encode_to_vec())).await;

        }

    }

    async fn close_socket(&mut self, connection: &mut WebSocketConnection, code: u16, reason: String){
        connection.ws.send(Message::Close(Some(CloseFrame{ 
            code, 
            reason: reason.into()
        })));
        self.remove_ws(&connection.addr, true);
    }

    async fn on_ws_text(&mut self, connection: &mut WebSocketConnection, text: String) {
        println!("🎵happy happy happy🎵: {}", text);
        connection.ws.send(Message::Text("OK".to_string())).await;
    }

    async fn add_ws(&self, who: SocketAddr, socket: WebSocket) {
        let state = ConnectionState::Active(WebSocketConnection::new(who, socket));
        self.sockets.lock().await.insert(who, Arc::new(Mutex::new(state)));
    }

    async fn remove_ws(&self, who: &SocketAddr, close_socket: bool) {
        let mut guard = self.sockets.lock().await;
        let opt = guard.remove(who);
        
        if !close_socket{
            return;
        }

        let state = if let Some(x) = opt {
            x
        } else {
            return;
        };
        let mut state_guard = state.lock().await;
        if let ConnectionState::Active(connection) = std::mem::replace(&mut *state_guard, ConnectionState::Closed){
            connection.ws.close();
        }
    }

    async fn get_ws(&self, who: &SocketAddr) -> Result<Arc<Mutex<ConnectionState>>, SocketManagerError>
    {
        let mut map_guard = self.sockets.lock().await;
        let state = if let Some(x) = map_guard.get_mut(who){
            x
        } else {
            return Err(SocketManagerError::NoAddress(*who));
        };

        Ok(state.clone())
    }

    async fn contains(&self, who: &SocketAddr) -> bool{
        self.sockets.lock().await.contains_key(who)
    }

    pub async fn handle_socket(
        &mut self,
        /*authenticated_device: ???, */
        mut socket: WebSocket,
        who: SocketAddr,
    ) {
        /* authenticated_device should be put into the socket_manager,
        we should probably have a representation like in the real server */
        if self.contains(&who).await{
            return; // do not handle socket twice
        }
        self.add_ws(who, socket).await;

        let state = if let Ok(x) = self.get_ws(&who).await {
            x
        } else {
            return; // socket does not exist
        };

        // this will always check if the state is active, and exit if some other thread has closed the socket
        while let ConnectionState::Active(ref mut connection) = *state.lock().await {
            let msg = match connection.ws.recv().await {
                Some(Ok(x)) => x,
                None => break,
                _ => {
                    self.close_socket(connection, 1007, "Badly formatted".to_string()).await;
                    break;
                }
            };

            match msg {
                Message::Binary(b) => self.on_ws_binary(connection, b).await,
                Message::Text(t) => self.on_ws_text(connection, t).await,
                Message::Close(_) => {
                    println!("handle_socket: '{}' disconnected", who);
                    self.remove_ws(&who, false).await;
                    break;
                }
                _ => {}
            }
        }
    }
}


fn get_path_segment<T: FromStr<Err = impl std::fmt::Debug>>(uri: &str, n: usize) -> Result<T, String>{
    if uri.contains("?"){
        return Err("Contains query params".to_string())
    }

    let mut parts: Vec<&str> = uri.split("/").collect();
    if parts.is_empty() {
        return Err("no parts".to_string())
    }

    parts.remove(0);

    if n >= parts.len(){
        return Err("larger than count".to_string())
    }

    match T::from_str(parts[n]) {
        Ok(x) => Ok(x),
        Err(_) => Err("failed to convert".to_string())
    }
}

fn current_millis() -> u128{
    SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
}

fn generate_req_id() -> u64{
    let mut rng = OsRng;
    let rand_v: u64 = rng.gen();
    rand_v
}