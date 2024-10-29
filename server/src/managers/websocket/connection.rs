use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::Error;
use libsignal_core::ProtocolAddress;
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::sync::{Mutex};
use std::{collections::HashMap, sync::Arc};
use std::fmt::Debug;
use common::signal_protobuf::{
    envelope, web_socket_message, Envelope, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use prost::{bytes::Bytes, Message as PMessage};
use rand::rngs::OsRng;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};


#[async_trait::async_trait]
pub trait WSStream {
    async fn recv(&mut self) -> Option<Result<Message, Error>>;
    async fn send(&mut self, msg: Message) -> Result<(), Error>;
    async fn close(self) -> Result<(), Error>;
}

#[async_trait::async_trait]
impl WSStream for WebSocket {
    async fn recv(&mut self) -> Option<Result<Message, Error>> {
        self.recv().await
    }
    async fn send(&mut self, msg: Message) -> Result<(), Error> {
        self.send(msg).await
    }
    async fn close(self) -> Result<(), Error> {
        self.close().await
    }
}

#[derive(Debug)]
pub struct WebSocketConnection<T: WSStream + Debug> {
    pub protocol_address: ProtocolAddress,
    pub socket_address: SocketAddr,
    ws: ConnectionState<T>,
    pub pending_requests: HashSet<u64>,
}

impl <T: WSStream + Debug> WebSocketConnection<T> {
    pub fn new(protocol_addr: ProtocolAddress, socket_addr: SocketAddr, ws: T) -> Self {
        Self {
            protocol_address: protocol_addr,
            socket_address: socket_addr,
            ws: ConnectionState::Active(ws),
            pending_requests: HashSet::new(),
        }
    }

    pub async fn send_message(&mut self, mut message: Envelope) -> Result<(), String>{
        let id = generate_req_id();
        message.ephemeral = Some(false);
        let body = message.encode_to_vec();
        let req = WebSocketRequestMessage {
            verb: Some("PUT".to_string()),
            path: Some("/api/v1/message".to_string()),
            body: Some(body),
            headers: vec![
                "X-Signal-Key: false".to_string(),
                format!("X-Signal-Timestamp: {}", current_millis()),
            ],
            id: Some(id),
        };
        let ws_msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request as i32),
            request: Some(req),
            response: None
        };
        self.pending_requests.insert(id);
        Ok(())
    }

    pub async fn close(&mut self) {
        let socket = if let ConnectionState::Active(x) = std::mem::replace(&mut self.ws, ConnectionState::Closed) {
            x
        } else {
            return; 
        };
        self.ws = ConnectionState::Closed;
        socket.close().await;
    }

    pub async fn close_reason(&mut self, code: u16, reason: String) -> Result<(), axum::Error>{
        self.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))).await
    }

    pub fn is_active(& self) -> bool{
        self.ws.is_active()
    }

    pub async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        match self.ws {
            ConnectionState::Active(ref mut socket) => socket.recv().await,
            ConnectionState::Closed => None
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        match self.ws {
            ConnectionState::Active(ref mut socket) => socket.send(msg).await,
            ConnectionState::Closed => Err(axum::Error::new("Connection is closed"))
        }
    }

    pub async fn on_receive(&mut self, proto_message: WebSocketMessage){
        
    }
}


#[derive(Debug)]
pub enum ConnectionState<T: WSStream> {
    Active(T),
    Closed,
}

impl<T: WSStream + Debug> ConnectionState<T> {
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Active(_))
    }
}

pub type ClientConnection<T> = Arc<Mutex<WebSocketConnection<T>>>;
pub type ConnectionMap<T> = Arc<Mutex<HashMap<ProtocolAddress, ClientConnection<T>>>>;

fn generate_req_id() -> u64 {
    let mut rng = OsRng;
    let rand_v: u64 = rng.gen();
    rand_v
}

fn current_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}