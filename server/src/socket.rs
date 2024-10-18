use axum::extract::ws::{Message, WebSocket};
use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

type SocketMap = Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<WebSocket>>>>>;

#[derive(Clone, Debug)]
pub struct SocketManager {
    sockets: SocketMap,
}

/*
All ws should happen here, take in other managers or classes
if you need to do something on ws binary or text
*/

impl SocketManager {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn on_ws_binary(&mut self, who: SocketAddr, bytes: Vec<u8>) {
        println!("BINARY: {}", String::from_utf8(bytes).unwrap());
    }

    pub async fn on_ws_text(&mut self, who: SocketAddr, text: String) {
        println!("TEXT: {}", text);
        self.ws_send(
            &who,
            Message::Binary(format!("hello {}", who).as_bytes().to_vec()),
        )
        .await;
    }

    pub async fn add_ws(&self, who: SocketAddr, socket: WebSocket) {
        let socket = Arc::new(Mutex::new(socket));
        self.sockets.write().await.insert(who, socket);
    }

    pub async fn remove_ws(&self, who: &SocketAddr) {
        self.sockets.write().await.remove(who);
    }

    pub async fn get_ws(&self, who: &SocketAddr) -> Option<Arc<Mutex<WebSocket>>> {
        self.sockets.read().await.get(who).cloned()
    }

    // do not use this, unless is socket_handler
    pub async fn ws_recv(&self, who: &SocketAddr) -> Option<Result<Message, axum::Error>> {
        match self.get_ws(who).await {
            Some(x) => x.lock().await.recv().await,
            None => None,
        }
    }

    // only use this
    pub async fn ws_send(
        &self,
        who: &SocketAddr,
        message: Message,
    ) -> Option<Result<(), axum::Error>> {
        match self.get_ws(who).await {
            Some(x) => Some(x.lock().await.send(message).await),
            None => None,
        }
    }
}
