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

    async fn on_ws_binary(&mut self, who: SocketAddr, bytes: Vec<u8>) {
        println!("BINARY: {}", String::from_utf8(bytes).unwrap());
    }

    async fn on_ws_text(&mut self, who: SocketAddr, text: String) {
        println!("TEXT: {}", text);
        self.ws_send(
            &who,
            Message::Binary(format!("hello {}", who).as_bytes().to_vec()),
        )
        .await;
    }

    async fn add_ws(&self, who: SocketAddr, socket: WebSocket) {
        let socket = Arc::new(Mutex::new(socket));
        self.sockets.write().await.insert(who, socket);
    }

    async fn remove_ws(&self, who: &SocketAddr) {
        self.sockets.write().await.remove(who);
    }

    async fn get_ws(&self, who: &SocketAddr) -> Option<Arc<Mutex<WebSocket>>> {
        self.sockets.read().await.get(who).cloned()
    }

    // do not use this, unless is socket_handler
    async fn ws_recv(&self, who: &SocketAddr) -> Option<Result<Message, axum::Error>> {
        match self.get_ws(who).await {
            Some(x) => x.lock().await.recv().await,
            None => None,
        }
    }

    // only use this
    async fn ws_send(&self, who: &SocketAddr, message: Message) -> Option<Result<(), axum::Error>> {
        match self.get_ws(who).await {
            Some(x) => Some(x.lock().await.send(message).await),
            None => None,
        }
    }

    pub async fn handle_socket(
        &mut self,
        /*authenticated_device: ???, */
        mut socket: WebSocket,
        who: SocketAddr,
    ) {
        /* authenticated_device should be put into the socket_manager,
        we should probably have a representation like in the real server */
        self.add_ws(who, socket).await;

        while let Some(msg_res) = self.ws_recv(&who).await {
            let msg = match msg_res {
                Ok(x) => x,
                Err(y) => {
                    println!("handle_socket ERROR: {}", y);
                    continue;
                }
            };

            match msg {
                Message::Binary(b) => self.on_ws_binary(who, b).await,
                Message::Text(t) => self.on_ws_text(who, t).await,
                Message::Close(_) => {
                    println!("handle_socket: '{}' disconnected", who);
                    self.remove_ws(&who).await;
                    break;
                }
                _ => {}
            }
        }
    }
}
