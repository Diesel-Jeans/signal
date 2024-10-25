use std::collections::HashSet;
use std::net::SocketAddr;
use axum::extract::ws::{WebSocket, Message};
use axum::Error;

#[async_trait::async_trait]
pub trait WSStream {
    async fn recv(&mut self) -> Option<Result<Message, Error>>;
    async fn send(&mut self, msg: Message) -> Result<(), Error>;
    async fn close(self) -> Result<(), Error>;
}

#[async_trait::async_trait]
impl WSStream for WebSocket {
    async fn recv(&mut self) -> Option<Result<Message, Error>>{
        self.recv().await
    }
    async fn send(&mut self, msg: Message) -> Result<(), Error>{
        self.send(msg).await
    }
    async fn close(self) -> Result<(), Error>{
        self.close().await
    }
}

#[derive(Debug)]
pub struct WebSocketConnection<T: WSStream> {
    pub addr: SocketAddr,
    pub ws: T,
    pub pending_requests: HashSet<u64>
}

impl <T: WSStream>WebSocketConnection<T> {
    pub fn new(addr: SocketAddr, ws: T) -> Self {
        Self {
            addr, ws, pending_requests: HashSet::new()
        }
    }
}