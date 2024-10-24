use std::collections::HashSet;
use std::net::SocketAddr;
use axum::extract::ws::WebSocket;

#[derive(Debug)]
pub struct WebSocketConnection {
    pub addr: SocketAddr,
    pub ws: WebSocket,
    pub pending_requests: HashSet<u64>
}

impl WebSocketConnection {
    pub fn new(addr: SocketAddr, ws: WebSocket) -> Self {
        Self {
            addr, ws, pending_requests: HashSet::new()
        }
    }
}