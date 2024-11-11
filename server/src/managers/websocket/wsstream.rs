use axum::extract::ws::{WebSocket, Message};
use axum::Error;

#[async_trait::async_trait]
pub trait WSStream: Send + 'static {
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
