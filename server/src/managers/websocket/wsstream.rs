use axum::extract::ws::{Message, WebSocket};
use axum::Error;
use futures_util::{Sink, Stream};

#[async_trait::async_trait]
pub trait WSStream:
    Send + Sink<Message, Error = axum::Error> + Stream<Item = Result<Message, axum::Error>> + 'static
{
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
