use futures_util::{Sink, Stream};

#[async_trait::async_trait]
pub trait WSStream<M, E>:
    Send + Sink<M, Error = E> + Stream<Item = Result<M, E>> + 'static
{
    async fn recv(&mut self) -> Option<Result<M, E>>;
    async fn send(&mut self, msg: M) -> Result<(), E>;
    async fn close(self) -> Result<(), E>;
}


