use futures_util::stream::SplitSink;
use std::fmt::Debug;

#[derive(Debug)]
pub enum ConnectionState<T, M> {
    Active(SplitSink<T, M>),
    Closed,
}

impl<M, T: Debug> ConnectionState<M, T> {
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Active(_))
    }
}
