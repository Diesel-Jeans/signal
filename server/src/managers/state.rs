use super::{
    account_manager::AccountManager,
    client_presence_manager::ClientPresenceManager,
    key_manager::KeyManager,
    messages_manager::MessagesManager,
    websocket::{connection::WebSocketConnection, websocket_manager::WebSocketManager},
};
#[cfg(test)]
use crate::test_utils::websocket::{MockDB, MockSocket};
use crate::{database::SignalDatabase, message_cache::MessageCache, postgres::PostgresDatabase};
use axum::extract::ws::Message;
use common::websocket::wsstream::WSStream;
use rand::{rngs::OsRng, CryptoRng, Rng};
use std::fmt::Debug;

#[derive(Debug)]
pub struct SignalServerState<T, U, R>
where
    T: SignalDatabase,
    U: WSStream<Message, axum::Error> + Debug,
    R: CryptoRng + Rng + Send + 'static,
{
    pub db: T,
    pub websocket_manager: WebSocketManager<U, T, R>,
    pub account_manager: AccountManager<T>,
    pub key_manager: KeyManager<T>,
    pub message_manager: MessagesManager<T, WebSocketConnection<U, T, R>>,
    pub client_presence_manager: ClientPresenceManager<WebSocketConnection<U, T, R>>,
    pub message_cache: MessageCache<WebSocketConnection<U, T, R>>,
}

impl<T, U, R> Clone for SignalServerState<T, U, R>
where
    T: SignalDatabase + Clone,
    U: WSStream<Message, axum::Error> + Debug,
    R: CryptoRng + Rng + Send,
{
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            websocket_manager: self.websocket_manager.clone(),
            account_manager: self.account_manager.clone(),
            key_manager: self.key_manager.clone(),
            message_manager: self.message_manager.clone(),
            client_presence_manager: self.client_presence_manager.clone(),
            message_cache: self.message_cache.clone(),
        }
    }
}

impl<U, R> SignalServerState<PostgresDatabase, U, R>
where
    U: WSStream<Message, axum::Error> + Debug,
    R: CryptoRng + Rng + Send + 'static,
{
    pub async fn new() -> Self {
        SignalServerState::connect("DATABASE_URL").await
    }

    pub async fn connect(connection_str: &str) -> Self {
        let db = PostgresDatabase::connect(connection_str.to_string()).await;
        let cache = MessageCache::connect();
        Self {
            db: db.clone(),
            websocket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(db.clone()),
            key_manager: KeyManager::new(db.clone()),
            message_manager: MessagesManager::new(db, cache.clone()),
            client_presence_manager: ClientPresenceManager::connect(),
            message_cache: cache,
        }
    }
}

#[cfg(test)]
impl Default for SignalServerState<MockDB, MockSocket, OsRng> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SignalServerState<MockDB, MockSocket, OsRng> {
    pub fn new() -> Self {
        let db = MockDB {};
        let cache = MessageCache::connect();

        Self {
            db: db.clone(),
            websocket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(db.clone()),
            key_manager: KeyManager::new(db.clone()),
            message_manager: MessagesManager::new(db, cache.clone()),
            client_presence_manager: ClientPresenceManager::connect(),
            message_cache: cache,
        }
    }
}
