use std::fmt::Debug;

use super::websocket::{connection::WebSocketConnection, wsstream::WSStream};
#[cfg(test)]
use crate::test_utils::websocket::{MockDB, MockSocket};
use crate::{
    account::{Account, AuthenticatedDevice, Device},
    database::SignalDatabase,
    error::ApiError,
    message_cache::MessageCache,
    postgres::PostgresDatabase,
};
use anyhow::{Ok, Result};
use common::web_api::{
    AccountAttributes, DevicePreKeyBundle, PreKeyResponse, SetKeyRequest, UploadPreKey,
    UploadSignedPreKey,
};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId, ServiceIdKind};
use libsignal_protocol::IdentityKey;

use super::{
    account_manager::AccountManager, key_manager::KeyManager, messages_manager::MessagesManager,
    websocket::websocket_manager::WebSocketManager,
};
use axum::extract::ws::WebSocket;

#[derive(Debug)]
pub struct SignalServerState<T, U>
where
    T: SignalDatabase,
    U: WSStream + Debug,
{
    pub db: T,
    pub websocket_manager: WebSocketManager<U, T>,
    pub account_manager: AccountManager<T>,
    pub key_manager: KeyManager<T>,
    pub message_manager: MessagesManager<T, WebSocketConnection<U, T>>,
    pub message_cache: MessageCache<WebSocketConnection<U, T>>,
}

impl<T, U> Clone for SignalServerState<T, U>
where
    T: SignalDatabase + Clone,
    U: WSStream + Debug,
{
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            websocket_manager: self.websocket_manager.clone(),
            account_manager: self.account_manager.clone(),
            key_manager: self.key_manager.clone(),
            message_manager: self.message_manager.clone(),
            message_cache: self.message_cache.clone(),
        }
    }
}

impl SignalServerState<PostgresDatabase, WebSocket> {
    pub async fn new() -> Self {
        let db = PostgresDatabase::connect("DATABASE_URL".to_string()).await;
        let cache = MessageCache::connect();
        Self {
            db: db.clone(),
            websocket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(db.clone()),
            key_manager: KeyManager::new(db.clone()),
            message_manager: MessagesManager::new(db, cache.clone()),
            message_cache: cache,
        }
    }
}

#[cfg(test)]
impl Default for SignalServerState<MockDB, MockSocket> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SignalServerState<MockDB, MockSocket> {
    pub fn new() -> Self {
        let db = MockDB {};
        let cache = MessageCache::connect();

        Self {
            db: db.clone(),
            websocket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(db.clone()),
            key_manager: KeyManager::new(db.clone()),
            message_manager: MessagesManager::new(db, cache.clone()),
            message_cache: cache,
        }
    }
}
