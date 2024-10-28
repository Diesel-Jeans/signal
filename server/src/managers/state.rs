use crate::{
    database::SignalDatabase, in_memory_db::InMemorySignalDatabase, postgres::PostgresDatabase,
    socket::SocketManager,
};

use super::{account_manager::AccountManager, key_manager::KeyManager};
use axum::extract::ws::WebSocket;

#[derive(Clone, Debug)]
pub struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: SocketManager<WebSocket>,
    account_manager: AccountManager<T>,
    key_manager: KeyManager,
}

impl<T: SignalDatabase> SignalServerState<T> {
    pub(self) fn database(&self) -> T {
        self.db.clone()
    }
    pub fn socket_manager(&self) -> &SocketManager<WebSocket> {
        &self.socket_manager
    }
    pub fn account_manager(&self) -> &AccountManager<T> {
        &self.account_manager
    }
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
}

impl SignalServerState<InMemorySignalDatabase> {
    pub async fn new() -> Self {
        let db = InMemorySignalDatabase::new();
        Self {
            db: db.clone(),
            socket_manager: SocketManager::new(),
            account_manager: AccountManager::new(db),
            key_manager: KeyManager::new(),
        }
    }
}

impl SignalServerState<PostgresDatabase> {
    pub async fn new() -> Self {
        let db = PostgresDatabase::connect()
            .await
            .expect("Failed to connect to the database.");
        Self {
            db: db.clone(),
            socket_manager: SocketManager::new(),
            account_manager: AccountManager::new(db),
            key_manager: KeyManager::new(),
        }
    }
}
