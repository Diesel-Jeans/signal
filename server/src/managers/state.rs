use crate::{
    database::SignalDatabase, in_memory_db::InMemorySignalDatabase, postgres::PostgresDatabase,
    socket::SocketManager,
};

use super::{account_manager::AccountManager, key_manager::KeyManager};

#[derive(Clone, Debug)]
pub struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: SocketManager,
    account_manager: AccountManager,
    key_manager: KeyManager,
}

impl<T: SignalDatabase> SignalServerState<T> {
    pub(self) fn database(&self) -> T {
        self.db.clone()
    }
    pub fn socket_manager(&self) -> &SocketManager {
        &self.socket_manager
    }
    pub fn account_manager(&self) -> &AccountManager {
        &self.account_manager
    }
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
}

impl SignalServerState<InMemorySignalDatabase> {
    async fn new() -> Self {
        Self {
            db: InMemorySignalDatabase::new(),
            socket_manager: SocketManager::new(),
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
        }
    }
}

impl SignalServerState<PostgresDatabase> {
    async fn new() -> Self {
        Self {
            db: PostgresDatabase::connect().await.unwrap(),
            socket_manager: SocketManager::new(),
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
        }
    }
}
