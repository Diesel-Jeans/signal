use std::fmt::Debug;

use super::{
    mock_helper::MockSocket,
    websocket::{connection::WebSocketConnection, wsstream::WSStream},
};
use crate::{
    account::{self, Account, AuthenticatedDevice, Device},
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

#[cfg(test)]
use super::mock_helper::MockDB;

#[derive(Debug)]
pub struct SignalServerState<T: SignalDatabase, U: WSStream + Debug> {
    pub db: T,
    pub websocket_manager: WebSocketManager<U, T>,
    pub account_manager: AccountManager,
    pub key_manager: KeyManager,
    pub message_manager: MessagesManager<T, WebSocketConnection<U, T>>,
    pub message_cache: MessageCache<WebSocketConnection<U, T>>,
}

impl<T: SignalDatabase + Clone, U: WSStream + Debug> Clone for SignalServerState<T, U> {
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
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
            message_manager: MessagesManager::new(db, cache.clone()),
            message_cache: cache,
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
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
            message_manager: MessagesManager::new(db, cache.clone()),
            message_cache: cache,
        }
    }
}

impl<T: SignalDatabase, U: WSStream + Debug> SignalServerState<T, U> {
    pub async fn create_account(
        &self,
        phone_number: String,
        account_attributes: AccountAttributes,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        primary_device: Device,
        key_bundle: DevicePreKeyBundle,
    ) -> Result<Account> {
        let device_id = primary_device.device_id();
        let account = self
            .account_manager
            .create_account(
                &self.db,
                phone_number,
                account_attributes,
                aci_identity_key,
                pni_identity_key,
                primary_device,
            )
            .await?;

        self.store_key_bundle(
            &key_bundle,
            &ProtocolAddress::new(account.pni().service_id_string(), device_id),
        )
        .await?;

        Ok(account)
    }

    pub async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        self.account_manager.get_account(&self.db, service_id).await
    }

    pub async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        self.account_manager
            .update_account_aci(&self.db, service_id, new_aci)
            .await
    }

    pub async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        self.account_manager
            .update_account_pni(&self.db, service_id, new_pni)
            .await
    }

    pub async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        self.account_manager
            .delete_account(&self.db, service_id)
            .await
    }

    pub async fn add_device(&self, service_id: &ServiceId, device: &Device) -> Result<()> {
        self.account_manager
            .add_device(&self.db, service_id, device)
            .await
    }

    pub async fn get_all_devices(&self, service_id: &ServiceId) -> Result<Vec<Device>> {
        self.account_manager
            .get_all_devices(&self.db, service_id)
            .await
    }

    pub async fn get_device(&self, service_id: &ServiceId, device_id: u32) -> Result<Device> {
        self.account_manager
            .get_device(&self.db, service_id, device_id)
            .await
    }

    pub async fn delete_device(&self, service_id: &ServiceId, device_id: u32) -> Result<()> {
        self.account_manager
            .delete_device(&self.db, service_id, device_id)
            .await
    }

    pub async fn handle_put_keys(
        &self,
        auth_device: &AuthenticatedDevice,
        bundle: SetKeyRequest,
        kind: ServiceIdKind,
    ) -> Result<(), ApiError> {
        self.key_manager
            .handle_put_keys(&self.db, auth_device, bundle, kind)
            .await
    }

    /// * `target_device_id` - device_id must be either a [Some<DeviceId>] or [None] for all devices
    pub async fn handle_get_keys<S: SignalDatabase>(
        &self,
        auth_device: &AuthenticatedDevice,
        target_service_id: ServiceId,
        target_device_id: Option<DeviceId>,
    ) -> Result<PreKeyResponse, ApiError> {
        self.key_manager
            .handle_get_keys(&self.db, auth_device, target_service_id, target_device_id)
            .await
    }

    pub async fn handle_post_keycheck<S: SignalDatabase>(
        &self,
        service_id: &ServiceId,
        auth_device: &AuthenticatedDevice,
        kind: ServiceIdKind,
        usr_digest: [u8; 32],
    ) -> Result<bool, ApiError> {
        self.key_manager
            .handle_post_keycheck(&self.db, auth_device, kind, usr_digest)
            .await
    }

    pub async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        self.account_manager
            .store_key_bundle(&self.db, data, address)
            .await
    }

    pub async fn get_one_time_pre_key_count(&self, service_id: &ServiceId) -> Result<(u32, u32)> {
        self.key_manager
            .get_one_time_pre_key_count(&self.db, service_id)
            .await
    }
}
