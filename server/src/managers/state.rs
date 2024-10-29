use crate::{
    account::{self, Account, Device},
    database::SignalDatabase,
    error::ApiError,
    in_memory_db::InMemorySignalDatabase,
    postgres::PostgresDatabase,
};
use anyhow::Result;
use common::web_api::{
    AccountAttributes, DevicePreKeyBundle, PreKeyResponse, SetKeyRequest, UploadPreKey,
    UploadSignedPreKey,
};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::IdentityKey;

use super::{account_manager::AccountManager, key_manager::KeyManager, websocket::websocket_manager::WebSocketManager};
use axum::extract::ws::WebSocket;

#[derive(Clone, Debug)]
pub struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: WebSocketManager<WebSocket>,
    account_manager: AccountManager,
    key_manager: KeyManager,
}

impl<T: SignalDatabase> SignalServerState<T> {
    pub(self) fn database(&self) -> T {
        self.db.clone()
    }
    pub fn socket_manager(&self) -> &WebSocketManager<WebSocket> {
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
    fn new() -> Self {
        Self {
            db: InMemorySignalDatabase::new(),
            socket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
        }
    }
}

impl SignalServerState<PostgresDatabase> {
    pub async fn new() -> Self {
        Self {
            db: PostgresDatabase::connect()
                .await
                .expect("Failed to connect to the database."),
            socket_manager: WebSocketManager::new(),
            account_manager: AccountManager::new(),
            key_manager: KeyManager::new(),
        }
    }
}

impl<T: SignalDatabase> SignalServerState<T> {
    pub async fn create_account(
        &self,
        phone_number: String,
        account_attributes: AccountAttributes,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        primary_device: Device,
    ) -> Result<()> {
        let key_bundle = DevicePreKeyBundle {
            aci_signed_pre_key: primary_device.aci_signed_pre_key().clone(),
            pni_signed_pre_key: primary_device.pni_signed_pre_key().clone(),
            aci_pq_pre_key: primary_device.aci_pq_pre_key().clone(),
            pni_pq_pre_key: primary_device.pni_pq_pre_key().clone(),
        };
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
        .await
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
        address: &ProtocolAddress,
        bundle: SetKeyRequest,
    ) -> Result<(), ApiError> {
        self.key_manager
            .handle_put_keys(&self.db, address, bundle)
            .await
    }

    pub async fn handle_get_keys<S: SignalDatabase>(
        &self,
        service_id: &ServiceId,
        address_and_registration_ids: Vec<(ProtocolAddress, u32)>,
    ) -> Result<PreKeyResponse, ApiError> {
        self.key_manager
            .handle_get_keys(&self.db, service_id, address_and_registration_ids)
            .await
    }

    pub async fn handle_post_keycheck<S: SignalDatabase>(
        &self,
        service_id: &ServiceId,
        address: ProtocolAddress,
        usr_digest: [u8; 32],
    ) -> Result<bool, ApiError> {
        self.key_manager
            .handle_post_keycheck(&self.db, service_id, address, usr_digest)
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
