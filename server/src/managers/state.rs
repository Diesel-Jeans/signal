use crate::{
    account::{self, Account, Device},
    database::SignalDatabase,
    in_memory_db::InMemorySignalDatabase,
    postgres::PostgresDatabase,
    socket::SocketManager,
};
use anyhow::Result;
use common::web_api::{DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};

use super::{account_manager::AccountManager, key_manager::KeyManager};

#[derive(Clone, Debug)]
struct SignalServerState<T: SignalDatabase> {
    db: T,
    socket_manager: SocketManager,
    account_manager: AccountManager,
    key_manager: KeyManager,
}

impl<T: SignalDatabase> SignalServerState<T> {
    pub(self) fn database(&self) -> T {
        self.db.clone()
    }
}

impl SignalServerState<InMemorySignalDatabase> {
    fn new() -> Self {
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

impl<T: SignalDatabase> SignalServerState<T> {
    pub async fn create_account(&self, account: &Account) -> Result<()> {
        self.account_manager.create_account(&self.db, account).await
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

    pub async fn store_aci_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        self.key_manager
            .store_aci_signed_pre_key(&self.db, spk)
            .await
    }

    pub async fn store_pni_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        self.key_manager
            .store_pni_signed_pre_key(&self.db, spk)
            .await
    }

    pub async fn store_pq_aci_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        self.key_manager
            .store_pq_aci_signed_pre_key(&self.db, pq_spk)
            .await
    }

    pub async fn store_pq_pni_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        self.key_manager
            .store_pq_pni_signed_pre_key(&self.db, pq_spk)
            .await
    }

    pub async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        self.key_manager
            .store_key_bundle(&self.db, data, address)
            .await
    }

    pub async fn get_key_bundle(&self, address: &ProtocolAddress) -> Result<DevicePreKeyBundle> {
        self.key_manager.get_key_bundle(&self.db, address).await
    }

    pub async fn get_one_time_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        self.key_manager
            .get_one_time_pre_key_count(&self.db, service_id)
            .await
    }

    pub async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        self.key_manager
            .store_one_time_pre_keys(&self.db, otpks, owner)
            .await
    }

    pub async fn get_one_time_pre_key(
        &self,
        owner: &ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        self.key_manager.get_one_time_pre_key(&self.db, owner).await
    }
}
