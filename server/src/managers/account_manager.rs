use crate::{
    account::{Account, Device},
    database::SignalDatabase,
    in_memory_db::InMemorySignalDatabase,
    postgres::PostgresDatabase,
};
use anyhow::{bail, Result};
use libsignal_core::{Aci, Pni, ServiceId};

#[derive(Debug, Clone)]
pub struct AccountManager {}

impl AccountManager {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn create_account<T: SignalDatabase>(&self, db: &T, account: &Account) -> Result<()> {
        db.add_account(account).await
    }

    pub async fn get_account<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
    ) -> Result<Account> {
        db.get_account(service_id).await
    }

    pub async fn update_account_aci<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
        new_aci: Aci,
    ) -> Result<()> {
        db.update_account_aci(service_id, new_aci).await
    }

    pub async fn update_account_pni<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
        new_pni: Pni,
    ) -> Result<()> {
        db.update_account_pni(service_id, new_pni).await
    }

    pub async fn delete_account<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
    ) -> Result<()> {
        db.delete_account(service_id).await
    }

    pub async fn add_device<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
        device: &Device,
    ) -> Result<()> {
        db.add_device(service_id, device).await
    }

    pub async fn get_all_devices<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
    ) -> Result<Vec<Device>> {
        db.get_all_devices(service_id).await
    }
    pub async fn get_device<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<Device> {
        db.get_device(service_id, device_id).await
    }
    pub async fn delete_device<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<()> {
        db.delete_device(service_id, device_id).await
    }
}
