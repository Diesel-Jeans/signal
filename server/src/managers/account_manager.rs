use crate::{
    account::{Account, Device},
    database::SignalDatabase,
    in_memory_db::InMemorySignalDatabase,
    postgres::PostgresDatabase,
};
use anyhow::{bail, Result};
use common::web_api::{AccountAttributes, DevicePreKeyBundle};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::IdentityKey;
use sqlx::database;
use uuid::Uuid;
#[derive(Debug, Clone)]
pub struct AccountManager {}

impl Default for AccountManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountManager {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn create_account<T: SignalDatabase>(
        &self,
        db: &T,
        phone_number: String,
        account_attributes: AccountAttributes,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        primary_device: Device,
    ) -> Result<Account> {
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            primary_device,
            pni_identity_key,
            aci_identity_key,
            phone_number,
            account_attributes,
        );
        db.add_account(&account).await?;
        Ok(account)
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

    pub async fn store_key_bundle<T: SignalDatabase>(
        &self,
        db: &T,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        db.store_key_bundle(data, address).await
    }
}
