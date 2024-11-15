use crate::{
    account::{Account, Device},
    database::SignalDatabase,
    postgres::PostgresDatabase,
};
use anyhow::{bail, Result};
use common::web_api::{AccountAttributes, DevicePreKeyBundle};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::IdentityKey;
use sqlx::database;
use uuid::Uuid;

#[derive(Default, Debug, Clone)]
pub struct AccountManager<T>
where
    T: SignalDatabase,
{
    db: T,
}

impl<T> AccountManager<T>
where
    T: SignalDatabase,
{
    pub fn new(db: T) -> Self {
        Self { db }
    }
    pub async fn create_account(
        &self,
        phone_number: String,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        primary_device: Device,
    ) -> Result<Account> {
        let account = Account::new(
            Pni::from(Uuid::new_v4()),
            aci_identity_key,
            pni_identity_key,
            primary_device,
            phone_number,
        );
        self.db.add_account(&account).await?;
        Ok(account)
    }

    pub async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        self.db.get_account(service_id).await
    }

    pub async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        self.db.update_account_aci(service_id, new_aci).await
    }

    pub async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        self.db.update_account_pni(service_id, new_pni).await
    }

    pub async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        self.db.delete_account(service_id).await
    }

    pub async fn add_device(&self, service_id: &ServiceId, device: &Device) -> Result<()> {
        self.db.add_device(service_id, device).await
    }

    pub async fn get_all_devices(&self, service_id: &ServiceId) -> Result<Vec<Device>> {
        self.db.get_all_devices(service_id).await
    }
    pub async fn get_device(&self, address: &ProtocolAddress) -> Result<Device> {
        self.db.get_device(address).await
    }
    pub async fn delete_device(&self, address: &ProtocolAddress) -> Result<()> {
        self.db.delete_device(address).await
    }

    pub async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        self.db.store_key_bundle(data, address).await
    }
}
