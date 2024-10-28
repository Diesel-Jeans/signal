use anyhow::Result;
use common::web_api::AccountAttributes;
use libsignal_protocol::IdentityKey;
use sqlx::database;

use crate::{account::Device, database::SignalDatabase};

#[derive(Debug, Clone)]
pub struct AccountManager<T: SignalDatabase> {
    database: T,
}

impl<T: SignalDatabase> AccountManager<T> {
    pub fn new(database: T) -> Self {
        Self { database }
    }

    pub async fn create_account(
        &self,
        phone_number: String,
        account_attributes: AccountAttributes,
        aci_identity_key: IdentityKey,
        pni_identity_key: IdentityKey,
        primary_device: Device,
    ) -> Result<()> {
        println!("Creating Account");
        Ok(())
    }

    pub fn get_account(&self) {}

    pub fn update_account_aci(&self) {}

    pub fn update_account_pni(&self) {}

    pub fn delete_account(&self) {}
}
