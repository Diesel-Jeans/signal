use anyhow::Result;
use axum::async_trait;
use common::signal_protobuf::Envelope;
use common::web_api::{Account, Device, DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::DeviceId;

#[async_trait]
pub trait SignalDatabase: Clone {
    async fn add_account(&self, account: Account) -> Result<()>;

    async fn get_account(&self, aci: Option<String>, pni: Option<String>) -> Result<Account>;
    async fn update_account_aci(
        &self,
        old_aci: Option<String>,
        new_aci: Option<String>,
    ) -> Result<()>;
    async fn update_account_pni(
        &self,
        old_pni: Option<String>,
        new_pni: Option<String>,
    ) -> Result<()>;

    async fn delete_account(&self, aci: Option<String>, pni: Option<String>) -> Result<()>;

    async fn get_devices(&self, owner: &Account) -> Result<Vec<Device>>;

    async fn get_device(&self, owner: &Account, device_id: DeviceId) -> Result<Device>;

    async fn delete_device(&self, owner: &Account, id: DeviceId) -> Result<()>;

    async fn push_msg_queue(
        &self,
        d_receiver: &Device,
        a_receiver: &Account,
        msg: &Envelope,
    ) -> Result<()>;
    async fn pop_msg_queue(
        &self,
        d_receiever: &Device,
        a_receiver: &Account,
    ) -> Result<Vec<Envelope>>;
    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        owner: &Device,
        account: &Account,
    ) -> Result<()>;
    async fn get_key_bundle(
        &self,
        d_owner: &Device,
        a_owner: &Account,
    ) -> Result<DevicePreKeyBundle>;
    async fn get_one_time_pre_key_count(&self, account: &Account) -> Result<u32>;
    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        d_owner: &Device,
        a_owner: &Account,
    ) -> Result<()>;

    async fn add_device(&self, owner: &Account, device: Device) -> Result<()>;
    async fn get_one_time_pre_key(
        &self,
        d_owner: &Device,
        a_owner: &Account,
    ) -> Result<UploadSignedPreKey>;
}
