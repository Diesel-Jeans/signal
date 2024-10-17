use anyhow::Result;
use axum::async_trait;
use common::signal_protobuf::Envelope;
use common::web_api::{Account, Device, DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};

/// Represents a database connection that can store objects related to the signal protocol.
#[async_trait]
pub trait SignalDatabase: Clone {
    /// Save a new account to the database.
    async fn add_account(&self, account: Account) -> Result<()>;

    /// Get an account that was saved in the database.
    ///
    /// Beware: the account can be saved using either ACI, PNI or both,
    /// So if you search for an account using an ACI, you will not find
    /// it if the account only has a PNI in the database.
    async fn get_account(&self, service_id: &ServiceId) -> Result<Account>;

    /// Add an ACI to an account overriding the existing ACI if any.
    async fn update_account_aci(&self, old_service_id: ServiceId, new_aci: Aci) -> Result<()>;

    /// Add an PNI to an account overriding the existing PNI if any.
    async fn update_account_pni(&self, old_service_id: ServiceId, new_pni: Pni) -> Result<()>;

    /// Delete the account associated with the given [ServiceId].
    async fn delete_account(&self, service_id: &ServiceId) -> Result<()>;

    /// Get all devices for the user.
    async fn get_devices(&self, owner: &ServiceId) -> Result<Vec<Device>>;

    /// Get a single device with the given [DeviceId].
    async fn get_device(&self, owner: &ServiceId, device_id: DeviceId) -> Result<Device>;

    /// Delete a device.
    async fn delete_device(&self, address: ProtocolAddress) -> Result<()>;

    /// Send a message to a given [ProtocolAddress].
    async fn push_msg_queue(&self, address: ProtocolAddress, msg: &Envelope) -> Result<()>;

    /// Retreive a message that was sent to the given [ProtocolAddress].
    async fn pop_msg_queue(&self, address: ProtocolAddress) -> Result<Vec<Envelope>>;

    /// Store the keys that are needed to start a conversation with the device that
    /// corrosponds to the given [ProtocolAddress].
    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        owner_address: ProtocolAddress,
    ) -> Result<()>;

    /// Get the keys that are needed to start a conversation with the device that
    /// corrosponds to the given [ProtocolAddress].
    async fn get_key_bundle(&self, address: ProtocolAddress) -> Result<DevicePreKeyBundle>;

    /// Get how many keys are left until a last resort key is used instead of
    /// a one time prekey. More keys should be uploaded when this value is below
    /// some threshold.
    async fn get_one_time_pre_key_count(&self, account: &ServiceId) -> Result<u32>;

    /// Store new one time prekeys to avoid running out.
    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner_address: ProtocolAddress,
    ) -> Result<()>;

    /// Add a device to an account.
    async fn add_device(&self, owner: &ServiceId, device: Device) -> Result<()>;

    /// Get a one time prekey so that you can start a conversation with the
    /// device that is associated with the given [ProtocolAddress].
    async fn get_one_time_pre_key(
        &self,
        owner_address: ProtocolAddress,
    ) -> Result<UploadSignedPreKey>;
}
