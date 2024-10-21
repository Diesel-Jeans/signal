use crate::account::Account;
use anyhow::Result;
use axum::async_trait;
use common::signal_protobuf::Envelope;
use common::web_api::{DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};

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
    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()>;

    /// Add an PNI to an account overriding the existing PNI if any.
    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()>;

    /// Delete the account associated with the given [ServiceId].
    async fn delete_account(&self, service_id: &ServiceId) -> Result<()>;

    /// Send a message to a given [ProtocolAddress].
    async fn push_message_queue(
        &self,
        address: ProtocolAddress,
        messages: Vec<Envelope>,
    ) -> Result<()>;

    /// Retreive a message that was sent to the given [ProtocolAddress].
    async fn pop_msg_queue(&self, address: ProtocolAddress) -> Result<Vec<Envelope>>;

    /// Store the keys that are needed to start a conversation with the device that
    /// corrosponds to the given [ProtocolAddress].
    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        address: ProtocolAddress,
    ) -> Result<()>;

    /// Get the keys that are needed to start a conversation with the device that
    /// corrosponds to the given [ProtocolAddress].
    async fn get_key_bundle(&self, address: ProtocolAddress) -> Result<DevicePreKeyBundle>;

    /// Get how many keys are left until a last resort key is used instead of
    /// a one time prekey. More keys should be uploaded when this value is below
    /// some threshold.
    async fn get_one_time_pre_key_count(&self, service_id: &ServiceId) -> Result<u32>;

    /// Store new one time prekeys to avoid running out.
    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: ProtocolAddress,
    ) -> Result<()>;

    /// Get a one time prekey so that you can start a conversation with the
    /// device that is associated with the given [ProtocolAddress].
    async fn get_one_time_pre_key(&self, owner: ProtocolAddress) -> Result<UploadSignedPreKey>;
}
