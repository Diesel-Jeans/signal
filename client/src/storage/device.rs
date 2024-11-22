use super::generic::{ProtocolStore, SignalStore, Storage};
use crate::storage::generic::StorageType;
use axum::async_trait;
use libsignal_core::ProtocolAddress;
use libsignal_core::{Aci, Pni};
use libsignal_protocol::{
    Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, SenderKeyRecord, SenderKeyStore,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore,
};
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

#[derive(Debug)]
pub struct Device;

impl Storage<Device> {
    pub async fn create(
        aci: Aci,
        pni: Pni,
        password: String,
        protocol_store: ProtocolStore<Device>,
    ) {
        todo!()
    }
}

#[async_trait]
impl SignalStore for Storage<Device> {
    async fn set_password(&mut self, new_password: String) {
        todo!()
    }

    async fn get_password(&self) -> &str {
        todo!()
    }

    async fn set_aci(&mut self, new_aci: libsignal_core::Aci) {
        todo!()
    }

    async fn get_aci(&self) -> &libsignal_core::Aci {
        todo!()
    }

    async fn set_pni(&mut self, new_pni: libsignal_core::Pni) {
        todo!()
    }

    async fn get_pni(&self) -> &libsignal_core::Pni {
        todo!()
    }
}

impl StorageType for Device {
    type IdentityKeyStore = DeviceIdentityKeyStore;
    type PreKeyStore = DevicePreKeyStore;
    type SignedPreKeyStore = DeviceSignedPreKeyStore;
    type KyberPreKeyStore = DeviceKyberPreKeyStore;
    type SessionStore = DeviceSessionStore;
    type SenderKeyStore = DeviceSenderKeyStore;
}

pub struct DeviceIdentityKeyStore {
    pool: Pool<Sqlite>,
}

impl DeviceIdentityKeyStore {
    pub async fn create(
        key_pair: IdentityKeyPair,
        registration_id: u32,
        pool: Pool<Sqlite>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        todo!()
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for DeviceIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        todo!()
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        todo!()
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        todo!()
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        todo!()
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        todo!()
    }
}

pub struct DevicePreKeyStore {
    pool: Pool<Sqlite>,
}

impl DevicePreKeyStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl PreKeyStore for DevicePreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        todo!()
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

pub struct DeviceSignedPreKeyStore {
    pool: Pool<Sqlite>,
}

impl DeviceSignedPreKeyStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}
#[async_trait(?Send)]
impl SignedPreKeyStore for DeviceSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        todo!()
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

pub struct DeviceKyberPreKeyStore {
    pool: Pool<Sqlite>,
}

impl DeviceKyberPreKeyStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for DeviceKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        todo!()
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

pub struct DeviceSessionStore {
    pool: Pool<Sqlite>,
}

impl DeviceSessionStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait(?Send)]
impl SessionStore for DeviceSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        todo!()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

pub struct DeviceSenderKeyStore {
    pool: Pool<Sqlite>,
}

impl DeviceSenderKeyStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for DeviceSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        todo!()
    }
}
