use crate::database::SignalDatabase;
use anyhow::Result;
use common::web_api::{DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::{ProtocolAddress, ServiceId};

#[derive(Debug, Clone)]
pub struct KeyManager {}

impl KeyManager {
    pub fn new() -> Self {
        Self {}
    }
    pub async fn store_aci_signed_pre_key<T: SignalDatabase>(
        &self,
        db: &T,
        spk: &UploadSignedPreKey,
    ) -> Result<()> {
        db.store_aci_signed_pre_key(spk).await
    }

    pub async fn store_pni_signed_pre_key<T: SignalDatabase>(
        &self,
        db: &T,
        spk: &UploadSignedPreKey,
    ) -> Result<()> {
        db.store_pni_signed_pre_key(spk).await
    }

    pub async fn store_pq_aci_signed_pre_key<T: SignalDatabase>(
        &self,
        db: &T,
        pq_spk: &UploadSignedPreKey,
    ) -> Result<()> {
        db.store_pq_aci_signed_pre_key(pq_spk).await
    }

    pub async fn store_pq_pni_signed_pre_key<T: SignalDatabase>(
        &self,
        db: &T,
        pq_spk: &UploadSignedPreKey,
    ) -> Result<()> {
        db.store_pq_pni_signed_pre_key(pq_spk).await
    }

    pub async fn store_key_bundle<T: SignalDatabase>(
        &self,
        db: &T,
        data: &DevicePreKeyBundle,
        address: &ProtocolAddress,
    ) -> Result<()> {
        db.store_key_bundle(data, address).await
    }

    pub async fn get_key_bundle<T: SignalDatabase>(
        &self,
        db: &T,
        address: &ProtocolAddress,
    ) -> Result<DevicePreKeyBundle> {
        db.get_key_bundle(address).await
    }

    pub async fn get_one_time_pre_key_count<T: SignalDatabase>(
        &self,
        db: &T,
        service_id: &ServiceId,
    ) -> Result<u32> {
        db.get_one_time_pre_key_count(service_id).await
    }

    pub async fn store_one_time_pre_keys<T: SignalDatabase>(
        &self,
        db: &T,
        otpks: Vec<UploadSignedPreKey>,
        owner: &ProtocolAddress,
    ) -> Result<()> {
        db.store_one_time_pre_keys(otpks, owner).await
    }

    pub async fn get_one_time_pre_key<T: SignalDatabase>(
        &self,
        db: &T,
        owner: &ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        db.get_one_time_pre_key(owner).await
    }
}
