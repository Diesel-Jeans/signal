use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use anyhow::{anyhow, Result};
use axum::async_trait;
use common::pre_key::PreKeyType;
use common::signal_protobuf::Envelope;
use common::web_api::{DevicePreKeyBundle, UploadPreKey, UploadSignedPreKey};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

type MessageTable = HashMap<ProtocolAddress, VecDeque<Envelope>>;
type DeviceTable = HashMap<ServiceId, Vec<Device>>;
type KeysTable =
    HashMap<ServiceId, HashMap<DeviceId, HashMap<PreKeyType, Vec<UploadSignedPreKey>>>>;

#[cfg(test)]
#[derive(Clone)]
pub struct MockDB{}

#[cfg(test)]
#[async_trait]
impl SignalDatabase for MockDB {
    async fn add_device(&self, service_id: &ServiceId, device: &Device) -> Result<()> {
        todo!()
    }
    async fn get_all_devices(&self, service_id: &ServiceId) -> Result<Vec<Device>> {
        todo!()
    }
    async fn get_device(&self, service_id: &ServiceId, device_id: u32) -> Result<Device> {
        todo!()
    }
    async fn delete_device(&self, service_id: &ServiceId, device_id: u32) -> Result<()> {
        todo!()
    }
    async fn store_aci_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        todo!()
    }

    async fn store_pni_signed_pre_key(&self, spk: &UploadSignedPreKey) -> Result<()> {
        todo!()
    }

    async fn store_pq_aci_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        todo!()
    }

    async fn store_pq_pni_signed_pre_key(&self, pq_spk: &UploadSignedPreKey) -> Result<()> {
        todo!()
    }

    async fn add_account(&self, account: &Account) -> Result<()> {
        todo!()
    }
    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        todo!()
    }
    async fn update_account_aci(&self, service_id: &ServiceId, new_aci: Aci) -> Result<()> {
        todo!()
    }
    async fn update_account_pni(&self, service_id: &ServiceId, new_pni: Pni) -> Result<()> {
        todo!()
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        todo!()
    }

    async fn push_message_queue(
        &self,
        address: ProtocolAddress,
        messages: Vec<Envelope>,
    ) -> Result<()> {
        todo!()
    }
    async fn pop_msg_queue(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        todo!()
    }
    async fn store_key_bundle(
        &self,
        data: &DevicePreKeyBundle,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }
    async fn get_key_bundle(&self, address: &ProtocolAddress) -> Result<DevicePreKeyBundle> {
        todo!()
    }

    async fn get_one_time_ec_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn get_one_time_pq_pre_key_count(&self, service_id: &ServiceId) -> Result<u32> {
        todo!()
    }

    async fn store_one_time_ec_pre_keys(
        &self,
        otpks: Vec<UploadPreKey>,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn store_one_time_pq_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner_address: &ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn get_one_time_ec_pre_key(
        &self,
        owner_address: &ProtocolAddress,
    ) -> Result<UploadPreKey> {
        todo!()
    }

    async fn get_one_time_pq_pre_key(
        &self,
        owner_address: &ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        todo!()
    }
}