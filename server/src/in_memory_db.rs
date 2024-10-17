use crate::database::SignalDatabase;
use anyhow::{anyhow, bail, Result};
use axum::async_trait;
use common::pre_key::PreKey;
use common::signal_protobuf::Envelope;
use common::web_api::{Account, Device, DevicePreKeyBundle, UploadSignedPreKey};
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use libsignal_protocol::{IdentityKey, PublicKey};
use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};
use std::default;
use std::fmt::format;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct InMemorySignalDatabase {
    pub mail_queues: Arc<Mutex<HashMap<ProtocolAddress, VecDeque<Envelope>>>>,
    pub devices: Arc<Mutex<HashMap<ServiceId, Vec<Device>>>>,
    pub keys:
        Arc<Mutex<HashMap<ServiceId, HashMap<DeviceId, HashMap<PreKey, Vec<UploadSignedPreKey>>>>>>,
    pub accounts: Arc<Mutex<HashMap<ServiceId, Account>>>,
}
/*
impl InMemorySignalDatabase {

    async fn create_user_id_for(
    database: Arc<Mutex<InMemorySignalDatabase>>,
    username: &Username,
) -> Result<UserID, ErrorMessage> {
    let mut database = database.lock().await;
    if !database
        .usernames
        .iter()
        .any(|(_, existing)| *username == **existing)
    {
        use rand::distributions::{Alphanumeric, DistString};

        let id: UserID = Alphanumeric
            .sample_string(&mut rand::thread_rng(), 16)
            .parse()
            .unwrap();
        database.usernames.insert(id.clone(), username.clone());
        Ok(id)
    } else {
        Err("Username already exists".into())
    }
}


    async fn get_user_id_for(&self, username: &Username) -> Result<UserID, Error> {
        if let Some(id) = self
            .usernames
            .iter()
            .find(|(_, existing)| **existing == *username)
        {
            Ok(id.0.clone())
        } else {
            Err("Username not found".into())
        }
    }

    async fn create_new_device_id(
        database: Arc<Mutex<InMemorySignalDatabase>>,
        id: &UserID,
    ) -> Result<DeviceID, Error> {
        let mut database = database.lock().await;
        if let Some(devices) = database.devices.get_mut(id) {
            let max = *devices.iter().max().unwrap_or(&0u32);
            for i in 0u32.into()..max {
                if !devices.contains(&i) {
                    devices.insert(i.to_owned());
                    return Ok(i.to_owned());
                }
            }
            let new_device = max + 1;
            devices.insert(new_device);
            Ok(new_device)
        } else {
            Err("Device could not be created because user did not exist".into())
        }
    }
}
*/

#[async_trait]
impl SignalDatabase for InMemorySignalDatabase {
    async fn add_account(&self, account: Account) -> Result<()> {
        self.devices
            .lock()
            .await
            .entry(account.service_id())
            .or_insert_with(Vec::new);
        assert!(self
            .devices
            .lock()
            .await
            .contains_key(&account.service_id()));
        Ok(())
    }
    async fn get_account(&self, service_id: &ServiceId) -> Result<Account> {
        self.accounts
            .lock()
            .await
            .get(&service_id)
            .ok_or_else(|| anyhow!("No user exists with ID"))
            .map(Clone::clone)
    }
    async fn update_account_aci(&self, old_service_id: ServiceId, new_aci: Aci) -> Result<()> {
        todo!()
    }
    async fn update_account_pni(&self, old_service_id: ServiceId, new_pni: Pni) -> Result<()> {
        todo!()
    }

    async fn delete_account(&self, service_id: &ServiceId) -> Result<()> {
        todo!()
    }

    async fn get_devices(&self, owner: &ServiceId) -> Result<Vec<Device>> {
        todo!()
    }

    async fn get_device(&self, owner: &ServiceId, device_id: DeviceId) -> Result<Device> {
        todo!()
    }

    async fn delete_device(&self, address: ProtocolAddress) -> Result<()> {
        todo!()
    }

    async fn push_msg_queue(&self, address: ProtocolAddress, msg: &Envelope) -> Result<()> {
        self.mail_queues
            .lock()
            .await
            .get_mut(&address)
            .ok_or(anyhow!(format!(
                "Device with id {} does not exist for user {}",
                address.device_id(),
                address.name()
            )))
            .map(|deque| deque.push_back(msg.clone()))
    }
    async fn pop_msg_queue(&self, address: ProtocolAddress) -> Result<Vec<Envelope>> {
        todo!()
    }
    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        owner_address: ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }
    async fn get_key_bundle(&self, address: ProtocolAddress) -> Result<DevicePreKeyBundle> {
        todo!()
    }

    async fn get_one_time_pre_key_count(&self, account: &ServiceId) -> Result<u32> {
        todo!()
        /*
        database
        .keys
        .get(&usr_id)
        .and_then(|device_map| device_map.get(&device_id))
        .and_then(|key_map| key_map.get(&PreKey::OneTime))
        .and_then(|key_list| Some(key_list.len()))
        .ok_or_else(|| anyhow::anyhow!("Could not get one time pre key count"))
        */
    }

    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner_address: ProtocolAddress,
    ) -> Result<()> {
        todo!()
    }

    async fn add_device(&self, owner: &ServiceId, device: Device) -> Result<()> {
        self.devices
            .lock()
            .await
            .get_mut(&owner)
            .ok_or(anyhow!("User does not exist."))
            .map(|list| list.push(device.clone()))?;

        // Create a message queue for the given device.
        let address = ProtocolAddress::new(owner.service_id_string(), device.device_id());
        match self.mail_queues.lock().await.entry(address.clone()) {
            Entry::Occupied(occupied_entry) => {
                bail!("Could not add a message queue for device {} because a message queue already exists for this device.", address)
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(VecDeque::new());
                Ok(())
            }
        }
    }
    async fn get_one_time_pre_key(
        &self,
        owner_address: ProtocolAddress,
    ) -> Result<UploadSignedPreKey> {
        todo!()
    }
}

impl InMemorySignalDatabase {
    pub fn new() -> Self {
        Self {
            mail_queues: Arc::new(Mutex::new(HashMap::new())),
            devices: Arc::new(Mutex::new(HashMap::new())),
            keys: Arc::new(Mutex::new(HashMap::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
