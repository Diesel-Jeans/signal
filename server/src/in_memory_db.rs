use crate::database::DeviceID;
use crate::database::PreKeyBundle;
use crate::database::SignalDatabase;
use crate::database::UserID;
use crate::database::Username;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use axum::async_trait;
use common::pre_key::PreKey;
use common::signal_protobuf::Envelope;
use common::web_api::Account;
use common::web_api::Device;
use common::web_api::DevicePreKeyBundle;
use common::web_api::UploadSignedPreKey;
use libsignal_protocol::IdentityKey;
use libsignal_protocol::PublicKey;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::default;
use std::fmt::format;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct InMemorySignalDatabase {
    pub mail_queues: Arc<Mutex<HashMap<Device, VecDeque<Envelope>>>>,
    pub devices: Arc<Mutex<HashMap<UserID, Vec<Device>>>>,
    pub keys:
        Arc<Mutex<HashMap<UserID, HashMap<DeviceID, HashMap<PreKey, Vec<UploadSignedPreKey>>>>>>,
    pub accounts: Arc<Mutex<HashMap<String, Account>>>,
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
        self.devices.lock().await.entry(0).or_insert_with(Vec::new);
        Ok(())
    }
    async fn get_account(&self, aci: Option<String>, pni: Option<String>) -> Result<Account> {
        let id = aci
            .or(pni)
            .ok_or_else(|| anyhow!("No user id was supplied."))?;

        self.accounts
            .lock()
            .await
            .get(&id)
            .ok_or_else(|| anyhow!("No user exists with ID: {}", id))
            .map(Clone::clone)
    }
    async fn update_account_aci(
        &self,
        old_aci: Option<String>,
        new_aci: Option<String>,
    ) -> Result<()> {
        todo!()
    }
    async fn update_account_pni(
        &self,
        old_pni: Option<String>,
        new_pni: Option<String>,
    ) -> Result<()> {
        todo!()
    }

    async fn delete_account(&self, aci: Option<String>, pni: Option<String>) -> Result<()> {
        todo!()
    }

    async fn get_devices(&self, owner: &Account) -> Result<Vec<Device>> {
        todo!()
    }

    async fn get_device(&self, owner: &Account, device_id: DeviceID) -> Result<Device> {
        todo!()
    }

    async fn delete_device(&self, owner: &Account, id: DeviceID) -> Result<()> {
        todo!()
    }

    async fn push_msg_queue(
        &self,
        d_receiver: &Device,
        a_receiever: &Account,
        msg: &Envelope,
    ) -> Result<()> {
        self.mail_queues
            .lock()
            .await
            .get_mut(d_receiver)
            .ok_or(anyhow!(format!(
                "Device with id {} does not exist for user {}",
                d_receiver.device_id,
                a_receiever.aci.clone().unwrap()
            )))
            .map(|deque| deque.push_back(msg.clone()))
    }
    async fn pop_msg_queue(
        &self,
        d_receiever: &Device,
        a_receiver: &Account,
    ) -> Result<Vec<Envelope>> {
        todo!()
    }
    async fn store_key_bundle(
        &self,
        data: DevicePreKeyBundle,
        owner: &Device,
        account: &Account,
    ) -> Result<()> {
        todo!()
    }
    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        d_owner: &Device,
        a_owner: &Account,
    ) -> Result<()> {
        todo!()
    }

    async fn get_one_time_pre_key_count(&self, user: &UserID) -> Result<u32> {
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

    async fn add_device(&self, owner: &Account, device: Device) -> Result<()> {
        todo!()
        /*
        self.devices
            .lock()
            .await
            .get_mut(owner)
            .ok_or(format!("User {} does not exist.", owner))
            .map(|list| list.push(device.clone()))?;

        // Create a message queue for the given device.
        let id = device.id.clone();
        match self.mail_queues.lock().await.entry(device) {
            Entry::Occupied(occupied_entry) => {
                Err(format!("Could not add a message queue for device {} because a message queue already exists for this device.", id))
            },
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(VecDeque::new());
                Ok(())
            }
        }
        */
    }

    async fn get_key_bundle(
        &self,
        d_owner: &Device,
        a_owner: &Account,
    ) -> Result<DevicePreKeyBundle> {
        todo!()
    }
    async fn get_one_time_pre_key(
        &self,
        d_owner: &Device,
        a_owner: &Account,
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
