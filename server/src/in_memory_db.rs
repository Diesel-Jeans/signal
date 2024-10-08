use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt::format;
use std::sync::Arc;

use crate::database::Device;
use crate::database::DeviceID;
use crate::database::Error;
use crate::database::PreKeyBundle;
use crate::database::SignalDatabase;
use crate::database::User;
use crate::database::UserID;
use crate::database::Username;
use axum::async_trait;
use common::pre_key::PreKey;
use common::signal_protobuf::Envelope;
use common::web_api::UploadSignedPreKey;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct InMemorySignalDatabase {
    pub mail_queues: Arc<Mutex<HashMap<Device, VecDeque<Envelope>>>>,
    pub devices: Arc<Mutex<HashMap<UserID, Vec<Device>>>>,
    pub keys:
        Arc<Mutex<HashMap<UserID, HashMap<DeviceID, HashMap<PreKey, Vec<UploadSignedPreKey>>>>>>,
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
    async fn add_user(&self, username: &str, password: &str) -> Result<(), Error> {
        self.devices.lock().await.entry(0).or_insert_with(Vec::new);
        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<User, Error> {
        todo!()
    }

    async fn update_user_username(
        &self,
        old_username: &str,
        new_username: &str,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn update_user_password(&self, username: &str, new_password: &str) -> Result<(), Error> {
        todo!()
    }

    async fn delete_user(&self, username: &str) -> Result<(), Error> {
        todo!()
    }

    async fn add_device(&self, owner: &UserID, device: Device) -> Result<(), Error> {
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
    }

    async fn get_devices(&self, owner: &User) -> Result<Vec<Device>, Error> {
        todo!()
    }

    async fn delete_device(&self, owner: &User, id: i32) -> Result<(), Error> {
        todo!()
    }

    async fn push_msg_queue(&self, reciver: &Device, msg: Envelope) -> Result<(), Error> {
        self.mail_queues
            .lock()
            .await
            .get_mut(reciver)
            .ok_or(format!(
                "Device with id {} does not exist for user {}",
                reciver.id, reciver.owner
            ))
            .map(|deque| deque.push_back(msg))
    }

    async fn pop_msg_queue(&self, reciver: &Device) -> Result<Vec<Envelope>, Error> {
        todo!()
    }

    async fn store_key_bundle(&self, data: PreKeyBundle, owner: &Device) -> Result<(), Error> {
        todo!()
    }

    async fn get_key_bundle(&self, owner: &Device) -> Result<PreKeyBundle, Error> {
        todo!()
    }

    async fn store_one_time_pre_keys(
        &self,
        otpks: Vec<UploadSignedPreKey>,
        owner: &Device,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn get_one_time_pre_key(&self, owner: &Device) -> Result<UploadSignedPreKey, Error> {
        todo!()
    }

    async fn get_one_time_pre_key_count(&self, user: &UserID) -> Result<u32, Error> {
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
}

impl InMemorySignalDatabase {
    pub fn new() -> Self {
        Self {
            mail_queues: Arc::new(Mutex::new(HashMap::new())),
            devices: Arc::new(Mutex::new(HashMap::new())),
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
