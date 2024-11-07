use crate::database::SignalDatabase;
use crate::message_cache::{MessageAvailabilityListener, MessageCache};
use crate::postgres::PostgresDatabase;
use anyhow::{Ok, Result};
use common::signal_protobuf::{envelope, Envelope};
use libsignal_core::{DeviceId, ProtocolAddress};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct MessagesManager<T, U>
where
    T: SignalDatabase,
    U: MessageAvailabilityListener,
{
    message_db: T,
    message_cache: MessageCache<U>,
}

impl<T, U> MessagesManager<T, U>
where
    T: SignalDatabase,
    U: MessageAvailabilityListener,
{
    pub async fn insert(&self, address: &ProtocolAddress, envelope: &mut Envelope) -> Result<u64> {
        let message_guid = Uuid::new_v4().to_string();

        Ok(self
            .message_cache
            .insert(address, envelope, &message_guid)
            .await
            .unwrap())
    }

    pub async fn may_have_persisted_messages(
        &self,
        address: &ProtocolAddress,
    ) -> Result<(bool, &str)> {
        let cache_has_messages = self.message_cache.has_messages(address).await?;
        let db_has_messages = self.has_messages(address).await?;

        let outcome = if (cache_has_messages && db_has_messages) {
            "both"
        } else if (cache_has_messages) {
            "cached"
        } else if (db_has_messages) {
            "persisted"
        } else {
            "none"
        };

        Ok((cache_has_messages || db_has_messages, outcome))
    }

    pub async fn get_messages_for_device(
        &self,
        address: &ProtocolAddress,
        cached_msg_only: bool,
    ) -> Result<Vec<Envelope>> {
        let cached_messages = self.message_cache.get_all_messages(address).await?;

        let db_messages = if !cached_msg_only {
            self.message_db.get_messages(address).await?
        } else {
            vec![]
        };

        Ok([cached_messages, db_messages].concat())
    }

    pub async fn delete(
        &self,
        address: &ProtocolAddress,
        message_guids: Vec<String>,
    ) -> Result<Vec<Envelope>> {
        let cache_removed_messages = self.message_cache.remove(address, message_guids).await?;

        let db_removed_messages = self.message_db.delete_messages(address).await?;

        Ok([cache_removed_messages, db_removed_messages].concat())
    }

    /// Remove messages from cache and store in DB
    pub async fn persist_messages(
        &self,
        address: &ProtocolAddress,
        messages: Vec<Envelope>,
    ) -> Result<usize> {
        let message_guids: Vec<String> = messages
            .iter()
            .map(|m| m.server_guid().to_string())
            .collect();

        self.message_db
            .push_message_queue(address, messages)
            .await?;

        let removed_from_cache = self.message_cache.remove(address, message_guids).await?;

        Ok(removed_from_cache.len())
    }

    pub fn add_message_availability_listener(
        &mut self,
        address: &ProtocolAddress,
        listener: Arc<Mutex<U>>,
    ) {
        self.message_cache
            .add_message_availability_listener(address, listener);
    }

    pub fn remove_message_availability_listener(&mut self, address: &ProtocolAddress) {
        self.message_cache
            .remove_message_availability_listener(address);
    }
}

impl<T, U> MessagesManager<T, U>
where
    T: SignalDatabase,
    U: MessageAvailabilityListener,
{
    async fn has_messages(&self, address: &ProtocolAddress) -> Result<bool> {
        let count = self.message_db.count_messages(address).await?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod message_manager_tests {
    use std::{default, string};

    use crate::account::{self, Account, AuthenticatedDevice, Device};
    use crate::message_cache::message_cache_tests::MockWebSocketConnection;
    use crate::message_cache::MessageCache;
    use crate::postgres::PostgresDatabase;
    use anyhow::Result;
    use common::web_api::{AccountAttributes, DeviceCapabilities};
    use deadpool_redis::redis::cmd;
    use libsignal_core::{Aci, Pni, ProtocolAddress, ServiceId};
    use libsignal_protocol::{IdentityKey, PublicKey};
    use serial_test::serial;
    use uuid::Uuid;

    use super::*;

    async fn init_manager() -> Result<MessagesManager<PostgresDatabase, MockWebSocketConnection>> {
        Ok(
            MessagesManager::<PostgresDatabase, MockWebSocketConnection> {
                message_cache: MessageCache::connect().await.unwrap(),
                message_db: PostgresDatabase::connect("DATABASE_URL_TEST".to_string())
                    .await
                    .unwrap(),
            },
        )
    }

    async fn teardown(msg_manager: &MessagesManager<PostgresDatabase, MockWebSocketConnection>) {
        let mut conn = msg_manager.message_cache.get_connection().await.unwrap();
        cmd("FLUSHALL").query_async::<()>(&mut conn).await.unwrap();
    }

    fn generate_random_envelope(account: &Account, message: &str) -> Envelope {
        Envelope {
            content: Some(bincode::serialize(message).unwrap()),
            ..Default::default()
        }
    }

    fn create_device(device_id: u32, name: &str) -> Device {
        let last_seen = 0;
        let created = 0;
        let auth_token = vec![0];
        let salt = String::from("salt");
        let registration_id = 0;
        return Device::new(
            device_id.into(),
            name.to_string(),
            last_seen,
            created,
            auth_token,
            salt,
            registration_id,
        );
    }

    fn create_identity_key() -> IdentityKey {
        let mut identity_key = [0u8; 33];
        identity_key[0] = 5;
        return IdentityKey::new(PublicKey::deserialize(&identity_key).unwrap());
    }

    fn create_account_attributes() -> AccountAttributes {
        return AccountAttributes {
            fetches_messages: true,
            registration_id: 0,
            pni_registration_id: 0,
            capabilities: DeviceCapabilities {
                storage: true,
                transfer: true,
                payment_activation: true,
                delete_sync: true,
                versioned_expiration_timer: true,
            },
            unidentified_access_key: Box::new([1u8, 2u8, 3u8]),
        };
    }

    fn create_account(device: Device) -> Account {
        let pni = Pni::from(Uuid::new_v4());
        let pni_identity_key = create_identity_key();
        let aci_identity_key = create_identity_key();
        let phone_number = "420-1337-69";
        let account_attr = create_account_attributes();
        return Account::new(
            pni,
            device,
            pni_identity_key,
            aci_identity_key,
            phone_number.to_string(),
            account_attr,
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_may_have_cached_persisted_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let mut envelope = generate_random_envelope(&account, "Hello Bob");

        // Cache
        msg_manager.insert(&address, &mut envelope).await;

        // Act
        let may_have_messages = msg_manager
            .may_have_persisted_messages(&address)
            .await
            .unwrap();

        // Teardown cache
        teardown(&msg_manager);

        assert_eq!(may_have_messages, (true, "cached"));
    }

    #[tokio::test]
    #[serial]
    async fn test_may_have_persisted_persisted_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let envelope = generate_random_envelope(&account, "Hello Bob");

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope])
            .await
            .unwrap();

        // Act
        let may_have_messages = msg_manager
            .may_have_persisted_messages(&address)
            .await
            .unwrap();

        // Teardown DB
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(may_have_messages, (true, "persisted"));
    }

    #[tokio::test]
    #[serial]
    async fn test_may_have_both_cached_and_db_persisted_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let mut envelope = generate_random_envelope(&account, "Hello Bob");

        // Cache
        msg_manager.insert(&address, &mut envelope).await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope])
            .await
            .unwrap();

        // Act
        let may_have_messages = msg_manager
            .may_have_persisted_messages(&address)
            .await
            .unwrap();

        // Teardown DB and cache
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(may_have_messages, (true, "both"));
    }

    #[tokio::test]
    #[serial]
    async fn test_count_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let envelope = generate_random_envelope(&account, "Hello Bob");

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope])
            .await
            .unwrap();

        // Act
        let count = msg_manager
            .message_db
            .count_messages(&address)
            .await
            .unwrap();

        // Teardown DB
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_messages_for_device() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(0, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let mut envelope1 = generate_random_envelope(&account, "Hello Bob");
        let mut envelope2 = generate_random_envelope(&account, "How are you?");

        // Cache
        msg_manager.insert(&address, &mut envelope1).await;

        msg_manager.insert(&address, &mut envelope2).await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope1, envelope2])
            .await
            .unwrap();

        let messages_for_device_cache_and_db = msg_manager
            .get_messages_for_device(&address, false)
            .await
            .unwrap();

        // Teardown DB and cache
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(messages_for_device_cache_and_db.len(), 4);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_cache_only_messages_for_device() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci, device_id);

        let mut envelope = generate_random_envelope(&account, "Hello Bob");

        // Cache
        msg_manager.insert(&address, &mut envelope).await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope])
            .await
            .unwrap();

        // Act
        let messages_for_device_cache_only = msg_manager
            .get_messages_for_device(&address, true)
            .await
            .unwrap();

        let messages_for_device_db_and_cache = msg_manager
            .get_messages_for_device(&address, false)
            .await
            .unwrap();

        // Teardown DB and cache
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(messages_for_device_cache_only.len(), 1);
        assert_eq!(messages_for_device_db_and_cache.len(), 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci.clone(), device_id);

        let mut envelope1 = generate_random_envelope(&account, "Hello Bob");
        let mut envelope2 = generate_random_envelope(&account, "How are you?");

        // Cache
        msg_manager.insert(&address, &mut envelope1).await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        msg_manager
            .message_db
            .push_message_queue(&address, vec![envelope1.clone(), envelope2.clone()])
            .await
            .unwrap();

        // Act
        let messages_for_device_db_and_cache = msg_manager
            .get_messages_for_device(&address, false)
            .await
            .unwrap();

        let deleted_messages = msg_manager
            .delete(
                &address,
                vec![
                    envelope1.server_guid().to_string(),
                    envelope2.server_guid().to_string(),
                ],
            )
            .await
            .unwrap();

        // Teardown DB and cache
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(messages_for_device_db_and_cache.len(), 3);
        assert_eq!(deleted_messages.len(), 3);
    }

    #[tokio::test]
    #[serial]
    async fn test_persist_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device = create_device(1, &user_id);
        let device_id = device.device_id();

        let account = create_account(device);
        let account_aci = account.aci().service_id_string();

        let address = ProtocolAddress::new(account_aci.clone(), device_id);

        let mut envelope1 = generate_random_envelope(&account, "Hello Bob");
        let mut envelope2 = generate_random_envelope(&account, "How are you?");

        // Cache
        msg_manager.insert(&address, &mut envelope1).await;

        msg_manager.insert(&address, &mut envelope2).await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        // Act
        let messages_in_cache = msg_manager
            .get_messages_for_device(&address, true)
            .await
            .unwrap();

        let messages_in_db = msg_manager.message_db.get_messages(&address).await.unwrap();

        let count_persisted_in_db = msg_manager
            .persist_messages(&address, vec![envelope1, envelope2])
            .await
            .unwrap();

        // Teardown DB and cache
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(messages_in_cache.len(), 2);
        assert_eq!(messages_in_db.len(), 0);
        assert_eq!(count_persisted_in_db, 2);
    }
}
