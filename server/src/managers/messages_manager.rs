use crate::database::SignalDatabase;
use crate::message_cache::{MessageAvailabilityListener, MessageCache};
use crate::postgres::PostgresDatabase;
use anyhow::{Ok, Result};
use common::signal_protobuf::{envelope, Envelope};
use libsignal_core::{DeviceId, ProtocolAddress};
use std::sync::Arc;
use tokio::sync::Mutex;

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
    pub async fn insert(
        &self,
        user_id: &str,
        device_id: DeviceId,
        mut envelope: Envelope,
        message_guid: &str,
    ) -> Result<u64> {
        Ok(self
            .message_cache
            .insert(user_id, device_id, envelope, message_guid)
            .await
            .unwrap())
    }

    pub async fn may_have_persisted_messages(
        &self,
        user_id: &str,
        device_id: DeviceId,
    ) -> Result<(bool, &str)> {
        let cache_has_messages = self.message_cache.has_messages(user_id, device_id).await?;
        let db_has_messages = self.has_messages(user_id, device_id).await?;

        // assert_eq!(cache_has_messages, true);
        // assert_eq!(db_has_messages, true);

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
        user_id: &str,
        device_id: DeviceId,
        cached_msg_only: bool,
    ) -> Result<Vec<Envelope>> {
        let cached_messages = self
            .message_cache
            .get_all_messages(user_id, device_id)
            .await?;

        // TODO: get all DB messages

        Ok([cached_messages].concat())
    }

    pub async fn delete(
        &self,
        user_id: &str,
        device_id: DeviceId,
        message_guids: Vec<String>,
    ) -> Result<Vec<Envelope>> {
        let removed_messages = self
            .message_cache
            .remove(user_id, device_id, message_guids)
            .await?;

        // TODO: deleteMessage in DB

        Ok(removed_messages)
    }

    /// Remove messages from cache and store in DB
    pub async fn persist_messages(
        &self,
        user_id: &str,
        device_id: DeviceId,
        messages: Vec<Envelope>,
    ) -> Result<usize> {
        let message_guids: Vec<String> = messages
            .iter()
            .map(|m| m.server_guid().to_string())
            .collect();

        // TODO: store in DB first

        let removed_from_cache = self
            .message_cache
            .remove(user_id, device_id, message_guids)
            .await?;

        Ok(removed_from_cache.len())
    }

    pub fn add_message_availability_listener(
        &mut self,
        user_id: &str,
        device_id: DeviceId,
        listener: Arc<Mutex<U>>,
    ) {
        self.message_cache
            .add_message_availability_listener(user_id, device_id, listener);
    }

    pub fn remove_message_availability_listener(&mut self, user_id: &str, device_id: DeviceId) {
        self.message_cache
            .remove_message_availability_listener(user_id, device_id);
    }
}

impl<T, U> MessagesManager<T, U>
where
    T: SignalDatabase,
    U: MessageAvailabilityListener,
{
    async fn has_messages(&self, user_id: &str, device_id: DeviceId) -> Result<bool> {
        let address = ProtocolAddress::new(user_id.to_string(), device_id);
        let count = self.message_db.has_messages(&address).await?;
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
            server_guid: Some(Uuid::new_v4().to_string()),
            destination_service_id: Some(account.aci().service_id_string()),
            ..Default::default()
        }
    }

    fn create_device(device_id: u32, name: &str) -> Device {
        let last_seen = 0;
        let created = 0;
        let auth_token = vec![0];
        let salt = String::from("salt");
        return Device::new(
            device_id.into(),
            name.to_string(),
            last_seen,
            created,
            auth_token,
            salt,
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

    fn create_account() -> Account {
        let pni = Pni::from(Uuid::new_v4());
        let device = create_device(0, "Alice");
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
        let account = create_account();
        let account_aci = account.aci().service_id_string();
        let user_id = Uuid::new_v4().to_string();
        let device_id = create_device(0, &user_id).device_id();
        let envelope = generate_random_envelope(&account, "Hello Bob");

        msg_manager
            .message_cache
            .insert(
                &user_id,
                device_id,
                envelope.clone(),
                envelope.server_guid(),
            )
            .await;

        let result = msg_manager
            .may_have_persisted_messages(&user_id, device_id)
            .await
            .unwrap();

        teardown(&msg_manager);

        assert_eq!(result, (true, "cached"));
    }

    #[tokio::test]
    #[serial]
    async fn test_may_have_both_cached_and_db_persisted_messages() {
        let msg_manager = init_manager().await.unwrap();
        let account = create_account();
        let account_aci = account.aci().service_id_string();
        let user_id = Uuid::new_v4().to_string();
        let device_id = create_device(0, &user_id).device_id();
        let envelope = generate_random_envelope(&account, "Hello Bob");

        // Cache
        msg_manager
            .message_cache
            .insert(
                &account_aci.clone().as_str(),
                device_id,
                envelope.clone(),
                envelope.server_guid(),
            )
            .await;

        // DB
        msg_manager.message_db.add_account(&account).await.unwrap();

        let address = ProtocolAddress::new(account_aci.clone(), device_id);
        msg_manager
            .message_db
            .push_message_queue(&address, vec![&envelope])
            .await
            .unwrap();

        let may_have_messages = msg_manager
            .may_have_persisted_messages(&account_aci.to_string().as_str(), device_id)
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
    async fn test_db_msg() {
        let msg_manager = init_manager().await.unwrap();
        let account = create_account();
        let account_aci = account.aci().service_id_string();
        let user_id = Uuid::new_v4().to_string();
        let device_id = create_device(0, &user_id).device_id();
        let envelope = generate_random_envelope(&account, "Hello Bob");

        msg_manager.message_db.add_account(&account).await.unwrap();

        let address = ProtocolAddress::new(account_aci, device_id);
        msg_manager
            .message_db
            .push_message_queue(&address, vec![&envelope])
            .await
            .unwrap();

        let count = msg_manager.message_db.has_messages(&address).await.unwrap();

        // Teardown DB
        msg_manager
            .message_db
            .delete_account(&ServiceId::Aci(account.aci()))
            .await
            .unwrap();

        assert_eq!(count, 1);
    }
}
