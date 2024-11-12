use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use crate::managers::account_manager::AccountManager;
use crate::managers::messages_manager::MessagesManager;
use crate::message_cache::{MessageAvailabilityListener, MessageCache};
use crate::postgres::PostgresDatabase;
use anyhow::Result;
use async_std::prelude::FutureExt;
use common::signal_protobuf::Envelope;
use libsignal_core::{ProtocolAddress, ServiceId};
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const QUEUE_BATCH_LIMIT: u8 = 100;
const MESSAGE_BATCH_LIMIT: u8 = 100;
const PERSIST_DELAY: u64 = 600;

#[derive(Debug)]
pub struct MessagePersister<T: SignalDatabase, U: MessageAvailabilityListener> {
    message_cache: MessageCache<U>,
    messages_manager: MessagesManager<T, U>,
    account_manager: AccountManager,
    db: T,
}

/*
 * Takes the message queues from the cache that is >10 minutes old,
 * removes them from the cache and puts them into the database using the MessagesManager
*/
impl<T, U> MessagePersister<T, U>
where
    T: SignalDatabase + Send + 'static + Sync,
    U: MessageAvailabilityListener + Send + 'static,
{
    pub fn new(
        message_manager: MessagesManager<T, U>,
        message_cache: MessageCache<U>,
        db: T,
        account_manager: AccountManager,
    ) -> Self {
        Self {
            message_cache,
            messages_manager: message_manager,
            account_manager,
            db,
        }
    }

    pub async fn start(
        mut message_persister: MessagePersister<T, U>,
        flag: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while !flag.load(Ordering::Relaxed) {
                message_persister.persist_next_queues().await;
            }
        })
    }

    pub async fn stop(flag: Arc<AtomicBool>) {
        flag.store(true, Ordering::Relaxed);
    }

    // Finds the message queues where the oldest message is >10 minutes old.
    async fn persist_next_queues(&mut self) -> Result<()> {
        let mut queues_to_persist: Vec<String> = Vec::new();
        let time = SystemTime::now();
        let time_in_secs: u64 = time.duration_since(UNIX_EPOCH)?.as_secs();
        let mut queues_persisted: Vec<String> = Vec::new();

        while {
            let time = SystemTime::now();
            let time_in_secs: u64 = time.duration_since(UNIX_EPOCH)?.as_secs();

            queues_to_persist = self
                .message_cache
                .get_message_queues_to_persist((time_in_secs - PERSIST_DELAY), QUEUE_BATCH_LIMIT)
                .await?;

            !queues_to_persist.is_empty()
        } {
            for queue_key in &queues_to_persist {
                let (account_id, device_id) = self
                    .message_cache
                    .get_account_and_device_id_from_queue_key(queue_key);

                let service_id =
                    ServiceId::parse_from_service_id_string(&account_id).ok_or_else(|| {
                        anyhow::anyhow!("Failed to parse service id from queue: {}", queue_key)
                    })?;

                let account = self
                    .account_manager
                    .get_account(&self.db, &service_id)
                    .await?;

                let device_id = device_id.parse::<u32>()?;

                let device = account
                    .devices()
                    .iter()
                    .find(|device| device.device_id() == device_id.into())
                    .ok_or_else(|| anyhow::anyhow!("Could not find device in account."))?;

                self.persist_queue(&account, &device).await?;
            }
        }

        Ok(())
    }

    // Takes the message queues where the oldest message is >10 minutes old.
    async fn persist_queue(&mut self, account: &Account, device: &Device) -> Result<()> {
        let message_count: u32 = 0;
        let mut messages: Vec<Envelope> = Vec::new();
        let protocol_address =
            ProtocolAddress::new(account.aci().service_id_string(), device.device_id());

        self.message_cache
            .lock_queue_for_persistence(&protocol_address);

        while {
            messages = self
                .message_cache
                .get_messages_to_persist(&protocol_address, MESSAGE_BATCH_LIMIT as i32)
                .await?;

            !messages.is_empty()
        } {
            let messages_removed_from_cache = self
                .messages_manager
                .persist_messages(&protocol_address, messages)
                .await?;
        }

        self.message_cache
            .unlock_queue_for_persistence(&protocol_address)
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod message_persister_tests {
    use super::*;
    use crate::managers::messages_manager::message_manager_tests::*;
    use crate::message_cache::message_cache_tests::{
        generate_random_envelope, generate_uuid, teardown, MockWebSocketConnection,
    };
    use crate::postgres::PostgresDatabase;
    use redis::cmd;
    use serial_test::serial;
    use std::time::Duration;
    use uuid::Uuid;

    async fn insert_with_custom_timestamp(
        message_cache: &MessageCache<MockWebSocketConnection>,
        timestamp: u64,
        protocol_address: &ProtocolAddress,
        envelope: &mut Envelope,
        message_guid: &str,
    ) {
        let mut connection = message_cache.get_connection().await.unwrap();
        let queue_total_index_key = message_cache.get_queue_index_key();
        let queue_key = message_cache.get_message_queue_key(protocol_address);

        cmd("ZADD")
            .arg(&queue_total_index_key)
            .arg("NX")
            .arg(timestamp)
            .arg(&queue_key)
            .query_async::<()>(&mut connection)
            .await
            .unwrap();

        message_cache
            .insert(protocol_address, envelope, message_guid)
            .await;
    }

    async fn check_queue_key_timestamp(
        message_cache: &MessageCache<MockWebSocketConnection>,
        max_time: u64,
        limit: u8,
    ) -> Vec<String> {
        let queue_index_key = message_cache.get_queue_index_key();
        let mut connection = message_cache.get_connection().await.unwrap();

        cmd("ZRANGE")
            .arg(&queue_index_key)
            .arg(0)
            .arg(&max_time)
            .arg("BYSCORE")
            .arg("LIMIT")
            .arg(0)
            .arg(&limit)
            .query_async::<Vec<String>>(&mut connection)
            .await
            .unwrap()
    }

    async fn has_messages(
        mut cache: &MessageCache<MockWebSocketConnection>,
        queue_keys: &Vec<String>,
    ) -> bool {
        let mut connection = cache.get_connection().await.unwrap();

        for queue_key in queue_keys {
            if cmd("ZCARD")
                .arg(&queue_key)
                .query_async::<u64>(&mut connection)
                .await
                .unwrap()
                != 0
            {
                return false;
            }
        }
        true
    }

    async fn no_queue_persist_keys_in_cache(
        message_cache: &MessageCache<MockWebSocketConnection>,
        protocol_addresses: &Vec<ProtocolAddress>,
    ) -> bool {
        let mut connection = message_cache.get_connection().await.unwrap();

        for address in protocol_addresses {
            let queue_lock_key = message_cache.get_persist_in_progress_key(address);

            let locked = cmd("GET")
                .arg(&queue_lock_key)
                .query_async::<Option<String>>(&mut connection)
                .await
                .unwrap();

            if let Some(queue_lock_key) = locked {
                return false;
            }
        }
        true
    }

    async fn message_persister_test_setup_run(
        message_times: Vec<u64>,
    ) -> (bool, bool, Vec<String>, Vec<String>) {
        let _ = dotenv::dotenv();
        let db = PostgresDatabase::connect("DATABASE_URL".to_string()).await;
        let cache = MessageCache::connect();
        let message_manager = MessagesManager::new(db.clone(), cache.clone());
        let account_manager = AccountManager::new();

        let message_persister: MessagePersister<PostgresDatabase, MockWebSocketConnection> =
            MessagePersister::new(message_manager, cache.clone(), db.clone(), account_manager);

        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ten_minutes_past_timestamp = now_timestamp - 600;

        let mut accounts = Vec::new();
        let mut protocol_addresses = Vec::new();

        for message_time in message_times {
            let user_id = Uuid::new_v4().to_string();
            let device = create_device(1, &user_id);
            let device_id = device.device_id();

            let account = create_account(device);
            let account_aci = account.aci().service_id_string();
            accounts.push(account.clone());

            let protocol_address = ProtocolAddress::new(account_aci, device_id);
            protocol_addresses.push(protocol_address.clone());

            let envelope_uuid = generate_uuid();
            let mut envelope =
                generate_random_envelope("This is a test of MessagePersister", &envelope_uuid);

            db.add_account(&account).await.unwrap();

            insert_with_custom_timestamp(
                &message_persister.message_cache,
                message_time,
                &protocol_address,
                &mut envelope,
                &envelope_uuid,
            )
            .await;
        }

        let mut queue_keys_before_message_persister = check_queue_key_timestamp(
            &message_persister.message_cache,
            now_timestamp, // now time
            10,
        )
        .await;

        let queues_over_ten_minutes = check_queue_key_timestamp(
            &message_persister.message_cache,
            ten_minutes_past_timestamp, // ten minutes
            10,
        )
        .await;

        let message_persister_stop_flag = Arc::new(AtomicBool::new(false));

        MessagePersister::<PostgresDatabase, MockWebSocketConnection>::start(
            message_persister,
            message_persister_stop_flag.clone(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        MessagePersister::<PostgresDatabase, MockWebSocketConnection>::stop(
            message_persister_stop_flag,
        )
        .await;

        let queue_keys_after_message_persister =
            check_queue_key_timestamp(&cache, now_timestamp, 10).await;

        let message_queues_older_than_10_minutes_has_been_deleted =
            has_messages(&cache, &queues_over_ten_minutes).await;

        let no_queue_persist_keys_in_cache =
            no_queue_persist_keys_in_cache(&cache, &protocol_addresses).await;

        teardown(cache.get_connection().await.unwrap()).await;

        for account in accounts {
            db.delete_account(&ServiceId::Aci(account.aci()))
                .await
                .unwrap();
        }

        (
            no_queue_persist_keys_in_cache,
            message_queues_older_than_10_minutes_has_been_deleted,
            queue_keys_before_message_persister,
            queue_keys_after_message_persister,
        )
    }

    #[tokio::test]
    #[serial]
    async fn test_message_persister_late_msg() {
        let message_time = SystemTime::now() // 11 minutes old
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 660;

        let (no_queue_lock_keys_in_cache, old_msg_deleted, msg_before, msg_after) =
            message_persister_test_setup_run(vec![message_time]).await;

        assert_eq!(no_queue_lock_keys_in_cache, true);
        assert_eq!(old_msg_deleted, true);
        assert_eq!(msg_before.len(), 1);
        assert_eq!(msg_after.len(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_message_persister_new_msg() {
        let message_time = SystemTime::now() // 5 minutes old
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 300;

        let (no_queue_lock_keys_in_cache, old_msg_deleted, msg_before, msg_after) =
            message_persister_test_setup_run(vec![message_time]).await;

        assert_eq!(no_queue_lock_keys_in_cache, true);
        assert_eq!(old_msg_deleted, true);
        assert_eq!(msg_before.len(), 1);
        assert_eq!(msg_after.len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_message_persister_new_and_late_msg() {
        let message_time = SystemTime::now() // 10 minutes old
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let message_times = vec![
            message_time + 100,
            message_time + 200,
            message_time + 300,
            message_time - 100,
            message_time - 200,
        ];

        let (no_queue_lock_keys_in_cache, old_msg_deleted, msg_before, msg_after) =
            message_persister_test_setup_run(message_times).await;

        assert_eq!(no_queue_lock_keys_in_cache, true);
        assert_eq!(old_msg_deleted, true);
        assert_eq!(msg_before.len(), 5);
        assert_eq!(msg_after.len(), 3);
    }
}
