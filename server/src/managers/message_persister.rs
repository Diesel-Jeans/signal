use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use crate::managers::account_manager::AccountManager;
use crate::managers::messages_manager::MessagesManager;
use crate::managers::state::SignalServerState;
use crate::message_cache::{MessageAvailabilityListener, MessageCache};
use crate::postgres::PostgresDatabase;
use anyhow::Result;
use async_std::prelude::FutureExt;
use common::signal_protobuf::Envelope;
use libsignal_core::{ProtocolAddress, ServiceId};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const QUEUE_BATCH_LIMIT: u8 = 100;
const MESSAGE_BATCH_LIMIT: u8 = 100;
const PERSIST_DELAY: u64 = 600;

#[derive(Debug)]
pub struct MessagePersister<T: SignalDatabase, U: MessageAvailabilityListener> {
    running: bool,
    message_cache: MessageCache<U>,
    messages_manager: MessagesManager<T, U>,
    account_manager: AccountManager,
    db: T,
}

impl<T, U> MessagePersister<T, U>
where
    T: SignalDatabase + Send + 'static + Sync,
    U: MessageAvailabilityListener + Send + 'static + Sync,
{
    pub async fn new(state: SignalServerState<PostgresDatabase>) -> Self {
        let message_cache = MessageCache::connect()
            .await
            .expect("Could not connect to redis cache.");
        Self {
            running: false,
            message_cache: state.m,
            messages_manager: MessagesManager::new(db.clone(), message_cache),
            account_manager: AccountManager::new(),
            db,
        }
    }

    pub fn start(
        mut message_persister: MessagePersister<T, U>,
    ) -> (Arc<Mutex<bool>>, JoinHandle<MessagePersister<T, U>>) {
        let lock = Arc::new(Mutex::new(true));

        (
            lock,
            tokio::spawn(async move {
                while !lock.lock().await {
                    message_persister.persist_next_queues().await;
                }
                message_persister
            }),
        )
    }

    pub async fn stop(
        mut handle: JoinHandle<MessagePersister<T, U>>,
        lock: Arc<Mutex<bool>>,
    ) -> Result<MessagePersister<T, U>> {
        lock.lock().await = false;
        Ok(handle.await?)
    }
    async fn persist_next_queues(&mut self) -> Result<()> {
        let mut queues_to_persist: Vec<String> = Vec::new();
        let time = SystemTime::now();
        let time_in_secs: u64 = time.duration_since(UNIX_EPOCH)?.as_secs();
        let mut queues_persisted: Vec<String> = Vec::new();

        while {
            let time = SystemTime::now();
            let time_in_secs: u64 = time.duration_since(UNIX_EPOCH)?.as_secs();

            queues_persisted = self
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

                self.persist_queue(&account, device);
            }
        }

        Ok(())
    }

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
            .unlock_queue_for_persistence(&protocol_address);
        Ok(())
    }
}

#[cfg(test)]
mod message_persister_tests {
    use super::*;
    use crate::message_cache::message_cache_tests::{
        generate_random_envelope, generate_uuid, MockWebSocketConnection,
    };
    use crate::postgres::PostgresDatabase;
    use redis::cmd;
    use serial_test::serial;
    use std::thread::sleep;
    use std::time::Duration;

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

    #[tokio::test]
    #[serial]
    async fn test_message_persister() {
        let _ = dotenv::dotenv();
        let db = PostgresDatabase::connect("DATABASE_URL".to_string())
            .await
            .unwrap();

        let message_persister: MessagePersister<PostgresDatabase, MockWebSocketConnection> =
            MessagePersister::new(db).await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 660;
        let user_id = generate_uuid();
        let device_id = 1;

        let protocol_address = ProtocolAddress::new(user_id, device_id.into());
        let envelope_uuid = generate_uuid();
        let mut envelope =
            generate_random_envelope("This is a test of MessagePersister", &envelope_uuid);

        insert_with_custom_timestamp(
            &message_persister.message_cache,
            timestamp,
            &protocol_address,
            &mut envelope,
            &envelope_uuid,
        );

        let mut queue_keys =
            check_queue_key_timestamp(&message_persister.message_cache, timestamp + 60, 10).await;

        assert_eq!(queue_keys.len(), 1);

        let (lock, handle) = MessagePersister::start(message_persister);

        sleep(Duration::from_millis(10000)).await;

        let message_per = MessagePersister::stop(handle, lock).await.unwrap();

        queue_keys =
            check_queue_key_timestamp(&message_per.message_cache, timestamp + 60, 10).await;
    }
}
