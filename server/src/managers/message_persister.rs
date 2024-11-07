use crate::account::{Account, Device};
use crate::database::SignalDatabase;
use crate::managers::account_manager::AccountManager;
use crate::message_cache::{MessageAvailabilityListener, MessageCache};
use anyhow::Result;
use common::signal_protobuf::Envelope;
use libsignal_core::ServiceId;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

const QUEUE_BATCH_LIMIT: u8 = 100;
const MESSAGE_BATCH_LIMIT: u8 = 100;
const PERSIST_DELAY: u64 = 600;

#[derive(Debug)]
pub struct MessagePersister<T: MessageAvailabilityListener, U: SignalDatabase> {
    running: bool,
    message_cache: MessageCache<T>,
    account_manager: AccountManager,
    db: U,
}

impl<
        T: MessageAvailabilityListener + Send + 'static,
        U: SignalDatabase + Send + Sync + 'static,
    > MessagePersister<T, U>
{
    pub async fn new(db: U) -> Self {
        Self {
            running: false,
            message_cache: MessageCache::connect()
                .await
                .expect("Could not connect to the Redis cache."),
            account_manager: AccountManager::new(),
            db,
        }
    }

    pub fn start(mut message_persister: MessagePersister<T, U>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { message_persister.persist_next_queues().await })
    }

    pub fn stop(handle: JoinHandle<()>) {
        handle.abort();
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
        self.message_cache
            .lock_queue_for_persistence(account.aci().service_id_string(), device.device_id());

        let message_count: u32 = 0;
        let mut messages: Vec<Envelope> = Vec::new();

        while {
            messages = self
                .message_cache
                .get_messages_to_persist(
                    account.aci().service_id_string(),
                    device.device_id(),
                    MESSAGE_BATCH_LIMIT as i32,
                )
                .await?;

            !messages.is_empty()
        } {

            // let messages_removed_from_cache = self.message_manager.persist_messages().await?;
        }

        self.message_cache
            .unlock_queue_for_persistence(account.aci().service_id_string(), device.device_id());
        Ok(())
    }
}
