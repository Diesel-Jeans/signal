use anyhow::{Ok, Result};
use common::signal_protobuf::{envelope, Envelope};
use libsignal_core::DeviceId;

use crate::database::SignalDatabase;
use crate::message_cache::MessageCache;
use crate::postgres::PostgresDatabase;

pub struct MessagesManager {
    message_cache: MessageCache,
    // message_db: PostgresDatabase,
    // report_message_manager
    // message_deletion_executor
}

impl MessagesManager {
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
        // let db_has_messages = self.messages_db.has_messages(user_id, device_id).await?;

        if cache_has_messages {
            Ok((cache_has_messages, "cached"))
        } else {
            Ok((cache_has_messages, "none"))
        }
    }
}

#[cfg(test)]
mod message_manager_tests {
    use crate::message_cache::MessageCache;
    use anyhow::Result;
    use deadpool_redis::redis::cmd;
    use serial_test::serial;
    use uuid::Uuid;

    use super::*;

    async fn init_manager() -> Result<MessagesManager> {
        Ok(MessagesManager {
            message_cache: MessageCache::connect().await.unwrap(),
        })
    }

    async fn teardown(msg_manager: MessagesManager) {
        let mut conn = msg_manager.message_cache.get_connection().await.unwrap();
        cmd("FLUSHALL").query_async::<()>(&mut conn).await.unwrap();
    }

    fn generate_random_envelope(message: &str, uuid: String) -> Envelope {
        Envelope {
            content: Some(bincode::serialize(message).unwrap()),
            server_guid: Some(uuid),
            ..Default::default()
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_may_have_cached_persisted_messages() {
        let msg_manager = init_manager().await.unwrap();

        let user_id = Uuid::new_v4().to_string();
        let device_id = 1.into();
        let message_guid = Uuid::new_v4().to_string();
        let envelope = generate_random_envelope("Hello Bob", message_guid.clone());

        msg_manager
            .message_cache
            .insert(&user_id, device_id, envelope, &message_guid)
            .await;

        let result = msg_manager
            .may_have_persisted_messages(&user_id, device_id)
            .await
            .unwrap();

        assert_eq!(result, (true, "cached"));
        teardown(msg_manager);
    }
}
