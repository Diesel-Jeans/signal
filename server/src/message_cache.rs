use anyhow::Result;
use common::signal_protobuf::Envelope;
use deadpool_redis::redis::cmd;
use deadpool_redis::{Config, Connection, Runtime};
use futures_util::task::SpawnExt;
use futures_util::StreamExt;
use libsignal_core::DeviceId;
use redis::PubSubCommands;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const PAGE_SIZE: u32 = 100;

trait MessageAvailabilityListener {
    fn handle_new_messages_available(&self) -> bool;

    fn handle_messages_persisted(&self) -> bool;
}

// Should be websocketConnection once it is implemented
#[derive(Debug)]
pub struct WebsocketConnection;

impl MessageAvailabilityListener for WebsocketConnection {
    fn handle_new_messages_available(&self) -> bool {
        todo!()
    }

    fn handle_messages_persisted(&self) -> bool {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct MessageCache {
    pool: deadpool_redis::Pool,
    hashmap: HashMap<String, Arc<Mutex<WebsocketConnection>>>,
}

impl MessageCache {
    pub async fn connect() -> Result<MessageCache> {
        let _ = dotenv::dotenv();
        let redis_url = std::env::var("REDIS_URL").expect("Unable to read REDIS_URL .env var");
        let mut redis_config = Config::from_url(redis_url);
        let redis_pool: deadpool_redis::Pool = redis_config.create_pool(Some(Runtime::Tokio1))?;
        Ok(MessageCache {
            pool: redis_pool,
            hashmap: HashMap::new(),
        })
    }

    pub async fn get_connection(&self) -> Result<Connection> {
        Ok(self.pool.get().await?)
    }

    pub async fn insert(
        &self,
        user_id: &str,
        device_id: DeviceId,
        mut envelope: Envelope,
        message_guid: &str,
    ) -> Result<u64> {
        let queue_key = MessageCache::get_message_queue_key(user_id, device_id);
        let queue_metadata_key = MessageCache::get_message_queue_metadata_key(user_id, device_id);
        let queue_total_index_key = MessageCache::get_queue_index_key(user_id, device_id.into());

        envelope.server_guid = Some(message_guid.to_string());
        let data = bincode::serialize(&envelope)?;

        let mut connection = self.pool.get().await?;

        let message_guid_exists = cmd("HEXISTS")
            .arg(&queue_metadata_key)
            .arg(&message_guid)
            .query_async::<u8>(&mut connection)
            .await?;

        if (message_guid_exists == 1) {
            let num = cmd("HGET")
                .arg(&queue_metadata_key)
                .arg(&message_guid)
                .query_async::<String>(&mut connection)
                .await?;

            match num.parse() {
                Ok(num) => return Ok(num),
                Err(_) => return Ok(0),
            }
        }

        let message_id = cmd("HINCRBY")
            .arg(&queue_metadata_key)
            .arg("counter")
            .arg(1)
            .query_async::<u64>(&mut connection)
            .await?;

        cmd("ZADD")
            .arg(&queue_key)
            .arg("NX")
            .arg(message_id)
            .arg(&data)
            .query_async::<()>(&mut connection)
            .await?;

        cmd("HSET")
            .arg(&queue_metadata_key)
            .arg(&message_guid)
            .arg(message_id)
            .query_async::<()>(&mut connection)
            .await?;

        cmd("EXPIRE")
            .arg(&queue_key)
            .arg(2678400)
            .query_async::<()>(&mut connection)
            .await?;

        cmd("EXPIRE")
            .arg(&queue_metadata_key)
            .arg(2678400)
            .query_async::<()>(&mut connection)
            .await?;

        let time = SystemTime::now();
        let time_in_millis: u64 = time.duration_since(UNIX_EPOCH)?.as_millis() as u64;

        cmd("ZADD")
            .arg(&queue_total_index_key)
            .arg("NX")
            .arg(time_in_millis)
            .arg(&queue_key)
            .query_async::<()>(&mut connection)
            .await?;

        // notifies the message availability manager
        let queue_name = format!("{}::{}", user_id, device_id);
        if let Some(listener) = self.hashmap.get(&queue_name as &str) {
            listener.lock().await.handle_new_messages_available();
        }

        Ok(message_id)
    }

    pub async fn remove(
        &self,
        user_id: &str,
        device_id: DeviceId,
        message_guids: Vec<String>,
    ) -> Result<Vec<Envelope>> {
        let queue_key = MessageCache::get_message_queue_key(user_id, device_id);
        let queue_metadata_key = MessageCache::get_message_queue_metadata_key(user_id, device_id);
        let queue_total_index_key = MessageCache::get_queue_index_key(user_id, device_id);
        let mut removed_messages: Vec<Envelope> = Vec::new();

        let mut connection = self.pool.get().await?;

        for guid in message_guids {
            let message_id: Option<String> = cmd("HGET")
                .arg(&queue_metadata_key)
                .arg(&guid)
                .query_async(&mut connection)
                .await?;

            if let Some(msg_id) = message_id.clone() {
                // retrieving the message
                let envelope = cmd("ZRANGE")
                    .arg(&queue_key)
                    .arg(&msg_id)
                    .arg(&msg_id)
                    .arg("BYSCORE")
                    .arg("LIMIT")
                    .arg(0)
                    .arg(1)
                    .query_async::<Option<Vec<Vec<u8>>>>(&mut connection)
                    .await?;

                // delete the message
                cmd("ZREMRANGEBYSCORE")
                    .arg(&queue_key)
                    .arg(&msg_id)
                    .arg(&msg_id)
                    .query_async::<()>(&mut connection)
                    .await?;

                // delete the guid from the cache
                cmd("HDEL")
                    .arg(&queue_metadata_key)
                    .arg(&guid)
                    .query_async::<()>(&mut connection)
                    .await?;

                if let Some(envel) = envelope {
                    removed_messages.push(bincode::deserialize(&envel[0])?);
                }
            }
        }

        if cmd("ZCARD")
            .arg(&queue_key)
            .query_async::<u64>(&mut connection)
            .await?
            == 0
        {
            cmd("DEL")
                .arg(&queue_key)
                .query_async::<()>(&mut connection)
                .await?;

            cmd("DEL")
                .arg(&queue_metadata_key)
                .query_async::<()>(&mut connection)
                .await?;

            cmd("ZREM")
                .arg(&queue_total_index_key)
                .arg(&queue_key)
                .query_async::<()>(&mut connection)
                .await?;
        }

        Ok(removed_messages)
    }

    pub async fn has_messages(&self, user_id: &str, device_id: DeviceId) -> Result<bool> {
        let mut connection = self.pool.get().await?;

        let msg_count = cmd("ZCARD")
            .arg(MessageCache::get_message_queue_key(user_id, device_id))
            .query_async::<u32>(&mut connection)
            .await?;

        Ok(msg_count > 0)
    }

    pub async fn get_all_messages(
        &self,
        user_id: &str,
        device_id: DeviceId,
    ) -> Result<Vec<Envelope>> {
        let messages = self.get_items(user_id, device_id, -1).await?;

        if (messages.is_empty()) {
            return Ok(Vec::new());
        }
        let mut envelopes = Vec::new();

        // messages is a [envelope1, msg_id1, envelope2, msg_id2, ...]
        for i in (0..messages.len()).step_by(2) {
            envelopes.push(bincode::deserialize(&messages[i])?);
        }
        Ok(envelopes)
    }

    async fn get_items(
        &self,
        destination_user_id: &str,
        dest_device_id: DeviceId,
        after_message_id: i32,
    ) -> Result<Vec<Vec<u8>>> {
        let message_sort = format!("({}", after_message_id);
        let queue_key = MessageCache::get_message_queue_key(destination_user_id, dest_device_id);
        let queue_lock_key =
            MessageCache::get_persist_in_progress_key(destination_user_id, dest_device_id);

        let mut connection = self.pool.get().await?;

        let locked = cmd("GET")
            .arg(&queue_lock_key)
            .query_async::<Option<String>>(&mut connection)
            .await?;

        // if there is a queue lock key on, due to persist of message.
        if let Some(lock_key) = locked {
            return Ok(Vec::new());
        }

        let mut messages = cmd("ZRANGE")
            .arg(queue_key.clone())
            .arg(message_sort.clone())
            .arg("+inf")
            .arg("BYSCORE")
            .arg("LIMIT")
            .arg(0)
            .arg(PAGE_SIZE)
            .arg("WITHSCORES")
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await?;

        Ok(messages.clone())
    }

    pub async fn get_messages_to_persist(
        &self,
        user_id: &str,
        device_id: DeviceId,
        limit: i32,
    ) -> Result<Vec<Envelope>> {
        let mut connection = self.pool.get().await?;

        let messages = cmd("ZRANGE")
            .arg(MessageCache::get_message_queue_key(
                user_id,
                device_id.into(),
            ))
            .arg(0)
            .arg(limit)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await?;

        let valid_envelopes: Vec<Envelope> = messages
            .into_iter()
            .filter_map(|m| bincode::deserialize(&m).ok())
            .collect();

        Ok(valid_envelopes)
    }

    fn get_message_queue_key(user_id: &str, device_id: DeviceId) -> String {
        format!("user_messages::{{{}::{}}}", user_id.to_string(), device_id)
    }

    fn get_persist_in_progress_key(user_id: &str, device_id: DeviceId) -> String {
        format!(
            "user_queue_persisting::{{{}::{}}}",
            user_id.to_string(),
            device_id
        )
    }

    fn get_message_queue_metadata_key(user_id: &str, device_id: DeviceId) -> String {
        format!(
            "user_messages_count::{{{}::{}}}",
            user_id.to_string(),
            device_id
        )
    }

    fn get_queue_index_key(user_id: &str, device_id: DeviceId) -> String {
        format!("{}::{}", user_id, device_id)
    }

    pub async fn add_message_availability_listener(
        &mut self,
        uuid: &str,
        device_id: DeviceId,
        listener: Arc<Mutex<WebsocketConnection>>,
    ) {
        let queue_name = format!("{}::{}", uuid, device_id);
        self.hashmap.insert(queue_name, listener);
    }

    pub async fn remove_message_availability_listener(&mut self, uuid: &str, device_id: DeviceId) {
        let queue_name: String = format!("{}::{}", uuid, device_id);
        self.hashmap.remove(&queue_name);
    }
}

#[cfg(test)]
mod message_cache_tests {
    use super::*;
    use serial_test::serial;
    use uuid::Uuid;

    fn generate_uuid() -> String {
        let guid = Uuid::new_v4();
        guid.to_string()
    }

    fn generate_random_envelope(message: &str, uuid: &str) -> Envelope {
        let mut data = bincode::serialize(message).unwrap();
        Envelope {
            content: Some(data),
            server_guid: Some(uuid.to_string()),
            ..Default::default()
        }
    }

    async fn teardown(mut con: deadpool_redis::Connection) {
        cmd("FLUSHALL").query_async::<()>(&mut con).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_insert() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut connection = message_cache.pool.get().await.unwrap();

        let uuid = generate_uuid();
        let device_id = 1;
        let mut envelope =
            generate_random_envelope("Hello this is a test of insert()", &uuid);

        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5051",
                device_id.into(),
                envelope.clone(),
                &uuid,
            )
            .await
            .unwrap();

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5051",
                device_id.into(),
            ))
            .arg(message_id)
            .arg(message_id)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        assert_eq!(
            envelope,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );
        teardown(connection).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_same_id() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut connection = message_cache.pool.get().await.unwrap();

        let msg_guid = generate_uuid();
        let device_id = 1;
        let mut envelope1 = generate_random_envelope("This is a message", &msg_guid);
        let envelope2 = generate_random_envelope("This is another message", &msg_guid);

        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5052",
                device_id.into(),
                envelope1.clone(),
                &msg_guid,
            )
            .await
            .unwrap();

        // should return the same message id
        let message_id_2 = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5052",
                device_id.into(),
                envelope2.clone(),
                &msg_guid,
            )
            .await
            .unwrap();

        assert_eq!(message_id, message_id_2);

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5052",
                device_id.into(),
            ))
            .arg(message_id_2)
            .arg(message_id_2)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        assert_eq!(
            envelope1,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );
        teardown(connection).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_different_ids() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut connection = message_cache.pool.get().await.unwrap();

        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();
        let mut envelope1 = generate_random_envelope("First Message", &uuid1);
        let mut envelope2 = generate_random_envelope("Second Message", &uuid2);
        let device_id = 1;

        // inserting messages
        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5053",
                device_id.into(),
                envelope1.clone(),
                &generate_uuid(),
            )
            .await
            .unwrap();
        let message_id_2 = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5053",
                device_id.into(),
                envelope2.clone(),
                &generate_uuid(),
            )
            .await
            .unwrap();

        // they are inserted as two different messages
        assert_ne!(message_id, message_id_2);

        // querying the envelopes
        let result_1 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5053",
                device_id.into(),
            ))
            .arg(message_id)
            .arg(message_id)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        let result_2 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5053",
                device_id.into(),
            ))
            .arg(message_id_2)
            .arg(message_id_2)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        assert_ne!(
            bincode::deserialize::<Envelope>(&result_1[0]).unwrap(),
            bincode::deserialize::<Envelope>(&result_2[0]).unwrap()
        );

        teardown(connection).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_remove() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();

        let user_id = "b0231ab5-4c7e-40ea-a544-f925c5";
        let msg_guid = generate_uuid();
        let mut envelope = generate_random_envelope("This is a test of remove()", &msg_guid);

        let message_id = message_cache
            .insert(user_id, 1.into(), envelope.clone(), &msg_guid)
            .await
            .unwrap();

        let removed_messages = message_cache
            .remove(user_id, 1.into(), Vec::from([msg_guid.clone()]))
            .await
            .unwrap();

        assert_eq!(removed_messages.len(), 1);
        assert_eq!(removed_messages[0], envelope);
        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_get_all_messages() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();

        let user_id = "b0231ab5-4c7e-40ea-a544-f925c";
        let device_id = 1;
        let mut envelopes = Vec::new();

        for i in 0..10 {
            let uuid = generate_uuid();
            let envelope =
                generate_random_envelope(&format!("This is message nr. {}", i + 1), &uuid);
            let msg_id = message_cache
                .insert(user_id.clone(), 1.into(), envelope.clone(), &uuid)
                .await
                .unwrap();
            envelopes.push(envelope);
        }

        //getting those messages
        let mut messages = message_cache
            .get_all_messages(user_id.clone(), device_id.into())
            .await
            .unwrap();

        assert_eq!(messages.len(), 10);
        for (message, envelope) in messages.into_iter().zip(envelopes.into_iter()) {
            assert_eq!(message, envelope);
        }

        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_has_messages() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();

        let user_id = "b0231ab5-4c7e-40ea-a544-f925c5051";
        let device_id = 1;
        let msg_guid = generate_uuid();
        let envelope =
            generate_random_envelope("Hello this is a test of has_messages()", &msg_guid);

        let does_not_has_messages = message_cache
            .has_messages(user_id, device_id.into())
            .await
            .unwrap();

        assert!(!does_not_has_messages);

        let message_id = message_cache
            .insert(user_id, device_id.into(), envelope.clone(), &msg_guid)
            .await
            .unwrap();

        let has_messages = message_cache
            .has_messages(user_id, device_id.into())
            .await
            .unwrap();

        assert!(has_messages);
        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_get_messages_to_persist() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = "b0231ab5-4c7e-40ea-a544-f925c5051";
        let device_id = 1;
        let message_guid = generate_uuid();

        let mut message = generate_random_envelope("Hello this is a test", &message_guid);

        let message_id = message_cache
            .insert(user_id, device_id.into(), message, &message_guid)
            .await
            .unwrap();

        let envelopes = message_cache
            .get_messages_to_persist(user_id, device_id.into(), -1)
            .await
            .unwrap();

        assert_eq!(envelopes.len(), 1);
        teardown(connection).await;
    }
}
