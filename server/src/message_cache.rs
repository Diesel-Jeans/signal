use anyhow::Result;
use common::signal_protobuf::Envelope;
use deadpool_redis::redis::cmd;
use deadpool_redis::{Config, Connection, Runtime};
use futures_util::task::SpawnExt;
use futures_util::StreamExt;
use libsignal_core::{DeviceId, ProtocolAddress};
use redis::PubSubCommands;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const PAGE_SIZE: u32 = 100;

#[async_trait::async_trait]
pub trait MessageAvailabilityListener {
    async fn handle_new_messages_available(&mut self) -> bool;

    async fn handle_messages_persisted(&mut self) -> bool;
}

#[derive(Clone, Debug)]
pub struct MessageCache<T: MessageAvailabilityListener> {
    pool: deadpool_redis::Pool,
    hashmap: HashMap<String, Arc<Mutex<T>>>,
}

impl<T: MessageAvailabilityListener> MessageCache<T> {
    pub async fn connect() -> Result<MessageCache<T>> {
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
        address: &ProtocolAddress,
        envelope: &mut Envelope,
        message_guid: &str,
    ) -> Result<u64> {
        let mut connection = self.pool.get().await?;

        let queue_key: String = MessageCache::<T>::get_message_queue_key(address);
        let queue_metadata_key: String = MessageCache::<T>::get_message_queue_metadata_key(address);
        let queue_total_index_key: String = MessageCache::<T>::get_queue_index_key(address);

        envelope.server_guid = Some(message_guid.to_string());
        let data = bincode::serialize(&envelope)?;

        let message_guid_exists = cmd("HEXISTS")
            .arg(&queue_metadata_key)
            .arg(message_guid)
            .query_async::<u8>(&mut connection)
            .await?;

        if (message_guid_exists == 1) {
            let num = cmd("HGET")
                .arg(&queue_metadata_key)
                .arg(message_guid)
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
            .arg(message_guid)
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
        let queue_name = format!("{}::{}", address.name(), address.device_id());
        if let Some(listener) = self.hashmap.get(&queue_name) {
            listener.lock().await.handle_new_messages_available().await;
        }

        Ok(message_id)
    }

    pub async fn remove(
        &self,
        address: &ProtocolAddress,
        message_guids: Vec<String>,
    ) -> Result<Vec<Envelope>> {
        let mut connection = self.pool.get().await?;

        let queue_key: String = MessageCache::<T>::get_message_queue_key(address);
        let queue_metadata_key: String = MessageCache::<T>::get_message_queue_metadata_key(address);
        let queue_total_index_key: String = MessageCache::<T>::get_queue_index_key(address);

        let mut removed_messages: Vec<Envelope> = Vec::new();

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

    pub async fn has_messages(&self, address: &ProtocolAddress) -> Result<bool> {
        let mut connection = self.pool.get().await?;

        let msg_count = cmd("ZCARD")
            .arg(MessageCache::<T>::get_message_queue_key(address))
            .query_async::<u32>(&mut connection)
            .await?;

        Ok(msg_count > 0)
    }

    pub async fn get_all_messages(&self, address: &ProtocolAddress) -> Result<Vec<Envelope>> {
        let messages = self.get_items(address, -1).await?;

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
        address: &ProtocolAddress,
        after_message_id: i32,
    ) -> Result<Vec<Vec<u8>>> {
        let mut connection = self.pool.get().await?;

        let queue_key = MessageCache::<T>::get_message_queue_key(address);
        let queue_lock_key = MessageCache::<T>::get_persist_in_progress_key(address);
        let message_sort = format!("({}", after_message_id);

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
        address: &ProtocolAddress,
        limit: i32,
    ) -> Result<Vec<Envelope>> {
        let mut connection = self.pool.get().await?;

        let messages = cmd("ZRANGE")
            .arg(MessageCache::<T>::get_message_queue_key(address))
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

    fn get_message_queue_key(address: &ProtocolAddress) -> String {
        format!(
            "user_messages::{{{}::{}}}",
            address.name(),
            address.device_id()
        )
    }

    fn get_persist_in_progress_key(address: &ProtocolAddress) -> String {
        format!(
            "user_queue_persisting::{{{}::{}}}",
            address.name(),
            address.device_id()
        )
    }

    fn get_message_queue_metadata_key(address: &ProtocolAddress) -> String {
        format!(
            "user_messages_count::{{{}::{}}}",
            address.name(),
            address.device_id()
        )
    }

    fn get_queue_index_key(address: &ProtocolAddress) -> String {
        format!("{}::{}", address.name(), address.device_id())
    }

    pub async fn add_message_availability_listener(
        &mut self,
        address: &ProtocolAddress,
        listener: Arc<Mutex<T>>,
    ) {
        let queue_name = format!("{}::{}", address.name(), address.device_id());
        self.hashmap.insert(queue_name, listener);
    }

    pub async fn remove_message_availability_listener(&mut self, address: &ProtocolAddress) {
        let queue_name: String = format!("{}::{}", address.name(), address.device_id());
        self.hashmap.remove(&queue_name);
    }
}

#[cfg(test)]
pub mod message_cache_tests {
    use super::*;
    use serial_test::serial;
    use uuid::Uuid;

    pub fn generate_uuid() -> String {
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

    pub async fn teardown(mut con: deadpool_redis::Connection) {
        cmd("FLUSHALL").query_async::<()>(&mut con).await.unwrap();
    }

    pub struct MockWebSocketConnection {
        pub evoked_handle_new_messages: bool,
        pub evoked_handle_messages_persisted: bool,
    }

    impl MockWebSocketConnection {
        fn new() -> Self {
            MockWebSocketConnection {
                evoked_handle_new_messages: false,
                evoked_handle_messages_persisted: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl MessageAvailabilityListener for MockWebSocketConnection {
        async fn handle_new_messages_available(&mut self) -> bool {
            self.evoked_handle_new_messages = true;
            true
        }

        async fn handle_messages_persisted(&mut self) -> bool {
            self.evoked_handle_messages_persisted = true;
            true
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_message_availability_listener_new_messages() {
        let mut message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let uuid = generate_uuid();
        let mut envelope = generate_random_envelope("Hello this is a test of insert()", &uuid);

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let websocket = Arc::new(Mutex::new(MockWebSocketConnection::new()));

        message_cache
            .add_message_availability_listener(&address, websocket.clone())
            .await;

        let message_id = message_cache
            .insert(&address, &mut envelope, &uuid)
            .await
            .unwrap();

        assert!(websocket.lock().await.evoked_handle_new_messages);
    }

    #[tokio::test]
    #[serial]
    async fn test_insert() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid = generate_uuid();
        let mut envelope =
            generate_random_envelope("Hello this is a test of insert()", &message_guid);

        let message_id = message_cache
            .insert(&address, &mut envelope, &message_guid)
            .await
            .unwrap();

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::<MockWebSocketConnection>::get_message_queue_key(&address))
            .arg(message_id)
            .arg(message_id)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        teardown(connection).await;

        assert_eq!(
            envelope,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_same_id() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid = generate_uuid();
        let mut envelope1 = generate_random_envelope("This is a message", &message_guid);
        let mut envelope2 = generate_random_envelope("This is another message", &message_guid);

        let message_id = message_cache
            .insert(&address, &mut envelope1, &message_guid)
            .await
            .unwrap();

        // should return the same message id
        let message_id_2 = message_cache
            .insert(&address, &mut envelope2, &message_guid)
            .await
            .unwrap();

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::<MockWebSocketConnection>::get_message_queue_key(&address))
            .arg(message_id_2)
            .arg(message_id_2)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        teardown(connection).await;

        assert_eq!(
            envelope1,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );

        assert_eq!(message_id, message_id_2);
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_different_ids() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid1 = generate_uuid();
        let message_guid2 = generate_uuid();
        let mut envelope1 = generate_random_envelope("First Message", &message_guid1);
        let mut envelope2 = generate_random_envelope("Second Message", &message_guid2);

        // inserting messages
        let message_id = message_cache
            .insert(&address, &mut envelope1, &message_guid1)
            .await
            .unwrap();

        let message_id_2 = message_cache
            .insert(&address, &mut envelope2, &message_guid2)
            .await
            .unwrap();

        // querying the envelopes
        let result_1 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::<MockWebSocketConnection>::get_message_queue_key(&address))
            .arg(message_id)
            .arg(message_id)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        let result_2 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::<MockWebSocketConnection>::get_message_queue_key(&address))
            .arg(message_id_2)
            .arg(message_id_2)
            .query_async::<Vec<Vec<u8>>>(&mut connection)
            .await
            .unwrap();

        teardown(connection).await;

        // they are inserted as two different messages
        assert_ne!(message_id, message_id_2);

        assert_ne!(
            bincode::deserialize::<Envelope>(&result_1[0]).unwrap(),
            bincode::deserialize::<Envelope>(&result_2[0]).unwrap()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_remove() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid = generate_uuid();
        let mut envelope = generate_random_envelope("This is a test of remove()", &message_guid);

        let message_id = message_cache
            .insert(&address, &mut envelope, &message_guid)
            .await
            .unwrap();

        let removed_messages = message_cache
            .remove(&address, vec![message_guid])
            .await
            .unwrap();

        teardown(connection).await;

        assert_eq!(removed_messages.len(), 1);
        assert_eq!(removed_messages[0], envelope);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_all_messages() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let mut envelopes = Vec::new();

        for i in 0..10 {
            let message_guid = generate_uuid();
            let mut envelope =
                generate_random_envelope(&format!("This is message nr. {}", i + 1), &message_guid);

            message_cache
                .insert(&address, &mut envelope, &message_guid)
                .await
                .unwrap();

            envelopes.push(envelope);
        }

        //getting those messages
        let mut messages = message_cache.get_all_messages(&address).await.unwrap();

        teardown(connection).await;

        assert_eq!(messages.len(), 10);

        for (message, envelope) in messages.into_iter().zip(envelopes.into_iter()) {
            assert_eq!(message, envelope);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_has_messages() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid = generate_uuid();
        let mut envelope =
            generate_random_envelope("Hello this is a test of has_messages()", &message_guid);

        let does_not_has_messages = message_cache.has_messages(&address).await.unwrap();

        let message_id = message_cache
            .insert(&address, &mut envelope, &message_guid)
            .await
            .unwrap();

        let has_messages = message_cache.has_messages(&address).await.unwrap();

        teardown(connection).await;

        assert!(!does_not_has_messages);
        assert!(has_messages);
    }

    #[tokio::test]
    #[serial]
    async fn test_get_messages_to_persist() {
        let message_cache: MessageCache<MockWebSocketConnection> =
            MessageCache::connect().await.unwrap();

        let mut connection = message_cache.pool.get().await.unwrap();

        let user_id = generate_uuid();
        let device_id = 1;
        let address = ProtocolAddress::new(user_id, device_id.into());

        let message_guid = generate_uuid();
        let mut envelope = generate_random_envelope("Hello this is a test", &message_guid);

        message_cache
            .insert(&address, &mut envelope, &message_guid)
            .await
            .unwrap();

        let envelopes = message_cache
            .get_messages_to_persist(&address, -1)
            .await
            .unwrap();

        teardown(connection).await;

        assert_eq!(envelopes.len(), 1);
    }
}
