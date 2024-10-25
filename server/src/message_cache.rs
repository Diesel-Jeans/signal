use anyhow::Result;
use common::signal_protobuf::Envelope;
use deadpool_redis::redis::cmd;
use deadpool_redis::{Config, Runtime};
use futures_util::task::SpawnExt;
use futures_util::StreamExt;
use redis::{Msg, PubSubCommands};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

const PAGE_SIZE: u32 = 100;
const QUEUE_KEYSPACE_PREFIX: &str = "__keyspace@0__:user_queue::";
const PERSISTING_KEYSPACE_PREFIX: &str = "__keyspace@0__:user_queue_persisting::";

pub struct PubSubConnection {}

trait MessageAvailabilityListener {
    fn handle_new_messages_available(&self) -> bool;

    fn handle_messages_persisted(&self) -> bool;
}

// Should be websocketConnection once it is implemented
#[derive(Debug)]
struct Foo;

impl MessageAvailabilityListener for Foo {
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
    hashmap: HashMap<String, Arc<Mutex<Foo>>>,
    subscription_sender: Sender<String>,
}

impl PubSubConnection {
    pub async fn listen_to_pubsub(
        mut subscription_rx: Receiver<String>, // For receiving new subscription requests
        message_tx: Sender<String>,            // Sender to send received messages back to main
    ) {
        let redis_client: redis::Client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let (mut sink, mut stream) = redis_client.get_async_pubsub().await.unwrap().split();

        tokio::spawn(async move {
            loop {
                let ifmsg = subscription_rx.recv().await;
                if ifmsg.is_none() {
                    continue;
                }
                let msg = ifmsg.unwrap();
                sink.subscribe(&msg).await.unwrap();
                println!("Subscribed to {}", msg);
            }
        });

        tokio::spawn(async move {
            loop {
                let message: Msg = stream.next().await.unwrap();
                let channel = message.get_channel_name();
                let msg = message.get_payload::<String>().unwrap();
                println!("Got a message, {} : {}", channel, msg);
                // message_tx.send(msg.clone()).await.expect("panic message");
            }
        });
    }
}

impl MessageCache {
    pub async fn connect() -> Result<MessageCache> {
        let _ = dotenv::dotenv();
        let redis_url = std::env::var("REDIS_URL").expect("Unable to read REDIS_URL .env var");
        let mut redis_config = Config::from_url(redis_url);
        let redis_pool: deadpool_redis::Pool = redis_config.create_pool(Some(Runtime::Tokio1))?;
        let (subscription_tx, subscription_rx) = mpsc::channel::<String>(100);
        let (message_tx, message_rx) = mpsc::channel::<String>(100);
        let message_cache = MessageCache {
            pool: redis_pool,
            hashmap: HashMap::new(),
            subscription_sender: subscription_tx,
        };
        tokio::spawn(async move {
            PubSubConnection::listen_to_pubsub(subscription_rx, message_tx).await;
        });
        message_cache.set_redis_config().await;

        Ok(message_cache)
    }

    pub async fn insert(
        &self,
        user_id: String,
        device_id: u32,
        mut message: Envelope,
        message_guid: String,
    ) -> Result<i64> {
        let mut conn = self.pool.get().await?;
        let queue_key: String = MessageCache::get_message_queue_key(user_id.clone(), device_id);
        let queue_metadata_key: String =
            MessageCache::get_message_queue_metadata_key(user_id.clone(), device_id);
        let queue_total_index_key: String =
            MessageCache::get_queue_index_key(user_id.clone(), device_id);
        message.server_guid = Option::from(message_guid.clone());
        let data = bincode::serialize(&message)?;

        let message_guid_exists: i32 = cmd("HEXISTS")
            .arg(queue_metadata_key.clone())
            .arg(message_guid.clone())
            .query_async(&mut conn)
            .await?;

        if (message_guid_exists == 1) {
            let num: String = cmd("HGET")
                .arg(queue_metadata_key.clone())
                .arg(message_guid.clone())
                .query_async(&mut conn)
                .await?;
            return Ok(num.parse().expect("Number could not be parsed"));
        }

        let message_id: i64 = cmd("HINCRBY")
            .arg(queue_metadata_key.clone())
            .arg("counter")
            .arg(1)
            .query_async(&mut conn)
            .await?;

        cmd("ZADD")
            .arg(queue_key.clone())
            .arg("NX")
            .arg(message_id.clone())
            .arg(data.clone())
            .query_async::<()>(&mut conn)
            .await?;

        cmd("HSET")
            .arg(queue_metadata_key.clone())
            .arg(message_guid.clone())
            .arg(message_id.clone())
            .query_async::<()>(&mut conn)
            .await?;

        cmd("EXPIRE")
            .arg(queue_key.clone())
            .arg(2678400)
            .query_async::<()>(&mut conn)
            .await?;

        cmd("EXPIRE")
            .arg(queue_metadata_key.clone())
            .arg(2678400)
            .query_async::<()>(&mut conn)
            .await?;

        let current_time = "12345".to_string();

        cmd("ZADD")
            .arg(queue_total_index_key)
            .arg("NX")
            .arg(current_time)
            .arg(queue_key.clone())
            .query_async::<()>(&mut conn)
            .await?;

        // notifies the message availability manager
        let queue_name = format!("{}::{}", user_id, device_id);
        if let Some(listener) = self.hashmap.get(&queue_name) {
            listener.lock().await.handle_new_messages_available();
        }

        Ok(message_id.clone())
    }

    pub async fn remove(
        &self,
        user_id: String,
        device_id: u32,
        message_guids: Vec<String>,
    ) -> Result<Vec<Envelope>> {
        let mut conn = self.pool.get().await.unwrap();
        let queue_key: String = MessageCache::get_message_queue_key(user_id.clone(), device_id);
        let queue_metadata_key: String =
            MessageCache::get_message_queue_metadata_key(user_id.clone(), device_id);
        let queue_total_index_key: String =
            MessageCache::get_queue_index_key(user_id.clone(), device_id);
        let mut removed_messages: Vec<Envelope> = Vec::new();

        for guid in message_guids {
            let message_id: Option<String> = cmd("HGET")
                .arg(queue_metadata_key.clone())
                .arg(guid.clone())
                .query_async(&mut conn)
                .await?;

            if let Some(msg_id) = message_id.clone() {
                // retrieving the message
                let envelope: Option<Vec<Vec<u8>>> = cmd("ZRANGE")
                    .arg(queue_key.clone())
                    .arg(msg_id.clone())
                    .arg(msg_id.clone())
                    .arg("BYSCORE")
                    .arg("LIMIT")
                    .arg(0)
                    .arg(1)
                    .query_async(&mut conn)
                    .await?;

                // delete the message
                cmd("ZREMRANGEBYSCORE")
                    .arg(queue_key.clone())
                    .arg(msg_id.clone())
                    .arg(msg_id.clone())
                    .query_async::<()>(&mut conn)
                    .await?;

                // delete the guid from the cache
                cmd("HDEL")
                    .arg(queue_metadata_key.clone())
                    .arg(guid.clone())
                    .query_async::<()>(&mut conn)
                    .await?;

                if let Some(envel) = envelope {
                    removed_messages.push(bincode::deserialize(&envel[0])?);
                }
            }
        }

        if cmd("ZCARD")
            .arg(queue_key.clone())
            .query_async::<u64>(&mut conn)
            .await?
            == 0
        {
            cmd("DEL")
                .arg(queue_key.clone())
                .query_async::<()>(&mut conn)
                .await?;

            cmd("DEL")
                .arg(queue_metadata_key.clone())
                .query_async::<()>(&mut conn)
                .await?;

            cmd("ZREM")
                .arg(queue_total_index_key.clone())
                .arg(queue_key.clone())
                .query_async::<()>(&mut conn)
                .await?;
        }

        Ok(removed_messages)
    }

    pub async fn has_messages(&self, user_id: String, device_id: u32) -> Result<bool> {
        let mut conn = self.pool.get().await.unwrap();

        let msg_count = cmd("ZCARD")
            .arg(MessageCache::get_message_queue_key(user_id, device_id))
            .query_async::<u32>(&mut conn)
            .await?;

        Ok(msg_count > 0)
    }

    pub async fn get_all_messages(&self, user_id: String, device_id: u32) -> Vec<Envelope> {
        let messages = self.get_items(user_id.clone(), device_id.clone(), -1).await;

        if (messages.is_empty()) {
            return Vec::new();
        }
        let mut envelopes = Vec::new();

        for i in (0..messages.len()).step_by(2) {
            envelopes.push(bincode::deserialize(&messages[i]).unwrap());
        }
        envelopes
    }

    async fn get_items(
        &self,
        destination_user_id: String,
        dest_device_id: u32,
        after_message_id: i32,
    ) -> Vec<Vec<u8>> {
        let message_sort = format!("({}", after_message_id);
        let mut con = self.pool.get().await.unwrap();
        let queue_key =
            MessageCache::get_message_queue_key(destination_user_id.clone(), dest_device_id);
        let queue_lock_key =
            MessageCache::get_persist_in_progress_key(destination_user_id.clone(), dest_device_id);
        let locked: Option<String> = cmd("GET")
            .arg(queue_lock_key)
            .query_async(&mut con)
            .await
            .unwrap();

        // if there is a queue lock key on due to persist of message.
        if let Some(lock_key) = locked {
            return Vec::new();
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
            .query_async::<Vec<Vec<u8>>>(&mut con)
            .await
            .unwrap();

        messages.clone()
    }

    fn get_message_queue_key(user_id: String, device_id: u32) -> String {
        format!("user_messages::{{{}::{}}}", user_id, device_id)
    }

    fn get_persist_in_progress_key(user_id: String, device_id: u32) -> String {
        format!("user_queue_persisting::{{{}::{}}}", user_id, device_id)
    }

    fn get_message_queue_metadata_key(user_id: String, device_id: u32) -> String {
        format!("user_messages_count::{{{}::{}}}", user_id, device_id)
    }

    fn get_queue_index_key(user_id: String, device_id: u32) -> String {
        format!("{}::{}", user_id, device_id)
    }

    async fn add_message_availability_listener(&mut self, uuid: String, device_id: String) {
        let queue_name: String = format!("{}::{}", uuid, device_id);
        //self.hashmap.insert(queue_name.clone(), listener);
        for channel in Self::get_keyspace_channels(queue_name) {
            self.subscribe(channel.as_str()).await;
        }
    }

    async fn remove_message_availability_listener(&mut self, uuid: String, device_id: String) {
        let queue_name: String = format!("{}::{}", uuid, device_id);
        //self.hashmap.remove(&queue_name);
        for channel in Self::get_keyspace_channels(queue_name) {
            self.unsubscribe(channel.as_str()).await;
        }
    }

    pub async fn unsubscribe(&mut self, channel: &str) {
        self.subscription_sender
            .send(channel.to_string())
            .await
            .unwrap();
    }

    pub async fn subscribe(&self, channel: &str) {
        self.subscription_sender
            .send(channel.to_string())
            .await
            .unwrap();
    }

    fn get_keyspace_channels(queue_name: String) -> Vec<String> {
        let mut keyspace_channels: Vec<String> = Vec::from([
            format!("{}{{{}}}", QUEUE_KEYSPACE_PREFIX, queue_name),
            format!("{}{{{}}}", PERSISTING_KEYSPACE_PREFIX, queue_name),
        ]);
        keyspace_channels
    }

    async fn set_redis_config(&self) {
        let mut conn = self.pool.get().await.unwrap();
        cmd("CONFIG")
            .arg("SET")
            .arg("notify-keyspace-events")
            .arg("Ex")
            .query_async::<()>(&mut conn)
            .await
            .unwrap();
        self.subscribe("__keyevent@0__:expired").await;
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

    fn generate_random_envelope(message: String, uuid: String) -> Envelope {
        let mut envelope = Envelope::default();
        let mut data = bincode::serialize(&envelope).unwrap();
        envelope.content = Option::from(data);
        envelope.server_guid = Option::from(uuid);
        envelope
    }

    async fn teardown(mut con: deadpool_redis::Connection) {
        cmd("FLUSHALL").query_async::<()>(&mut con).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_insert() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();
        let uuid = generate_uuid();
        let mut envelope =
            generate_random_envelope("Hello this is a test of insert()".to_string(), uuid.clone());
        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5051".to_string(),
                1,
                envelope.clone(),
                uuid,
            )
            .await
            .unwrap();

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5051".to_string(),
                1,
            ))
            .arg(message_id.clone())
            .arg(message_id.clone())
            .query_async::<Vec<Vec<u8>>>(&mut conn)
            .await
            .unwrap();

        assert_eq!(
            envelope,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );
        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_same_id() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();
        let msg_guid = generate_uuid();
        let mut envelope1 =
            generate_random_envelope("This is a message".to_string(), msg_guid.clone());
        let envelope2 =
            generate_random_envelope("This is another message".to_string(), msg_guid.clone());

        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5052".to_string(),
                1,
                envelope1.clone(),
                msg_guid.clone(),
            )
            .await
            .unwrap();

        // should return the same message id
        let message_id_2 = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5052".to_string(),
                1,
                envelope2.clone(),
                msg_guid.clone(),
            )
            .await
            .unwrap();

        assert_eq!(message_id, message_id_2);

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5052".to_string(),
                1,
            ))
            .arg(message_id_2.clone())
            .arg(message_id_2.clone())
            .query_async::<Vec<Vec<u8>>>(&mut conn)
            .await
            .unwrap();

        assert_eq!(
            envelope1,
            bincode::deserialize::<Envelope>(&result[0]).unwrap()
        );
        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_insert_different_ids() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();
        let mut envelope1 = generate_random_envelope("First Message".to_string(), uuid1.clone());
        let mut envelope2 = generate_random_envelope("Second Message".to_string(), uuid2.clone());

        // inserting messages
        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5053".to_string(),
                1,
                envelope1.clone(),
                generate_uuid(),
            )
            .await
            .unwrap();
        let message_id_2 = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c5053".to_string(),
                1,
                envelope2.clone(),
                generate_uuid(),
            )
            .await
            .unwrap();

        // they are inserted as two different messages
        assert_ne!(message_id, message_id_2);

        // querying the envelopes
        let result_1 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5053".to_string(),
                1,
            ))
            .arg(message_id.clone())
            .arg(message_id.clone())
            .query_async::<Vec<Vec<u8>>>(&mut conn)
            .await
            .unwrap();

        let result_2 = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c5053".to_string(),
                1,
            ))
            .arg(message_id_2.clone())
            .arg(message_id_2.clone())
            .query_async::<Vec<Vec<u8>>>(&mut conn)
            .await
            .unwrap();

        assert_ne!(
            bincode::deserialize::<Envelope>(&result_1[0]).unwrap(),
            bincode::deserialize::<Envelope>(&result_2[0]).unwrap()
        );

        teardown(conn).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_remove() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();
        let user_id = "b0231ab5-4c7e-40ea-a544-f925c5".to_string();
        let msg_guid = generate_uuid();
        let mut envelope =
            generate_random_envelope("This is a test of remove()".to_string(), msg_guid.clone());

        let message_id = message_cache
            .insert(user_id.clone(), 1, envelope.clone(), msg_guid.clone())
            .await
            .unwrap();

        let removed_messages = message_cache
            .remove(user_id, 1, Vec::from([msg_guid.clone()]))
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
        let user_id = "b0231ab5-4c7e-40ea-a544-f925c".to_string();
        let mut envelopes = Vec::new();
        for i in 0..10 {
            let uuid = generate_uuid();
            let envelope =
                generate_random_envelope(format!("This is message nr. {}", i + 1), uuid.clone());
            let msg_id = message_cache
                .insert(user_id.clone(), 1, envelope.clone(), uuid.clone())
                .await
                .unwrap();
            envelopes.push(envelope);
        }

        //getting those messages
        let mut messages = message_cache.get_all_messages(user_id.clone(), 1).await;

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
        let envelope = generate_random_envelope(
            "Hello this is a test of has_messages()".to_string(),
            msg_guid.clone(),
        );

        let does_not_has_messages = message_cache
            .has_messages(user_id.to_string(), device_id)
            .await
            .unwrap();

        assert_eq!(does_not_has_messages, false);

        let message_id = message_cache
            .insert(
                user_id.to_string(),
                device_id,
                envelope.clone(),
                msg_guid.clone(),
            )
            .await
            .unwrap();

        let has_messages = message_cache
            .has_messages(user_id.to_string(), device_id)
            .await
            .unwrap();

        assert_eq!(has_messages, true);
        teardown(conn).await;
    }
}
