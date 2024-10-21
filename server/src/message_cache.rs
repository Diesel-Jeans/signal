use anyhow::Result;
use deadpool_redis::redis::cmd;
use deadpool_redis::{Config, Runtime};
use futures_util::task::SpawnExt;
use futures_util::StreamExt;
use redis::{Msg, PubSubCommands};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

const QUEUE_KEYSPACE_PREFIX: &str = "__keyspace@0__:user_queue::";
const PERSISTING_KEYSPACE_PREFIX: &str = "__keyspace@0__:user_queue_persisting::";

pub struct PubSubConnection {
    //pub pub_sub: Arc<Mutex<PubSub<'static>>>,
    //pub rx: Receiver<String>,
}

pub struct RedisPubSubMessageListener {
    event_receiver: Arc<Mutex<Receiver<String>>>,
}

#[derive(Clone, Debug)]
pub struct MessageCache {
    pool: deadpool_redis::Pool,
    //hashmap: HashMap<String, dyn MessageAvailabilityListener>,
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
                message_tx.send(msg.clone()).await.expect("panic message");
            }
        });
    }
}

impl RedisPubSubMessageListener {
    pub async fn listen_to_redis_messages() {}
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
            //hashmap: HashMap::new(),
            //pub_sub: Arc::new(Mutex::new(conn)),
            subscription_sender: subscription_tx,
            //event_receiver: Arc::new(Mutex::new(message_rx)),
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
        message: String,
        message_guid: String,
    ) -> Result<i64> {
        let mut conn = self.pool.get().await.unwrap();
        let queue_key: String = MessageCache::get_message_queue_key(user_id.clone(), device_id);
        let queue_metadata_key: String =
            MessageCache::get_message_queue_metadata_key(user_id.clone(), device_id);
        let queue_total_index_key: String =
            MessageCache::get_queue_index_key(user_id.clone(), device_id);

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
            .arg(message)
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

        Ok(message_id.clone())
    }

    /*
    pub async fn remove(&self, user_id: String, device_id: u32, message_guids: Vec<String>) -> Result<Vec<String>> {
        let mut conn = self.pool.get().await.unwrap();
        let queue_key: String = MessageCache::get_message_queue_key(user_id.clone(), device_id);
        let queue_metadata_key: String = MessageCache::get_message_queue_metadata_key(user_id.clone(), device_id);
        let mut removed_messages: Vec<String> = Vec::new();

        for guid in message_guids {
            let message_id : String = cmd("HGET")
                .arg(queue_metadata_key.clone())
                .arg(guid.clone())
                .query_async(&mut conn)
                .await?;

            if message_id.clone() {
                // retrieving the message
                let envelope = cmd("ZRANGE")
                    .arg(queue_key.clone())
                    .arg(message_id.clone())
                    .arg(message_id.clone())
                    .arg("BYSCORE")
                    .arg("LIMIT")
                    .arg(0)
                    .arg(1)
                    .query_async(&mut conn)
                    .await?;

                // delete the message
                cmd("ZREMRANGEBYSCORE")
                    .arg(queue_key.clone())
                    .arg(message_id.clone())
                    .arg(message_id.clone())
                    .query_async::<()>(&mut conn)
                    .await?;

                // delete the guid from the cache
                cmd("HDEL")
                    .arg(queue_metadata_key.clone())
                    .arg(guid.clone())
                    .query_async::<()>(&mut conn)
                    .await?;

                if envelope {
                    removed_messages.push(envelope.clone());
                }
            }
        }

        if cmd("ZCARD").arg(queue_key.clone()).query_async(&mut conn).await.unwrap() == 0{
            cmd("DEL")
                .arg(queue_key.clone())
                .query_async::<()>(&mut conn)
                .await?;

            cmd("DEL")
                .arg(queue_metadata_key.clone())
                .query_async::<()>(&mut conn)
                .await?;

            cmd("ZREM")
                .arg(queue_key.clone())
                .query_async::<()>(&mut conn)
                .await?;
        }

        return Ok(removed_messages);
    }


     */
    fn get_message_queue_key(user_id: String, device_id: u32) -> String {
        format!("user_messages::{{{}::{}}}", user_id, device_id)
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
        println!("Unsubscribing to channel: {}", channel);
    }

    pub async fn subscribe(&self, channel: &str) {
        self.subscription_sender
            .send(channel.to_string())
            .await
            .unwrap();
        println!("Subscribing to channel: {}", channel);
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

pub trait MessageAvailabilityListener {
    fn handle_new_messages_available() -> bool;

    fn handle_messages_persisted() -> bool;
}

#[cfg(test)]
mod message_cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_message_cache_insert() {
        let message_cache = MessageCache::connect().await.unwrap();
        let mut conn = message_cache.pool.get().await.unwrap();
        let message_id = message_cache
            .insert(
                "b0231ab5-4c7e-40ea-a544-f925c505".to_string(),
                1,
                "Hello this is a test of the insert()".to_string(),
                "123456".to_string(),
            )
            .await
            .unwrap();

        let result = cmd("ZRANGEBYSCORE")
            .arg(MessageCache::get_message_queue_key(
                "b0231ab5-4c7e-40ea-a544-f925c505".to_string(),
                1,
            ))
            .arg(message_id.clone())
            .arg(message_id.clone())
            .query_async::<Vec<String>>(&mut conn)
            .await
            .unwrap();

        println!("Redis returned: {result:?}");

        assert_eq!(
            "Hello this is a test of the insert() function".to_string(),
            result[0]
        )
    }
}
