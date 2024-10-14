use deadpool_redis::redis::{cmd};
use deadpool_redis::Connection;
use redis::{PubSubCommands};
use std::fmt::format;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::AsyncReadExt;
use uuid::uuid;

#[derive(Clone)]
pub struct MessageCache {

}

impl MessageCache {
    pub async fn insert(
        conn: &mut Connection,
        user_id: String,
        device_id: u32,
        message: String,
        message_guid: String,
    ) -> i64 {
        let queue_key: String = MessageCache::get_message_queue_key(user_id.clone(), device_id);
        let queue_metadata_key: String =
            MessageCache::get_message_queue_metadata_key(user_id.clone(), device_id);
        let queue_index_key: String = MessageCache::get_queue_index_key(user_id.clone(), device_id);

        let message_guid_exists: i32 = cmd("HEXISTS")
            .arg(queue_metadata_key.clone())
            .arg(message_guid.clone())
            .query_async(conn)
            .await
            .unwrap();

        if (message_guid_exists == 1) {
            let num: String = cmd("HGET")
                .arg(queue_metadata_key.clone())
                .arg(message_guid.clone())
                .query_async(conn)
                .await
                .unwrap();
            return num.parse().expect("Number could not be parsed");
        }

        let message_id: i64 = cmd("HINCRBY")
            .arg(queue_metadata_key.clone())
            .arg("counter")
            .arg(1)
            .query_async(conn)
            .await
            .unwrap();

        let message_ttl_key = format!("msg_key::{{{}::{}}}<{}>", user_id, device_id, message_id);
        println!("Sending with key: {}", message_ttl_key);

        cmd("HSET")
            .arg(queue_key.clone())
            .arg(message_ttl_key.clone())
            .arg(message.clone())
            .query_async::<()>(conn)
            .await
            .unwrap();

        cmd("SET")
            .arg(message_ttl_key.clone())
            .arg("")
            .query_async::<()>(conn)
            .await
            .unwrap();

        cmd("EXPIRE")
            .arg(message_ttl_key.clone())
            .arg(5)
            .query_async::<()>(conn)
            .await
            .unwrap();

        let current_time = "12345".to_string();

        cmd("ZADD")
            .arg(queue_index_key)
            .arg("NX")
            .arg(current_time)
            .arg(queue_key.clone())
            .query_async::<()>(conn)
            .await
            .unwrap();

        println!("Done.");
        message_id.clone()
    }

    fn get_message_queue_key(user_id: String, device_id: u32) -> String {
        format!("user_messages::{{{}::{}}}", user_id, device_id)
    }

    fn get_message_queue_metadata_key(user_id: String, device_id: u32) -> String {
        format!("user_messages_count::{{{}::{}}}", user_id, device_id)
    }

    fn get_queue_index_key(user_id: String, device_id: u32) -> String {
        format!("{}::{}", user_id, device_id)
    }

    pub async fn listen_for_expirations(mut conn: redis::Connection) {
        let mut con = conn.as_pubsub();
        con.subscribe("__keyevent@0__:expired").unwrap();
        println!("pubsub connection is up");
        while let Ok(msg) = con.get_message() {
            let key: String = msg.get_payload::<String>().unwrap();
            println!("{}", key);
            MessageCache::send_message_to_db(key);
        }
    }

    pub fn send_message_to_db(msg_id_key: String) {
        let user_msg_id = format!(
            "user_messages::{}}}",
            msg_id_key
                .strip_prefix("msg_key::")
                .unwrap_or(&*msg_id_key)
                .split('<')
                .next()
                .unwrap_or("")
                .trim_end_matches('}')
        );
        println!("{}", user_msg_id);
    }

    fn add_message_availability_listener(uuid: String, device_id: String) {
        let queue_name: String = format!("{}::{}", uuid, device_id);
    }

    fn subscribe_to_message_availability(queue_name: String) {


    }
}

pub trait MessageAvailabilityListener {
    fn handle_new_messages_available() -> bool;

    fn handle_messages_persisted() -> bool;
}
