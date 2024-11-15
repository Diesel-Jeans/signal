use common::signal_protobuf::Envelope;
use redis::cmd;
use uuid::Uuid;

use crate::message_cache::MessageAvailabilityListener;

pub fn generate_uuid() -> String {
    let guid = Uuid::new_v4();
    guid.to_string()
}

pub async fn teardown(key: &str, mut con: deadpool_redis::Connection){
    let pattern = format!("{}presence::*", key);
    let mut cursor = 0;

    loop {
        let (new_cursor, keys): (u64, Vec<String>) = cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern.clone())
            .query_async(&mut con)
            .await.expect("Teardown scan failed");

        if !keys.is_empty() {
            cmd("DEL")
                .arg(&keys)
                .query_async::<u8>(&mut con)
                .await.expect("Teardown delete failed");
        }

        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }

}

pub fn generate_random_envelope(message: &str, uuid: &str) -> Envelope {
    let mut data = bincode::serialize(message).unwrap();
    Envelope {
        content: Some(data),
        server_guid: Some(uuid.to_string()),
        ..Default::default()
    }
}

pub struct MockWebSocketConnection {
    pub evoked_handle_new_messages: bool,
    pub evoked_handle_messages_persisted: bool,
}

impl MockWebSocketConnection {
    pub(crate) fn new() -> Self {
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
