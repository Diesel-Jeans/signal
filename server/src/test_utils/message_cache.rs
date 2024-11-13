use common::signal_protobuf::Envelope;
use redis::cmd;
use uuid::Uuid;

use crate::message_cache::MessageAvailabilityListener;

pub fn generate_uuid() -> String {
    let guid = Uuid::new_v4();
    guid.to_string()
}

pub async fn teardown(mut con: deadpool_redis::Connection) {
    cmd("FLUSHALL").query_async::<()>(&mut con).await.unwrap();
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
