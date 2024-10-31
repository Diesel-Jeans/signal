
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::Query;
use axum::http::{StatusCode, Uri};
use axum::routing::head;
use libsignal_core::{ProtocolAddress};
use serde::de::IntoDeserializer;
use serde::Deserialize;
use serde_json::json;
use sha2::digest::consts::False;
use sha2::digest::typenum::Integer;
use std::fmt::{self, format, Debug};
use std::future::Future;
use std::net::SocketAddr;
use tonic::ConnectError;
use uuid::fmt::Braced;

use std::str::FromStr;
use std::thread::current;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, MutexGuard, RwLock};

use common::signal_protobuf::{
    envelope, web_socket_message, Envelope, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use common::web_api::{SignalMessage, SignalMessages};
use prost::{bytes::Bytes, Message as PMessage};

use rand::rngs::OsRng;
use rand::Rng;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::account::Account;
use crate::database::SignalDatabase;
use crate::managers::state::SignalServerState;
use super::connection::{WSStream, WebSocketConnection, ConnectionState, ConnectionMap, ClientConnection};
use crate::error::{ApiError, SocketManagerError};
use crate::query::PutV1MessageParams;

use chrono::Utc;

/*const WS_ENDPOINTS: [&str; 24] = [
    "v4/attachments/form/upload",
    "v1/config",
    "v1/certificate/delivery",
    "v1/devices",
    "v2/directory/auth",
    "v1/certificate/auth/group",
    "v1/archives/auth",
    "v1/archives/auth/read",
    "v1/archives/upload/form",
    "v1/archives/media/upload/form",
    "v1/devices/link",
    "v1/messages",
    "v1/messages/multi_recipient",
    "v2/accounts/phone_number_discoverability",
    "v1/profile",
    "v1/archives",
    "v1/archives/media",
    "v1/archives/media/batch",
    "v1/archives/media/delete",
    "v1/devices/capabilities",
    "v1/messages/report",
    "v1/archives/backupid",
    "v1/archives/keys",
    "v1/storage/auth",
];*/



#[derive(Debug)]
pub struct WebSocketManager<T: WSStream + Debug> {
    sockets: ConnectionMap<T>,
}

impl<T: WSStream + Debug> Clone for WebSocketManager<T> {
    fn clone(&self) -> Self {
        Self {
            sockets: Arc::clone(&self.sockets),
        }
    }
}

impl <T: WSStream + Debug + Send + 'static> WebSocketManager<T> {

    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    pub async fn insert<U: SignalDatabase + Send + 'static>(&mut self, connection: WebSocketConnection<T>, state: SignalServerState<U>){
        let address = connection.protocol_address();
        let connection: ClientConnection<T> = Arc::new(Mutex::new(connection));
        
        self.sockets.lock().await.insert(address.clone(), connection.clone());
        let mut mgr = self.clone();
        
        let protocol_address = address.clone();
        tokio::spawn(async move {
            let connection = connection.clone();
            let addr = connection.lock().await.socket_address();
            loop {
                let mut ws_guard = connection.lock().await;

                let timeout_res = tokio::time::timeout(Duration::from_millis(100), ws_guard.recv()).await;
                let msg_opt = match timeout_res {
                    Ok(x) => x,
                    _ => continue // did not receive message in time, release and let others access the connection
                };

                let res = if let Some(x) = msg_opt{
                    x
                } else{
                    ws_guard.close().await;
                    break;
                };
                let msg = match res {
                    Err(x) => {
                        println!("WebSocketManager recv ERROR: {}", x);
                        ws_guard.close().await;
                        break;
                    },
                    Ok(y) => y
                };

                match msg {
                    Message::Binary(b) => {
                        let msg = match WebSocketMessage::decode(Bytes::from(b)) {
                            Ok(x) => x,
                            Err(y) => {
                                println!("WebSocketManager ERROR - Message::Binary: {}", y);
                                ws_guard.close_reason(1007, "Badly formatted").await;
                                break;
                            }
                        };
                        ws_guard.on_receive(state.clone(), msg).await;
                    },
                    Message::Text(t) => {
                        println!("Message '{}' from '{}'", t, addr);
                        println!("replying...");
                        ws_guard.send(Message::Text(t)).await;
                        println!("sent!");
                    },
                    Message::Close(_) => {
                        ws_guard.close().await;
                        break;
                    },
                    _ => {}
                }
            } 
            match mgr.remove(&protocol_address).await {
                None => println!("WebSocketManager: Client was already removed from Manager!"),
                _ => {}
            };
        });
    }

    pub async fn is_connected(&mut self, address: &ProtocolAddress) -> bool{
        self.sockets.lock().await.contains_key(address)
    }

    pub async fn get(&self, address: &ProtocolAddress) -> Option<ClientConnection<T>>{
        self.sockets.lock().await.get(address).cloned()
    }

    pub async fn get_mut(&mut self, address: &ProtocolAddress) -> Option<ClientConnection<T>>{
        self.sockets.lock().await.get_mut(address).cloned()
    }

    async fn remove(&mut self, address: &ProtocolAddress) -> Option<ClientConnection<T>>{
        self.sockets.lock().await.remove(address)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use async_std::channel::Send;
    use axum::extract::ws::Message;
    use common::web_api::SignalMessages;
    use prost::Message as PMessage;

    use crate::managers::mock_db::MockDB;
    use crate::managers::state::SignalServerState;
    use crate::managers::websocket::connection::test::{MockSocket, create_connection, mock_envelope};
    use crate::managers::websocket::connection::{WebSocketConnection, ClientConnection};
    use crate::managers::websocket::net_helper;
    use crate::managers::websocket::websocket_manager::WebSocketManager;
    use crate::managers::state;

    #[tokio::test]
    async fn test_insert() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        assert!(mgr.is_connected(&address).await)
    }

    #[tokio::test]
    async fn test_none_msg() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        drop(sender);

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(!mgr.is_connected(&address).await);
        assert!(!ws.lock().await.is_active());
    }

    #[tokio::test]
    async fn test_error_msg() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        sender.send(Err(axum::Error::new("Error message"))).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(!mgr.is_connected(&address).await);
        assert!(!ws.lock().await.is_active());
    }

    #[tokio::test]
    async fn test_close_msg() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        sender.send(Ok(Message::Close(None))).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert!(!mgr.is_connected(&address).await);
        assert!(!ws.lock().await.is_active());
    }

    #[tokio::test]
    async fn test_text_msg() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        sender.send(Ok(Message::Text("hello".to_string()))).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        
        assert!(!receiver.is_empty());
        assert!(mgr.is_connected(&address).await);
        assert!(ws.lock().await.is_active());

        match receiver.recv().await.unwrap() {
            Message::Text(x) => assert!(
                x == "hello",
                "Expected 'hello'"
            ),
            _ => panic!("Did not receive text message"),
        }
    }

    #[tokio::test]
    async fn test_binary_decode_error() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        sender.send(Ok(Message::Binary("hello".as_bytes().to_vec()))).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        
        assert!(!receiver.is_empty());
        assert!(!mgr.is_connected(&address).await);
        assert!(!ws.lock().await.is_active());

        match receiver.recv().await.unwrap() {
            Message::Close(Some(x)) => {
                assert!(x.code == 1007);
                assert!(x.reason == "Badly formatted");
            },
            _ => panic!("Did not receive close message"),
        }
    }

    #[ignore = "not implemented"]
    #[tokio::test]
    async fn test_binary_decode_ok() {
        let msg = r#"
{
    "messages":[
        {
            "type": 1,
            "destinationDeviceId": 3,
            "destinationRegistrationId": 22,
            "content": "aGVsbG8="
        }
    ],
    "online": false,
    "urgent": true,
    "timestamp": 1730217386
}
"#;


        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address();
        mgr.insert(ws, SignalServerState::<MockDB>::new()).await;

        let ws: ClientConnection<MockSocket> = mgr.get(&address).await.unwrap();
        
        assert!(ws.lock().await.is_active());

        
        let id = net_helper::generate_req_id();
        let req = net_helper::create_request(
            id, 
            "PUT", 
            "v1/messages/aaa?story=false", 
            vec![], 
            Some(msg.as_bytes().to_vec()));
            
        sender.send(Ok(Message::Binary(req.encode_to_vec()))).await;
        

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        assert!(!receiver.is_empty());
        assert!(mgr.is_connected(&address).await);
        assert!(ws.lock().await.is_active());

        // TODO: check that response is ok
    }


}
