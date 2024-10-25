use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::Query;
use axum::http::Uri;
use libsignal_core::{DeviceId, ServiceId};
use serde::de::IntoDeserializer;
use serde::Deserialize;
use serde_json::json;
use sha2::digest::consts::False;
use sha2::digest::typenum::Integer;
use std::fmt::{self, Debug};
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
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::account::Account;
use crate::connection::{WSStream, WebSocketConnection};
use crate::error::SocketManagerError;
use crate::query::PutV1MessageParams;

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

pub trait ToEnvelope {
    fn to_envelope(
        &mut self,
        destination_id: ServiceId,
        account: Option<Account>,
        src_device_id: Option<DeviceId>,
        timestamp: i64,
        story: bool,
        urgent: bool,
    ) -> Envelope;
}

impl ToEnvelope for SignalMessage {
    fn to_envelope(
        &mut self,
        destination_id: ServiceId,
        account: Option<Account>,
        src_device_id: Option<DeviceId>,
        timestamp: i64,
        story: bool,
        urgent: bool,
    ) -> Envelope {
        let typex = envelope::Type::try_from(self.r#type as i32).unwrap();
        todo!() // TODO: make this when Account has been implemented correctly
    }
}

#[derive(Debug)]
enum ConnectionState<T: WSStream> {
    Active(WebSocketConnection<T>),
    Closed,
}

impl<T: WSStream + Debug> ConnectionState<T> {
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Active(_))
    }
}

type ConnectionMap<T> = Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<ConnectionState<T>>>>>>;

#[derive(Debug)]
pub struct SocketManager<T: WSStream> {
    sockets: ConnectionMap<T>,
}

impl<T: WSStream> Clone for SocketManager<T> {
    fn clone(&self) -> Self {
        Self {
            sockets: Arc::clone(&self.sockets),
        }
    }
}

impl<T: WSStream> SocketManager<T> {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn on_ws_binary(&mut self, connection: &mut WebSocketConnection<T>, bytes: Vec<u8>) {
        let msg = match WebSocketMessage::decode(Bytes::from(bytes)) {
            Ok(x) => x,
            Err(y) => {
                println!("handle_socket ws proto ERROR: {}", y);
                return;
            }
        };

        match msg.r#type() {
            web_socket_message::Type::Request => {
                if let Some(req) = msg.request {
                    self.handle_request(connection, req).await
                } else {
                    todo!() // TODO: handle not request when type request
                }
            }
            web_socket_message::Type::Response => {
                if let Some(res) = msg.response {
                    self.handle_response(connection, res).await
                } else {
                    todo!() // TODO: handle not response when type response
                }
            }
            _ => {
                self.close_socket(connection, 1007, "Badly formatted".to_string())
                    .await
            }
        }
    }

    async fn handle_request(
        &mut self,
        connection: &mut WebSocketConnection<T>,
        req: WebSocketRequestMessage,
    ) {
        let uri = Uri::from_str(req.path()).unwrap();
        let path = uri.path();

        if path.starts_with("v1/messages") {
            let id = get_path_segment::<String>(path, 2).unwrap();
            let query: Query<PutV1MessageParams> = Query::try_from_uri(&uri).unwrap();
            let json = String::from_utf8(req.body().to_vec()).unwrap();
            let messages = SignalMessages::deserialize(json!(json)).unwrap();
            todo!(); // TODO: call handle_put_messages
                     //self.send_response(connection, req, status, reason, headers, body);

        // add more endpoints below as needed
        } else {
            println!("Unkown WS request path '{}'", path)
        }
    }

    async fn handle_response(
        &mut self,
        connection: &mut WebSocketConnection<T>,
        res: WebSocketResponseMessage,
    ) {
        if let Some(id) = res.id {
            connection.pending_requests.remove(&id);
        } else {
            println!("response to what?") // TODO: should probably be handled better
        }
    }

    async fn send_response(
        &mut self,
        connection: &mut WebSocketConnection<T>,
        req: WebSocketRequestMessage,
        status: u16,
        reason: String,
        headers: Vec<String>,
        body: Option<Vec<u8>>,
    ) {
        todo!()
    }

    pub async fn send_message(&mut self, who: &SocketAddr, message: Envelope) {
        let state = if let Ok(x) = self.get_ws(who).await {
            x
        } else {
            return; // socket does not exist
        };
        let mut state_g = state.lock().await;
        if let ConnectionState::Active(ref mut connection) = *state_g {
            let id = generate_req_id();
            let body = message.encode_to_vec();
            let req = WebSocketRequestMessage {
                verb: Some("PUT".to_string()),
                path: Some("/api/v1/message".to_string()),
                body: Some(body),
                headers: vec![
                    "X-Signal-Key: false".to_string(),
                    format!("X-Signal-Timestamp: {}", current_millis()),
                ],
                id: Some(id),
            };
            connection.pending_requests.insert(id);
            connection
                .ws
                .send(Message::Binary(req.encode_to_vec()))
                .await;
        }
    }

    async fn close_socket(
        &mut self,
        connection: &mut WebSocketConnection<T>,
        code: u16,
        reason: String,
    ) {
        connection.ws.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })));
        self.remove_ws(&connection.addr);
    }

    async fn on_ws_text(&mut self, connection: &mut WebSocketConnection<T>, text: String) {
        // this is used for testing
        println!("🎵happy happy happy🎵: {}", text);
        connection.ws.send(Message::Text("OK".to_string())).await;
    }

    async fn add_ws(&self, who: SocketAddr, socket: T) {
        let state = ConnectionState::Active(WebSocketConnection::new(who, socket));
        self.sockets
            .lock()
            .await
            .insert(who, Arc::new(Mutex::new(state)));
    }

    async fn remove_ws(&self, who: &SocketAddr) {
        let mut guard = self.sockets.lock().await;
        guard.remove(who);
    }

    async fn get_ws(
        &self,
        who: &SocketAddr,
    ) -> Result<Arc<Mutex<ConnectionState<T>>>, SocketManagerError> {
        let mut map_guard = self.sockets.lock().await;
        let state = if let Some(x) = map_guard.get_mut(who) {
            x
        } else {
            return Err(SocketManagerError::NoAddress(*who));
        };

        Ok(state.clone())
    }

    async fn contains(&self, who: &SocketAddr) -> bool {
        self.sockets.lock().await.contains_key(who)
    }

    pub async fn handle_socket(
        &mut self,
        /*authenticated_device: ???, */
        mut socket: T,
        who: SocketAddr,
    ) {
        /* authenticated_device should be put into the socket_manager,
        we should probably have a representation like in the real server */
        if self.contains(&who).await {
            return; // do not handle socket twice
        }
        self.add_ws(who, socket).await;

        let state = if let Ok(x) = self.get_ws(&who).await {
            x
        } else {
            return; // socket does not exist
        };

        // this will always check if the state is active, and exit if some other thread has closed the socket
        loop {
            let mut state_g = state.lock().await;

            let connection = if let ConnectionState::Active(ref mut x) = *state_g {
                x
            } else {
                break;
            };

            let msg = match connection.ws.recv().await {
                Some(Ok(x)) => x,
                None => {
                    *state_g = ConnectionState::Closed;
                    break;
                }
                _ => {
                    self.close_socket(connection, 1007, "Badly formatted".to_string())
                        .await;
                    *state_g = ConnectionState::Closed;
                    break;
                }
            };

            match msg {
                Message::Binary(b) => self.on_ws_binary(connection, b).await,
                Message::Text(t) => self.on_ws_text(connection, t).await,
                Message::Close(_) => {
                    println!("handle_socket: '{}' disconnected", who);
                    self.remove_ws(&connection.addr).await;
                    *state_g = ConnectionState::Closed;
                    break;
                }
                _ => { /* i dont know if we should support more? */ }
            }
        }
    }
}

fn get_path_segment<T: FromStr<Err = impl std::fmt::Debug>>(
    uri: &str,
    n: usize,
) -> Result<T, String> {
    if uri.contains("?") {
        return Err("Contains query params".to_string());
    }

    let mut parts: Vec<&str> = uri.split("/").collect();
    if parts.is_empty() {
        return Err("no parts".to_string());
    }

    parts.remove(0);

    if n >= parts.len() {
        return Err("larger than count".to_string());
    }

    match T::from_str(parts[n]) {
        Ok(x) => Ok(x),
        Err(_) => Err("failed to convert".to_string()),
    }
}

fn current_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}

fn generate_req_id() -> u64 {
    let mut rng = OsRng;
    let rand_v: u64 = rng.gen();
    rand_v
}

#[cfg(test)]
pub(crate) mod test {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use crate::connection::WSStream;
    use crate::socket::{ConnectionState, SocketManager, SocketManagerError};
    use axum::extract::ws::Message;
    use axum::Error;

    use tokio::sync::mpsc;
    use tokio::sync::mpsc::{Receiver, Sender};

    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Debug)]
    struct MockSocket {
        client_sender: Receiver<Result<Message, Error>>,
        client_receiver: Sender<Message>,
    }

    impl MockSocket {
        fn new() -> (Self, Sender<Result<Message, Error>>, Receiver<Message>) {
            let (send_to_socket, client_sender) = mpsc::channel(10); // Queue for test -> socket
            let (client_receiver, receive_from_socket) = mpsc::channel(10); // Queue for socket -> test

            (
                Self {
                    client_sender,
                    client_receiver,
                },
                send_to_socket,
                receive_from_socket,
            )
        }
    }

    #[async_trait::async_trait]
    impl WSStream for MockSocket {
        async fn recv(&mut self) -> Option<Result<Message, Error>> {
            self.client_sender.recv().await
        }

        async fn send(&mut self, msg: Message) -> Result<(), Error> {
            self.client_receiver
                .send(msg)
                .await
                .map_err(|_| Error::new("Send failed".to_string()))
        }

        async fn close(self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_mock() {
        let (mut mock, mut sender, mut receiver) = MockSocket::new();

        tokio::spawn(async move {
            if let Some(Ok(Message::Text(x))) = mock.recv().await {
                mock.send(Message::Text(x)).await
            } else {
                panic!("Expected Text Message");
            }
        });

        sender.send(Ok(Message::Text("hello".to_string()))).await;

        match receiver.recv().await.unwrap() {
            Message::Text(x) => assert!(
                x == "hello",
                "ASSERTION ERROR >>>>>>>    Expected 'hello' in test_mock    <<<<<<<<"
            ),
            _ => panic!(">>>>>>>>>>>>>>>>>>>>> Did not receive text message"),
        }
    }

    async fn create_connection(
        manager: &SocketManager<MockSocket>,
        addr: &str,
        wait: u64,
    ) -> (
        Arc<Mutex<ConnectionState<MockSocket>>>,
        Sender<Result<Message, Error>>,
        Receiver<Message>,
    ) {
        let (mock, sender, mut receiver) = MockSocket::new();
        let who = SocketAddr::from_str(addr).unwrap();
        let mut tmgr = manager.clone();
        tokio::spawn(async move {
            tmgr.handle_socket(mock, who).await;
        });

        // could be fixed with some notify code
        tokio::time::sleep(tokio::time::Duration::from_millis(wait)).await;

        let state = manager.get_ws(&who).await.unwrap();

        (state, sender, receiver)
    }

    #[tokio::test]
    async fn test_active_then_close() {
        let mut sm: SocketManager<MockSocket> = SocketManager::new();

        let (state, sender, _) = create_connection(&sm, "127.0.0.1:5555", 100).await;

        sender.send(Ok(Message::Text("Hello".to_string()))).await;

        assert!(
            state.lock().await.is_active(),
            ">>>>>>>>>>>>>>>>>>>>>> State was closed prematurely"
        );

        sender.send(Ok(Message::Close(None))).await;

        assert!(
            !state.lock().await.is_active(),
            ">>>>>>>>>>>>>>>>>>>>> State was active, expected was closed"
        )
    }

    #[tokio::test]
    async fn test_text_relay_ok() {
        let mut sm: SocketManager<MockSocket> = SocketManager::new();

        let (state, sender, mut receiver) = create_connection(&sm, "127.0.0.1:5555", 100).await;

        sender.send(Ok(Message::Text("Hello".to_string()))).await;

        assert!(
            state.lock().await.is_active(),
            ">>>>>>>>>>>>>>>>>>>>>> State was closed prematurely"
        );

        match receiver.recv().await {
            Some(Message::Text(x)) => assert!(x == "OK"),
            _ => panic!("Unexpected message format"),
        }

        sender.send(Ok(Message::Close(None))).await;

        assert!(
            !state.lock().await.is_active(),
            ">>>>>>>>>>>>>>>>>>>>> State was active, expected was closed"
        )
    }
}
