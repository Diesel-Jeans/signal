use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::Error;
use common::signal_protobuf::{
    envelope, web_socket_message, Envelope, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use libsignal_core::{ProtocolAddress, ServiceIdKind, DeviceId};
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::SystemTimeError;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::account::AuthenticatedDevice;
use crate::database::SignalDatabase;
use crate::managers::state::SignalServerState;
use crate::message_cache::MessageAvailabilityListener;

use prost::{bytes::Bytes, Message as PMessage};

use super::net_helper::{create_request, current_millis, generate_req_id};
use super::wsstream::WSStream;

#[derive(Debug)]
pub enum UserIdentity {
    ProtocolAddress(ProtocolAddress),
    AuthenticatedDevice(AuthenticatedDevice),
}

#[derive(Debug)]
pub struct WebSocketConnection<W: WSStream + Debug, DB: SignalDatabase> {
    identity: UserIdentity,
    socket_address: SocketAddr,
    ws: ConnectionState<W>,
    pending_requests: HashSet<u64>,
    state: SignalServerState<DB, W>
}

impl<W: WSStream + Debug + Send + 'static, DB: SignalDatabase + Send + 'static> WebSocketConnection<W, DB> {
    pub fn new(identity: UserIdentity, socket_addr: SocketAddr, ws: W, state: SignalServerState<DB, W>) -> Self {
        Self {
            identity,
            socket_address: socket_addr,
            ws: ConnectionState::Active(ws),
            pending_requests: HashSet::new(),
            state: state
        }
    }

    pub fn socket_address(&self) -> SocketAddr {
        self.socket_address
    }

    pub fn protocol_address(&self) -> ProtocolAddress {
        match &self.identity {
            UserIdentity::AuthenticatedDevice(x) => x.get_protocol_address(ServiceIdKind::Aci),
            UserIdentity::ProtocolAddress(y) => y.clone(),
        }
    }

    pub async fn send_message(&mut self, mut message: Envelope) -> Result<(), String> {
        let msg = match self.create_message(message) {
            Ok(x) => x,
            Err(_) => return Err("Time went backwards".to_string()),
        };
        match self.send(Message::Binary(msg.encode_to_vec())).await {
            Ok(_) => Ok(()),
            Err(x) => Err(format!("{}", x)),
        }
    }

    pub async fn send_messages(&mut self, cached_only: bool) -> bool{
        let msg_mgr = self.state.message_manager();
        
        let addr = self.protocol_address();
        let res = msg_mgr.get_messages_for_device(&addr, cached_only).await;
        let envelopes = match res {
            Ok(x) => x,
            Err(_) => {
                println!("Failed to fetch messages");
                return false
            }
        };

        for envelope in envelopes{
            self.send_message(envelope).await.map_err(|e| println!("{}", e));
        }
        return true
    }

    fn create_message(
        &mut self,
        mut message: Envelope,
    ) -> Result<WebSocketMessage, SystemTimeError> {
        let id = generate_req_id();
        message.ephemeral = Some(false);
        let msg = create_request(
            id,
            "PUT",
            "/api/v1/message",
            vec![
                "X-Signal-Key: false".to_string(),
                format!("X-Signal-Timestamp: {}", current_millis()?),
            ],
            Some(message.encode_to_vec()),
        );
        self.pending_requests.insert(id);
        Ok(msg)
    }

    pub async fn close(&mut self) {
        if let ConnectionState::Active(socket) =
            std::mem::replace(&mut self.ws, ConnectionState::Closed)
        {
            socket.close().await;
        }
    }

    pub async fn close_reason(&mut self, code: u16, reason: &str) -> Result<(), String> {
        let fut = self.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.to_string().into(),
        })));

        if let Err(x) = fut.await {
            return Err(format!("{}", x));
        }
        self.close().await;
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.ws.is_active()
    }

    pub async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        match self.ws {
            ConnectionState::Active(ref mut socket) => socket.recv().await,
            ConnectionState::Closed => None,
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<(), axum::Error> {
        match self.ws {
            ConnectionState::Active(ref mut socket) => socket.send(msg).await,
            ConnectionState::Closed => Err(axum::Error::new("Connection is closed")),
        }
    }

    pub async fn on_receive(
        &mut self,
        proto_message: WebSocketMessage,
    ) {
        todo!()
    }
}


#[async_trait::async_trait]
impl<T, U> MessageAvailabilityListener for WebSocketConnection<T, U>
where T: WSStream + Debug + 'static, U: SignalDatabase{
    async fn handle_new_messages_available(&mut self) -> bool {
        if !self.is_active(){
            return false
        }
        
        self.send_messages(true).await
    }

    async fn handle_messages_persisted(&mut self) -> bool {
        if !self.is_active(){
            return false
        }
        self.send_messages(false).await
    }
}

#[derive(Debug)]
pub enum ConnectionState<T: WSStream> {
    Active(T),
    Closed,
}

impl<T: WSStream + Debug> ConnectionState<T> {
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Active(_))
    }
}

pub type ClientConnection<T, U> = Arc<Mutex<WebSocketConnection<T, U>>>;
pub type ConnectionMap<T, U> = Arc<Mutex<HashMap<ProtocolAddress, ClientConnection<T, U>>>>;

#[cfg(test)]
pub(crate) mod test {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use crate::managers::mock_helper::{MockDB, MockSocket};
    use crate::managers::state::SignalServerState;
    use crate::managers::websocket::net_helper::{self, unpack_messages};
    use common::signal_protobuf::{envelope, Envelope, WebSocketMessage, WebSocketRequestMessage};
    use common::web_api::SignalMessages;
    use libsignal_core::ProtocolAddress;
    use sha2::digest::consts::False;

    use super::{ClientConnection, UserIdentity, WSStream, WebSocketConnection};
    use axum::extract::ws::{CloseFrame, Message};
    use axum::Error;

    use tokio::sync::mpsc::{channel, Receiver, Sender};

    use prost::{bytes::Bytes, Message as PMessage};
    use std::sync::Arc;
    use tokio::sync::Mutex;


    pub fn mock_envelope() -> Envelope {
        Envelope {
            r#type: Some(envelope::Type::PlaintextContent as i32),
            source_service_id: Some("aaa".to_string()),
            source_device: Some(1),
            client_timestamp: Some(1730217386),
            content: Some("Hello".as_bytes().to_vec()),
            server_guid: Some("a".to_string()),
            server_timestamp: Some(1730217387),
            ephemeral: Some(false),
            destination_service_id: Some("aa".to_string()),
            urgent: Some(true),
            updated_pni: Some("b?".to_string()),
            story: Some(false),
            report_spam_token: None,
            shared_mrm_key: None,
        }
    }

    pub fn create_connection(
        name: &str,
        device_id: u32,
        socket_addr: &str,
        state: SignalServerState::<MockDB, MockSocket>
    ) -> (
        WebSocketConnection<MockSocket, MockDB>,
        Sender<Result<Message, Error>>,
        Receiver<Message>,
    ) {
        let (mock, sender, mut receiver) = MockSocket::new();
        let who = SocketAddr::from_str(socket_addr).unwrap();
        let paddr = ProtocolAddress::new(name.to_string(), device_id.into());

        let ws = WebSocketConnection::new(UserIdentity::ProtocolAddress(paddr), who, mock, state);

        (ws, sender, receiver)
    }

    #[tokio::test]
    async fn test_send_and_recv() {
        let state = SignalServerState::<MockDB, MockSocket>::new();
        let (mut client, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4042", state);

        sender.send(Ok(Message::Text("hello".to_string()))).await;

        match client.recv().await {
            Some(Ok(Message::Text(x))) => assert!(x == "hello", "message was not hello"),
            _ => panic!("Unexpected error when receiving msg"),
        }

        client.send(Message::Text("hello back".to_string())).await;

        if receiver.is_empty() {
            panic!("receiver was empty when it was expected not to be")
        }

        match receiver.recv().await {
            Some(Message::Text(x)) => assert!(x == "hello back", "message was not 'hello back'"),
            _ => panic!("Unexpected error when receiving msg"),
        }
    }

    #[tokio::test]
    async fn test_close() {
        let state = SignalServerState::<MockDB, MockSocket>::new();
        let (mut client, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4042", state);

        assert!(client.is_active());
        client.close().await;
        assert!(!client.is_active());
    }

    #[tokio::test]
    async fn test_close_reason() {
        let state = SignalServerState::<MockDB, MockSocket>::new();
        let (mut client, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4042", state);
        assert!(client.is_active());
        client.close_reason(666, "test").await;
        assert!(!client.is_active());

        assert!(!receiver.is_empty());
        match receiver.recv().await {
            Some(Message::Close(Some(x))) => {
                assert!(x.code == 666);
                assert!(x.reason == "test");
            }
            _ => panic!("Did not receive close frame"),
        }
    }

    #[tokio::test]
    async fn test_send_message() {
        let state = SignalServerState::<MockDB, MockSocket>::new();
        let (mut client, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4042", state);
        let env = mock_envelope();
        client.send_message(env.clone()).await;

        assert!(!receiver.is_empty());

        let msg = match receiver.recv().await {
            Some(Message::Binary(x)) => WebSocketMessage::decode(Bytes::from(x))
                .expect("unexpected error in decode websocket message"),
            _ => panic!("Did not receive close frame"),
        };

        assert!(msg.request.is_some());
        assert!(client.pending_requests.len() != 0);
        let req = msg.request.unwrap();

        assert!(req.verb.unwrap() == "PUT");
        assert!(req.path.unwrap() == "/api/v1/message");
        assert!(req.headers.len() == 2);
        assert!(req.headers[0] == "X-Signal-Key: false");
        assert!(req.headers[1].starts_with("X-Signal-Timestamp:"));
        assert!(req.body.unwrap() == env.encode_to_vec());
    }

    #[ignore = "Not implemented"]
    #[tokio::test]
    async fn test_on_receive() {
        todo!()
    }
}
