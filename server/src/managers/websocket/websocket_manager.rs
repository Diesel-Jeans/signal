
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

    pub async fn insert(&mut self, connection: WebSocketConnection<T>){
        let address = connection.protocol_address.clone();
        let connection: ClientConnection<T> = Arc::new(Mutex::new(connection));
        
        self.sockets.lock().await.insert(address.clone(), connection.clone());
        let mut mgr = self.clone();
        
        let protocol_address = address.clone();
        tokio::spawn(async move {
            let connection = connection.clone();
            let addr = connection.lock().await.socket_address;

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
                        ws_guard.on_receive(msg).await;
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

    use crate::managers::websocket::connection::test::{MockSocket, create_connection, mock_envelope};
    use crate::managers::websocket::connection::{WebSocketConnection, ClientConnection};
    use crate::managers::websocket::net_helper;
    use crate::managers::websocket::websocket_manager::WebSocketManager;

    #[tokio::test]
    async fn test_insert() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

        assert!(mgr.is_connected(&address).await)
    }

    #[tokio::test]
    async fn test_none_msg() {
        let mut mgr: WebSocketManager<MockSocket> = WebSocketManager::new();
        let (ws, sender, mut receiver) = create_connection("a", 1, "127.0.0.1:4043");
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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
        let address = ws.protocol_address.clone();
        mgr.insert(ws).await;

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


/*impl<T: WSStream> SocketManager<T> {
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn on_ws_binary(&mut self, connection: &mut WebSocketConnection<T>, bytes: Vec<u8>) {
        let msg = match WebSocketMessage::decode(Bytes::from(bytes)) {
            Ok(x) => x,
            Err(y) => {
                println!("on_ws_binary could not decode bytes: {}", y);
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
    ){
        let uri = Uri::from_str(req.path()).unwrap();
        let path = uri.path();

        if path.starts_with("v1/messages") {
            self.ws_put_message_handler(path, uri.clone(), connection, req).await

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
        status: u32,
        reason: String,
        mut headers: Vec<String>,
        body: Option<Vec<u8>>,
    ) {
        if !headers.iter().any(|x| x.starts_with("Content-Length")){
            headers.push(format!("Content-Length: {}", body.as_ref().map(|v| v.len()).unwrap_or(0)));
        }

        let res = WebSocketResponseMessage {
            id: req.id,
            status: Some(status),
            message: Some(reason),
            headers: headers,
            body: body
        };

        let ws_msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response as i32),
            request: None,
            response: Some(res)
        };
        connection.ws
        .send(Message::Binary(ws_msg.encode_to_vec())).await;
    }

    async fn send_server_error(&mut self, connection: &mut WebSocketConnection<T>,
        req: WebSocketRequestMessage){

        self.send_response(
            connection, 
            req, 
            500, 
            "Error Response".to_string(), 
            vec![format!("Date: {}", current_rfc1123())], 
            None).await
        }

    pub async fn send_message(&mut self, who: &SocketAddr, mut message: Envelope) {
        let state = if let Ok(x) = self.get_ws(who).await {
            x
        } else {
            return; // socket does not exist
        };
        let mut state_g = state.lock().await;
        if let ConnectionState::Active(ref mut connection) = *state_g {
            let id = generate_req_id();
            message.ephemeral = Some(false);
            let body = message.encode_to_vec();
            let req = WebSocketRequestMessage {
                verb: Some("PUT".to_string()),
                body: Some(body),
                path: Some("/api/v1/message".to_string()),
                headers: vec![
                    "X-Signal-Key: false".to_string(),
                    format!("X-Signal-Timestamp: {}", current_millis()),
                ],
                id: Some(id),
            };
            let ws_msg = WebSocketMessage {
                r#type: Some(web_socket_message::Type::Request as i32),
                request: Some(req),
                response: None
            };
            connection.pending_requests.insert(id);
            connection
                .ws
                .send(Message::Binary(ws_msg.encode_to_vec()))
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
        self.sockets.lock().await.remove(who);
    }

    async fn get_ws(
        &self,
        who: &SocketAddr,
    ) -> Result<Arc<Mutex<ConnectionState<T>>>, SocketManagerError> {
        let mut map_guard = self.sockets.lock().await;
        let state = map_guard
            .get_mut(who)
            .ok_or_else(|| SocketManagerError::NoAddress(*who))?;

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

    async fn ws_put_message_handler(&mut self, path: &str, uri: Uri, connection: &mut WebSocketConnection<T>, req: WebSocketRequestMessage, ){
        let id = match  get_path_segment::<String>(path, 2) {
            Err(x) => {
                println!("{}", x);
                self.send_response(connection, req, 400, x, vec![], None).await;
                return;
            },
            Ok(y) => y
        };

        let query: PutV1MessageParams = match  Query::try_from_uri(&uri) {
            Err(x) => {
                println!("{}", x.body_text());
                self.send_response(connection, req, 400, x.body_text(), vec![], None).await;
                return;
            },
            Ok(y) => y.0
        };

        let json = match String::from_utf8(req.body().to_vec()) {
            Err(x) => {
                println!("Body bytes to json failed");
                self.send_response(connection, req, 400, "malformed json".to_string(), vec![], None).await;
                return;
            },
            Ok(y) => y
        };

        let json = match SignalMessages::deserialize(json!(json)) {
            Err(x) => {
                println!("Failed to convert json to SignalMessages");
                self.send_response(connection, req, 400, "Failed to convert json to SignalMessages".to_string(), vec![], None).await;
                return;
            },
            Ok(y) => y
        };

        // TODO: call the real endpoint handler when it is done
        let res: Result<(), ApiError> = Err(ApiError{status_code: StatusCode::UNAUTHORIZED, message: "z".to_string()});

        match res {
            Err(x) => self.send_response(
                connection, 
                req, 
                x.status_code.as_u16().into(), 
                x.message, 
                vec![], 
                None).await, // TODO: real server can output jason if error
            Ok(y) => self.send_response(
                connection, 
                req, 
                200, 
                "OK".to_string(), 
                vec![], 
                None) // TODO: convert OK body to some bytes
                .await,
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

fn current_rfc1123() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
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

    use tokio::sync::mpsc::{channel, Receiver, Sender};

    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Debug)]
    struct MockSocket {
        client_sender: Receiver<Result<Message, Error>>,
        client_receiver: Sender<Message>,
    }

    impl MockSocket {
        fn new() -> (Self, Sender<Result<Message, Error>>, Receiver<Message>) {
            let (send_to_socket, client_sender) = channel(10); // Queue for test -> socket
            let (client_receiver, receive_from_socket) = channel(10); // Queue for socket -> test

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
    async fn test_send_text_response_ok() {
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
}*/
