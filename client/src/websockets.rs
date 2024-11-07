use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine as _};
use common::signalservice::{WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage};
use futures_util::{SinkExt, StreamExt};
use native_tls::{Certificate, TlsConnector as NativeTlsConnector};
use prost::Message as ProstMessage;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::{
    collections::HashMap,
    fs,
    future::Future,
    net::ToSocketAddrs,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    runtime::Handle,
    spawn,
    sync::Mutex,
    task::{yield_now, AbortHandle, JoinHandle},
    time::sleep,
};
use tokio_native_tls::{TlsConnector, TlsStream};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http,
        protocol::{frame, Message, WebSocketConfig},
    },
    WebSocketStream,
};

// Constants used by Signal, and therefore also used in our project
const SECOND: u32 = 1000;
const MINUTE: u32 = SECOND * 60;

// 30 seconds + 5 seconds for closing the socket above.
const KEEPALIVE_INTERVAL_MS: u32 = 30 * SECOND;

// If the machine was in suspended mode for more than 5 minutes - trigger
// immediate disconnect.
const STALE_THRESHOLD_MS: u32 = 5 * MINUTE;

// If we don't receive a response to keepalive request within 30 seconds -
// close the socket.
const KEEPALIVE_TIMEOUT_MS: u32 = 30 * SECOND;

struct StreamHandler {
    pub stream: WebSocketStream<TlsStream<TcpStream>>,
}

impl StreamHandler {
    async fn try_new(
        address: String,
        port: String,
        username: String,
        password: String,
    ) -> Result<StreamHandler> {
        let stream =
            open_ws_connection_to_server_as_client(address, port, username, password).await?;
        Ok(StreamHandler { stream })
    }
}

#[derive(Clone)]
pub(crate) struct WebsocketHandler {
    socket: Arc<Mutex<StreamHandler>>,
    receiver_handle: Arc<thread::JoinHandle<JoinHandle<()>>>,
    text_channel: Arc<Mutex<mpsc::Receiver<Message>>>,
    ws_request_channel: Arc<Mutex<mpsc::Receiver<WebSocketRequestMessage>>>,
    outgoing_id: Arc<Mutex<u64>>,
    outgoing_map: Arc<Mutex<HashMap<u64, AbortHandle>>>,
    incoming_response: Arc<Mutex<HashMap<u64, WebSocketResponseMessage>>>,
    keepalive_handler: Option<Arc<Mutex<KeepaliveHandler>>>,
    has_keepalive: bool,
}

impl WebsocketHandler {
    pub async fn try_new(
        keepalive_options: Option<KeepAliveOptions>,
        address: String,
        port: String,
        username: String,
        password: String,
    ) -> Result<WebsocketHandler> {
        let socket = Arc::new(Mutex::new(
            StreamHandler::try_new(address, port, username, password).await?,
        ));
        let res: Arc<Mutex<HashMap<u64, WebSocketResponseMessage>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let out: Arc<Mutex<HashMap<u64, AbortHandle>>> = Arc::new(Mutex::new(HashMap::new()));
        let (handle, text_channel, request_channel) =
            WebsocketHandler::get_handle_for_ws_listener(socket.clone(), res.clone(), out.clone());

        let mut ws_handler = WebsocketHandler {
            socket,
            receiver_handle: Arc::new(handle),
            text_channel: Arc::new(Mutex::new(text_channel)),
            outgoing_id: Arc::new(Mutex::new(1)),
            outgoing_map: out,
            has_keepalive: keepalive_options.is_some(),
            incoming_response: res,
            keepalive_handler: None,
            ws_request_channel: Arc::new(Mutex::new(request_channel)),
        };

        if keepalive_options.is_some() {
            let keepalive = KeepaliveHandler::new(
                keepalive_options.unwrap(),
                Arc::new(Mutex::new(ws_handler.clone())),
            );
            ws_handler.keepalive_handler = Some(Arc::new(Mutex::new(keepalive)));
            ws_handler
                .keepalive_handler
                .clone()
                .unwrap()
                .lock()
                .await
                .reset_keepalive()
                .await;
        }

        Ok(ws_handler)
    }

    fn get_handle_for_ws_listener(
        sock: Arc<Mutex<StreamHandler>>,
        incoming: Arc<Mutex<HashMap<u64, WebSocketResponseMessage>>>,
        outgoing: Arc<Mutex<HashMap<u64, AbortHandle>>>,
    ) -> (
        thread::JoinHandle<JoinHandle<()>>,
        mpsc::Receiver<Message>,
        mpsc::Receiver<WebSocketRequestMessage>,
    ) {
        let (message_tx, message_rx) = mpsc::channel::<Message>();
        let handle = Handle::current();
        let mtx = message_tx.clone();
        let (request_tx, request_rx) = mpsc::channel::<WebSocketRequestMessage>();

        //This is a fragile house of cards so don't change the spawn structure
        let hand = thread::spawn(move || {
            handle.spawn(async move {
                while let Some(Ok(msg)) = sock.lock().await.stream.next().await {
                    match msg {
                        Message::Text(msg) => {
                            if mtx.send(Message::Text(msg)).is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            let Ok(wsm) = WebSocketMessage::decode(data.as_slice()) else {
                                continue;
                            };
                            //Types of WebSocketMessage: 0 = UNKNOWN, 1 = REQUEST, 2 = RESPONSE
                            match wsm.r#type {
                                Some(1) => {
                                    let request = wsm
                                        .request
                                        .expect("Got a request type without an attached request");
                                    if request_tx.send(request).is_err() {
                                        //Requests will be handled by the receive channel
                                        break;
                                    }
                                }
                                Some(2) => {
                                    //Expect is fine here, as it is system breaking to get a type mismatch
                                    let wsrm = wsm.response.expect(
                                        "Got a WebSocketMessageResponse type without a response",
                                    );
                                    let Some(id) = wsrm.id else { break };
                                    incoming.lock().await.insert(id, wsrm);
                                    if let Some(hand) = outgoing.lock().await.get(&id) {
                                        hand.abort();
                                        outgoing.lock().await.remove(&id);
                                    }
                                }
                                _ => todo!(),
                            }
                        }
                        _ => continue,
                    }
                    thread::yield_now();
                }
            })
        });
        (hand, message_rx, request_rx)
    }

    //ONLY FOR TESTING PURPOSES!!!
    #[cfg(test)]
    async fn send_text_no_response_expected(&mut self, text: String) -> Result<()> {
        Ok(self
            .socket
            .lock()
            .await
            .stream
            .send(Message::Text(text))
            .await?)
    }

    pub async fn send_request(
        &mut self,
        options: SendRequestOptions,
    ) -> Result<WebSocketResponseMessage> {
        let mut lock = self.outgoing_id.lock().await;
        let id = *lock;
        *lock += 1;
        drop(lock);

        if self.outgoing_map.lock().await.contains_key(&id) {
            bail!("Duplicate outgoing request")
        }

        let mut header_vec: Vec<String> = Vec::new();

        if let Some(headers) = options.headers {
            headers
                .iter()
                .for_each(|(key, value)| header_vec.push(format!("{}:{}", key, value)));
        }

        //Make the protobuf message and convert it to bytes
        let ws_msg = WebSocketMessage {
            r#type: Some(1),
            request: Some(WebSocketRequestMessage {
                id: Some(id),
                verb: Some(options.verb),
                path: Some(options.path),
                headers: header_vec,
                body: options.body,
            }),
            response: None,
        };
        let msg = Message::Binary(ws_msg.encode_to_vec());

        //Send the message over ws
        self.socket.lock().await.stream.send(msg).await?;

        let self_clone = self.clone();

        let promise = spawn(async move {
            if self_clone.has_keepalive {
                set_timeout(KEEPALIVE_TIMEOUT_MS.into(), || async move {
                    if let Some(handle) = self_clone.outgoing_map.lock().await.remove(&id) {
                        handle.abort();
                    }
                    self_clone
                        .socket
                        .lock()
                        .await
                        .stream
                        .send(Message::Close(Some(frame::CloseFrame {
                            code: 3008.into(),
                            reason: "Timed out".into(),
                        })))
                        .await;
                })
                .await;
            }
        });

        //Add future to hashmap
        self.outgoing_map
            .lock()
            .await
            .insert(id, promise.abort_handle());

        promise.await?;

        if let Some(incoming) = self.incoming_response.lock().await.get(&id) {
            let Some(status) = incoming.status else {
                panic!()
            };

            if (200..=299).contains(&status) {
                Ok(incoming.clone())
            } else {
                bail!("Got a bad response")
            }
        } else {
            bail!("Incoming response missing")
        }
    }

    pub async fn get_messages(&mut self) -> Vec<WebSocketRequestMessage> {
        let mut msg_vec: Vec<WebSocketRequestMessage> = Vec::new();

        while let Ok(msg) = self.ws_request_channel.lock().await.try_recv() {
            msg_vec.push(msg);
        }

        msg_vec
    }

    pub async fn close(&mut self, code: u16, reason: String) -> Result<()> {
        Ok(self
            .socket
            .lock()
            .await
            .stream
            .close(Some(frame::CloseFrame {
                code: code.into(),
                reason: reason.into(),
            }))
            .await?)
    }
}

#[derive(Clone)]
pub struct SendRequestOptions {
    verb: String,
    path: String,
    body: Option<Vec<u8>>,
    timeout: Option<u32>,
    headers: Option<Vec<(String, String)>>,
}
impl SendRequestOptions {
    pub fn new(
        verb: impl Into<String>,
        path: impl Into<String>,
        body: impl Into<Option<Vec<u8>>>,
    ) -> Self {
        SendRequestOptions {
            verb: verb.into(),
            path: path.into(),
            body: body.into(),
            timeout: None,
            headers: None,
        }
    }
}

#[derive(Clone)]
pub struct KeepAliveOptions {
    pub path: Option<String>,
}

#[derive(Clone)]
struct KeepaliveHandler {
    keepalive_options: KeepAliveOptions,
    last_alive_at: Arc<Mutex<Instant>>,
    timer_map: Arc<Mutex<HashMap<u32, JoinHandle<()>>>>,
    websocket_resource: Arc<Mutex<WebsocketHandler>>,
}

impl KeepaliveHandler {
    pub fn new(
        keepalive_options: KeepAliveOptions,
        websocket_resource: Arc<Mutex<WebsocketHandler>>,
    ) -> Self {
        KeepaliveHandler {
            keepalive_options,
            last_alive_at: Arc::new(Mutex::new(Instant::now())),
            timer_map: Arc::new(Mutex::new(HashMap::new())),
            websocket_resource,
        }
    }

    pub async fn reset_keepalive(&mut self) {
        *self.last_alive_at.clone().lock().await = Instant::now();
        self.set_timeout(KEEPALIVE_INTERVAL_MS).await;
    }

    //KeepAlive contains two send methods to replicate the functionality of Signal-Desktop to the best of my ability
    async fn keepalive_super_send(&mut self) -> Result<bool> {
        let request_options = SendRequestOptions {
            verb: "GET".to_string(),
            path: "/v1/keepalive".to_string(),
            body: None,
            headers: None,
            timeout: Some(KEEPALIVE_TIMEOUT_MS),
        };

        let result = self
            .websocket_resource
            .lock()
            .await
            .send_request(request_options)
            .await?;

        if let Some(status) = result.status {
            if !(200..300).contains(&status) {
                self.websocket_resource
                    .lock()
                    .await
                    .close(3001, format!("keepalive response with {} code", status))
                    .await?;
                bail!("keepalive response with {} code", status);
            }
        } else {
            bail!("keepalive response without code");
        }

        Ok(true)
    }

    pub async fn keepalive_send(&mut self) -> Result<bool> {
        if self.last_alive_at.lock().await.elapsed().as_millis() > STALE_THRESHOLD_MS.into() {
            self.websocket_resource
                .lock()
                .await
                .close(
                    3001,
                    format!(
                        "Last keepalive request was too far in the past: {}",
                        self.last_alive_at.lock().await.elapsed().as_millis()
                    ),
                )
                .await?;
            bail!("Connection is stale")
        }

        self.clone().keepalive_super_send().await
    }

    pub async fn set_timeout(&mut self, timeout: u32) {
        let counter = loop {
            //Don't ask me why Signal-Desktop does this, but we're also doing it. Just be happy I didn't implement the 0 bit bitshift
            let mut id = 0;
            if self.timer_map.lock().await.contains_key(&id) {
                id += 1;
            } else {
                break id;
            }
        };

        let handler = Arc::new(Mutex::new(self.clone()));
        let handle = spawn(async move {
            loop {
                let now = Instant::now();
                while now.elapsed().as_millis() <= timeout.into() {
                    yield_now().await;
                }
                match handler.lock().await.keepalive_send().await {
                    Ok(true) => (),
                    _ => break,
                }
            }
        });

        // Lock the timer_map and insert the handle for the spawned task
        self.timer_map.lock().await.insert(counter, handle);
    }

    pub async fn clear_timeout(&mut self) {
        for (key, handle) in self.timer_map.lock().await.iter_mut() {
            handle.abort();
            self.timer_map.lock().await.remove(key);
        }
    }
}

pub(crate) async fn open_ws_connection_to_server_as_client(
    address: String,
    port: String,
    username: String,
    password: String,
) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let auth_kv_pair = format!("{}:{}", username, password);
    let auth_value = general_purpose::STANDARD.encode(&auth_kv_pair);

    let ws_url = format!("wss://{}@{}:{}/v1/websocket", auth_kv_pair, address, port);
    let mut ws_req = ws_url.clone().into_client_request()?;
    let mhead = ws_req.headers_mut();
    mhead.insert(
        http::header::AUTHORIZATION,
        format!("Basic {}", auth_value).parse()?,
    );
    //No idea what this does, but Harder's python script sets this header field automatically
    mhead.insert(
        http::header::SEC_WEBSOCKET_EXTENSIONS,
        "permessage-deflate; client_max_window_bits"
            .to_string()
            .parse()?,
    );

    let mut tls_connector = NativeTlsConnector::builder();
    for cert in get_certs()? {
        tls_connector.add_root_certificate(cert);
    }

    let connector = tls_connector.build()?;

    // Create a TcpSocket, enable keepalive, and set intervals - all related to issue #56
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_keepalive(true)?;
    socket.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(10))
            .with_interval(Duration::from_secs(10)),
    )?;

    // Resolve address and convert to SockAddr
    let socket_address = format!("{}:{}", address.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve address"))?;
    let sock_addr = socket2::SockAddr::from(socket_address);

    // Connect and convert to Tokio TcpStream.parse()?
    socket.connect(&sock_addr)?;
    let tcp_stream = TcpStream::from_std(socket.into())?;
    let stream_connector = TlsConnector::from(connector);

    // Apply TLS wrapping
    let tls_stream = stream_connector
        .connect(address.as_str(), tcp_stream)
        .await?;

    //Config to ensure the correct max frame size is enforced, related to issue #56
    let conf = WebSocketConfig {
        max_frame_size: Some(0x210000),
        ..WebSocketConfig::default()
    };

    let (ws_stream, _) = client_async_with_config(ws_req, tls_stream, Some(conf)).await?;

    Ok(ws_stream)
}

//A bit overengineered for a single certificate, but it should be kept in case more certificates are added
fn get_certs() -> Result<Vec<Certificate>> {
    let path = "../server/cert/rootCA.crt";
    Ok(vec![Certificate::from_pem(&fs::read(path)?)?])
}

async fn set_timeout<F, Fut>(delay_ms: u64, callback: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()> + 'static,
{
    // Wait for the specified duration
    sleep(Duration::from_millis(delay_ms)).await;

    // Execute the callback function
    callback().await;
}

#[cfg(test)]
mod websocket_tests {
    use super::*;
    use std::{
        env,
        thread::sleep,
        time::{Duration, SystemTime},
    };

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_websocket() {
        dotenv::dotenv().ok();
        let mut handler = WebsocketHandler::try_new(
            Some(KeepAliveOptions {
                path: Some("/v1/keepalive".to_string()),
            }),
            env::var("SERVER_ADDRESS").unwrap(),
            env::var("HTTPS_PORT").unwrap(),
            env::var("TEST_USERNAME").unwrap(),
            env::var("TEST_PASSWORD").unwrap(),
        )
        .await
        .unwrap();

        handler
            .send_text_no_response_expected(format!(
                "Hello World! {}",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ))
            .await
            .unwrap();

        handler
            .send_text_no_response_expected("Hello, world!".to_string())
            .await
            .unwrap();

        let res = handler
            .send_request(SendRequestOptions {
                verb: "GET".to_owned(),
                path: "/".to_owned(),
                headers: None,
                body: None,
                timeout: None,
            })
            .await
            .unwrap();

        println!("Response status: {:?}", res.status.unwrap());

        sleep(Duration::from_millis(100));

        while let Ok(msg) = handler.text_channel.lock().await.try_recv() {
            match msg {
                Message::Text(msg) => println!("{}", msg),
                Message::Ping(payload) => {
                    println!(
                        "Ping: {}",
                        payload.iter().map(|x| x.to_string()).collect::<String>()
                    )
                }
                Message::Pong(payload) => {
                    println!(
                        "Pong: {}",
                        payload.iter().map(|x| x.to_string()).collect::<String>()
                    )
                }
                _ => println!("Non-text message"),
            }
        }

        println!("Testing keepalive");
        sleep(Duration::from_millis(5000));

        handler.close(1000, "Normal closure".into()).await.unwrap();

        assert!(true)
    }
}
