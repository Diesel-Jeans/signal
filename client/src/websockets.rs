use crate::encryption::{decrypt, encrypt};
use anyhow::Result;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use common::signal_protobuf::{
    WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{FutureExt, SinkExt, StreamExt, TryStream, TryStreamExt};
use libsignal_protocol::InMemSignalProtocolStore;
use native_tls::{Certificate, TlsConnector as NativeTlsConnector, TlsStream};
use prost::encoding::hash_map::encode;
use prost::Message as ProstMessage;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::collections::HashMap;
use std::env;
use std::fmt::{Display, Formatter};
use std::future::{Future, IntoFuture};
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::pin::Pin;
use std::process::Output;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use surf::http::headers::ToHeaderValues;
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::{AbortHandle, JoinHandle, Unconstrained};
use tokio::time::sleep;
use tokio::*;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{frame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{http, WebSocket};
use tokio_tungstenite::*;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

//Constants used by Signal, and therefore also used in our project
const SECOND: u32 = 1000;
const MINUTE: u32 = SECOND * 60;
const HOUR: u32 = MINUTE * 60;
const DAY: u32 = HOUR * 24;
const WEEK: u32 = DAY * 7;
const MONTH: u32 = DAY * 30;
// 30 seconds + 5 seconds for closing the socket above.
const KEEPALIVE_INTERVAL_MS: u32 = 30 * SECOND;

// If the machine was in suspended mode for more than 5 minutes - trigger
// immediate disconnect.
const STALE_THRESHOLD_MS: u32 = 5 * MINUTE;

// If we don't receive a response to keepalive request within 30 seconds -
// close the socket.
const KEEPALIVE_TIMEOUT_MS: u32 = 30 * SECOND;

struct StreamHandler {
    pub stream: WebSocketStream<tokio_native_tls::TlsStream<TcpStream>>,
}

impl StreamHandler {
    async fn try_new() -> Result<StreamHandler> {
        let stream = open_ws_connection_to_server_as_client().await?;
        Ok(StreamHandler { stream })
    }
}

type BoxedFuture = Pin<Box<dyn Future<Output=()> + Send>>;

//Rust can suck my fucking dick. Everything must be wrapped in an Arc because fuck you that's why.
#[derive(Clone)]
pub(crate) struct WebsocketHandler {
    pub(crate) socket: Arc<Mutex<StreamHandler>>,
    handle: Arc<thread::JoinHandle<()>>,
    rec_channel: Arc<mpsc::Receiver<Message>>,
    outgoing_id: u32,
    outgoing_map: Arc<Mutex<HashMap<u32, AbortHandle>>>,
    incoming_response: Arc<Mutex<HashMap<u32, WebSocketResponseMessage>>>,
    keepalive_bool: bool,
}
impl WebsocketHandler {
    pub async fn try_new() -> Result<WebsocketHandler> {
        let socket = Arc::new(Mutex::new(StreamHandler::try_new().await?));
        let (handle, rec_channel) = WebsocketHandler::get_handle_for_ws_listener(socket.clone());

        Ok(WebsocketHandler {
            socket,
            handle: Arc::new(handle),
            rec_channel: Arc::new(rec_channel),
            outgoing_id: 0,
            outgoing_map: Arc::new(Mutex::new(HashMap::new())),
            keepalive_bool: true,
            incoming_response: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn get_handle_for_ws_listener(
        mut sock: Arc<Mutex<StreamHandler>>,
    ) -> (std::thread::JoinHandle<()>, mpsc::Receiver<Message>) {
        let (mut tx, mut rx) = mpsc::channel::<Message>();
        let handle = Handle::current();
        let mtx = tx.clone();

        let hand = std::thread::spawn(move || {
            handle.block_on(async move {
                while let Some(Ok(msg)) = sock.lock().await.stream.next().await {
                    if let Err(e) = tx.send(msg) {
                        break;
                    }

                    std::thread::yield_now();
                }
            })
        });
        (hand, rx)
    }

    fn on_message(message: Message) {}

    //TODO: rename to send_request and ensure it only sends requests.
    async fn send_request(&mut self, msg: Message) -> Result<(WebSocketResponseMessage)> {
        let id = self.outgoing_id;
        let id_string = id.to_string();

        if self.outgoing_map.lock().await.contains_key(&id) {
            anyhow::bail!("Duplicate outgoing request")
        }

        self.outgoing_id = id + 1;

        //Make the protobuf message

        //Send the message over ws
        let mut guard = self.socket.lock().await.stream.send(msg).await?;

        let mut self_clone = self.clone();

        let promise = spawn(async move {
            if self_clone.keepalive_bool {
                set_timeout(KEEPALIVE_TIMEOUT_MS.into(), || async move {
                    self_clone.outgoing_map.lock().await.remove(&id);
                    self_clone
                        .socket
                        .lock()
                        .await
                        .stream
                        .send(Message::Close(Some(frame::CloseFrame {
                            code: 3001.into(),
                            reason: "Timed out".into(),
                        })))
                        .await;
                    //TODO: Kill the listener process
                    //anyhow::bail!("Timed out");
                    //Needed for the type inference, will never be reached
                }).await;
            }
        });
        //Add future to hashmap
        self.outgoing_map
            .lock()
            .await
            .insert(id, promise.abort_handle());

        promise.await;

        if let Some(incoming) = self.incoming_response.lock().await.get(&id) {
            Ok(incoming.clone())
        } else {
            anyhow::bail!("Incoming response missing")
        }
    }
}

pub struct KeepAliveOptions {
    path: Option<String>,
}

pub struct KeepAlive {
    ws: WebsocketHandler,
    receiver: Arc<Mutex<mpsc::Receiver<Message>>>,
    keepalive_options: KeepAliveOptions,
    path: String,
    keepalive_timer: Instant,
    last_alive_at: Instant,
}

impl KeepAlive {
    pub fn new() -> KeepAlive {
        todo!()
    }

    pub fn reset(mut self) {
        todo!()
    }

    //KeepAlive contains two send methods to replicate the functionality of Signal-Desktop to the best of my ability
    pub async fn super_send(mut self) {}

    pub fn send() {
        todo!()
    }
}

pub(crate) async fn open_ws_connection_to_server_as_client() -> Result<WebSocketStream<tokio_native_tls::TlsStream<TcpStream>>> {
    let address = env::var("SERVER_ADDRESS")?;
    let https_port = env::var("HTTPS_PORT")?;
    let username = env::var("TEST_USERNAME")?;
    let password = env::var("TEST_PASSWORD")?;

    //TODO: Fix authentication
    let auth_kv_pair = format!("{}:{}", username, password);
    let auth_value = engine::general_purpose::STANDARD.encode(&auth_kv_pair);

    let ws_url = format!(
        "wss://{}@{}:{}/v1/websocket",
        auth_kv_pair, address, https_port
    );
    let mut ws_req = ws_url.clone().into_client_request()?;
    let mhead = ws_req.headers_mut();
    mhead.insert(
        http::header::AUTHORIZATION,
        format!("Basic {}", auth_value).parse()?,
    );
    mhead.insert(
        http::header::SEC_WEBSOCKET_EXTENSIONS,
        "permessage-deflate; client_max_window_bits"
            .to_string()
            .parse()?,
    );
    mhead.insert(http::header::USER_AGENT, "Din mor".to_string().parse()?);

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
    let socket_address = format!("{}:{}", address.as_str(), https_port)
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

    println!("{}", ws_req.uri().to_string());

    let (ws_stream, _) = client_async_with_config(ws_req, tls_stream, Some(conf)).await?;

    println!("Reached ok");
    Ok(ws_stream)
}

//A bit overengineered for a single certificate, but it should be kept in case more certificates are added
fn get_certs() -> Result<Vec<Certificate>> {
    Ok(vec![Certificate::from_pem(
        include_str!("../../server/cert/rootCA.crt")
            .to_string()
            .as_bytes(),
    )?])
}

async fn set_timeout<F, Fut>(delay_ms: u64, callback: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output=()> + 'static,
{
    // Wait for the specified duration
    sleep(Duration::from_millis(delay_ms)).await;

    // Execute the callback function
    callback().await;
}

#[cfg(test)]
mod wstests {
    use super::*;
    use async_std::prelude::FutureExt as pFutureExt;
    use axum::response::IntoResponseParts;
    use futures_util::future::ok;
    use futures_util::stream::FusedStream;
    use futures_util::{FutureExt, StreamExt};
    use futures_util::{Sink, TryStream, TryStreamExt};
    use std::future::IntoFuture;
    use std::ops::Deref;
    use std::task::{Context, Poll};
    use std::thread;
    use std::thread::{sleep, yield_now};
    use std::time::{Duration, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_websocket() {
        dotenv::dotenv().ok();
        let mut handler = WebsocketHandler::try_new().await.unwrap();
        let hand = handler.socket.clone();

        handler
            .send_request(Message::Text(format!(
                "Hello World! {}",
                SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )))
            .await
            .unwrap();

        handler
            .send_request(Message::Text("Hello, world!".to_string()))
            .await
            .unwrap();

        handler
            .send_request(Message::Ping(vec![1, 2, 3].into()))
            .await
            .unwrap();

        sleep(Duration::from_millis(100));

        while let Ok(msg) = handler.rec_channel.try_recv() {
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
        assert!(true)
    }
}
