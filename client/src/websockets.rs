use crate::encryption::{decrypt, encrypt};
use anyhow::Result;
use common::signal_protobuf::{
    WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt, TryStream, TryStreamExt};
use libsignal_protocol::InMemSignalProtocolStore;
use native_tls::{Certificate, TlsConnector as NativeTlsConnector, TlsStream};
use prost::encoding::hash_map::encode;
use prost::Message as ProstMessage;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::env;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::net::ToSocketAddrs;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime};
use surf::http::headers::ToHeaderValues;
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, Unconstrained};
use tokio::*;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::WebSocket;
use tokio_tungstenite::*;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

struct StreamHandler {
    pub stream: WebSocketStream<tokio_native_tls::TlsStream<TcpStream>>,
}

impl StreamHandler {
    async fn try_new() -> Result<StreamHandler> {
        let stream = open_ws_connection_to_server_as_client().await?;
        Ok(StreamHandler { stream })
    }
}

pub(crate) struct WebsocketHandler {
    pub(crate) socket: Arc<Mutex<StreamHandler>>,
}
impl WebsocketHandler {
    pub async fn try_new() -> Result<WebsocketHandler> {
        Ok(WebsocketHandler {
            socket: Arc::new(Mutex::new(StreamHandler::try_new().await?)),
        })
    }

    async fn send_message(self, msg: Message) -> Result<()> {
        let mut guard = self.socket.try_lock()?;
        guard.stream.send(msg).await?;
        Ok(())
    }
}

pub(crate) async fn send_ws_message(
    mut ws_stream: WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    msg: String,
    id: u32,
    recipient: String,
) -> Result<()> {
    let wsrm = WebSocketRequestMessage {
        verb: Some("PUT".to_owned()),
        path: Some(("/v1/messages/".to_owned() + &recipient).to_owned()),
        body: Some(msg.into_bytes()),
        headers: vec!["".to_string()],
        id: Some(id.into()),
    };
    ws_stream.send(Message::Binary(wsrm.encode_to_vec()))?;

    Ok(())
}

pub(crate) async fn open_ws_connection_to_server_as_client() -> Result<WebSocketStream<tokio_native_tls::TlsStream<TcpStream>>> {
    let address = env::var("SERVER_ADDRESS")?;
    let https_port = env::var("HTTPS_PORT")?;
    let ws_url =
        ("wss://".to_string() + address.as_str() + ":" + https_port.as_str() + "/v1/websocket")
            .into_client_request()?;

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

    let (ws_stream, _) = client_async_with_config(
        ws_url,
        tls_stream,
        Some(conf),
        //Some(tokio_tungstenite::Connector::NativeTls(connector)),
    )
        .await?;

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

fn get_handle_for_ws_listener(
    mut sock: Arc<Mutex<StreamHandler>>,
) -> (
    // Unconstrained<impl Future<Output=()> + Sized>,
    std::thread::JoinHandle<()>,
    mpsc::Receiver<Message>,
) {
    println!("Entered handle function");
    let (mut tx, mut rx) = mpsc::channel::<Message>();
    let handle = Handle::current();
    let mtx = tx.clone();

    let hand = std::thread::spawn(move || {
        handle.block_on(async move {
            // println!("Entered async handler");
            // Lock the socket handler asynchronously
            while let Ok(msg) = sock.lock().await.stream.next().await.unwrap() {
                match msg {
                    Message::Close(m) => {
                        break;
                    }
                    _ => {
                        if let Err(e) = tx.send(msg) {
                            break;
                        }
                        std::thread::yield_now();
                    }
                }
            }
            std::thread::yield_now();
        })
    });
    (hand, rx)
}

#[cfg(test)]
mod tests {
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
        let handler = WebsocketHandler::try_new().await.unwrap();
        let hand = handler.socket.clone();

        // handler.send_message(Message::Text(format!(
        //     "Hello World! {}",
        //     SystemTime::now()
        //         .duration_since(std::time::UNIX_EPOCH)
        //         .unwrap()
        //         .as_secs()
        // )));

        handler
            .socket
            .try_lock()
            .unwrap()
            .stream
            .send(Message::Text(format!(
                "Hello World! {}",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )))
            .await
            .unwrap();
        handler
            .socket
            .try_lock()
            .unwrap()
            .stream
            .send(Message::Text("Hello, World!".into()))
            .await
            .unwrap();

        handler
            .socket
            .try_lock()
            .unwrap()
            .stream
            .send(Message::Ping(vec![1, 2, 3].into()))
            .await
            .unwrap();

        let (x, y) = get_handle_for_ws_listener(hand);

        sleep(Duration::from_millis(100));

        while let Ok(msg) = y.try_recv() {
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
