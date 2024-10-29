use crate::encryption::{decrypt, encrypt};
use anyhow::Result;
use common::signal_protobuf::{
    WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use libsignal_protocol::InMemSignalProtocolStore;
use native_tls::{Certificate, TlsConnector as NativeTlsConnector};
use prost::encoding::hash_map::encode;
use prost::Message as ProstMessage;
use std::env;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::SystemTime;
use surf::http::headers::ToHeaderValues;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::Unconstrained;
use tokio::*;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::WebSocket;
use tokio_tungstenite::*;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;
// use ::extract::ws::WebSocket as AxWebSocket;

struct StreamHandler {
    pub stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl StreamHandler {
    async fn try_new() -> Result<StreamHandler> {
        // let (mut write, mut read) = open_ws_connection_to_server_as_client().await?.split();
        // Ok(StreamHandler { write, read })
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

pub(crate) async fn open_ws_connection_to_server_as_client(
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let address = env::var("SERVER_ADDRESS")?;
    let https_port = env::var("HTTPS_PORT")?;
    let ws_url =
        ("wss://".to_string() + address.as_str() + ":" + https_port.as_str() + "/v1/websocket")
            .into_client_request()?;

    let mut tls_connector = NativeTlsConnector::builder();
    // .danger_accept_invalid_certs(true) // Ignore invalid certificates
    for cert in get_certs()? {
        tls_connector.add_root_certificate(cert);
    }

    let connector = tls_connector.build()?;
    let tls_connector = Connector::NativeTls(connector);

    let (ws_stream, _) =
        connect_async_tls_with_config(ws_url, None, false, Some(tls_connector)).await?;

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
    Unconstrained<impl Future<Output = ()> + Sized>,
    mpsc::Receiver<Message>,
) {
    let (tx, rx) = mpsc::channel::<Message>();
    let hand = tokio::task::unconstrained(async move {
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
                }
            }
        }
        std::thread::yield_now();
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
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_websocket() {
        dotenv::dotenv().ok();
        let handler = WebsocketHandler::try_new().await.unwrap();
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

        let sock = handler.socket.clone();

        let (x, y) = get_handle_for_ws_listener(sock);

        //Sleeps to allow the server to respond
        sleep(Duration::from_millis(50));

        x.now_or_never();
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
