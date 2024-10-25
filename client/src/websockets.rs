use crate::encryption::{decrypt, encrypt};
use anyhow::Result;
use common::signal_protobuf::{
    WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
};
use futures_util::{SinkExt, StreamExt};
use libsignal_protocol::InMemSignalProtocolStore;
use native_tls::{Certificate, TlsConnector as NativeTlsConnector};
use prost;
use prost::encoding::hash_map::encode;
use prost::Message as ProstMessage;
use std::env;
use surf::http::headers::ToHeaderValues;
use tokio::net::TcpStream;
use tokio::*;
use tokio_native_tls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::WebSocket;
use tokio_tungstenite::*;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

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

pub(crate) async fn open_ws_connection_to_server_as_client() -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
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

fn get_certs() -> Result<Vec<Certificate>> {
    let rootca = include_str!("../../server/cert/rootCA.crt").to_string();
    let server = include_str!("../../server/cert/server.crt").to_string();

    Ok(vec![
        Certificate::from_pem(rootca.as_bytes())?,
        Certificate::from_pem(server.as_bytes())?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::ok;
    #[tokio::test]
    async fn test_websocket() {
        dotenv::dotenv().ok();
        open_ws_connection_to_server_as_client()
            .await
            .expect("Failed to connect to server");
        // Define the WebSocket server URL
        let mut ws_url = "wss://echo.websocket.org".into_client_request().unwrap();

        // Connect to the WebSocket server
        let (mut ws_stream, _) = tungstenite::connect(ws_url).expect("Failed to connect");

        println!("WebSocket connection established!");

        let fuck_rust = ws_stream.read();
        match fuck_rust {
            Ok(msg) => println!("Got message: {}", msg),
            Err(e) => println!("Got error: {:?}", e),
        }

        assert!(true)
    }
}
