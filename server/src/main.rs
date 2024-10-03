mod in_memory_db;

use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use crate::in_memory_db::InMemoryDB;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use common::signal_protobuf::Envelope;
use common::signal_protocol_messages::RegistrationRequest;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::spawn;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task;
use tungstenite::{accept, Message};

/// Hello, world!
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = ServerState::new();
    let app = Router::new()
        .route("/message/:address", put(handle_send_message))
        .route("/bundle/:address", post(handle_publish_bundle))
        .route("/bundle/:address", get(handle_fetch_bundle))
        .route("/client", post(handle_register_client))
        .route("/client", put(handle_update_client))
        .route("/client/:address", delete(handle_delete_client))
        .route("/device/:address", post(handle_register_device))
        .route("/device/:address", delete(handle_delete_device))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:12345").await?;
    receive_websocket().await;
    tokio::spawn(receive_websocket());
    tokio::spawn(async { axum::serve(listener, app).await.expect("server did not start"); println!("Server started")});
    Ok(())
}

async fn receive_websocket() {
    let addr = "127.0.0.1:8888";


    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    println!("Listening on: {}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(handle_connection(stream, addr));
    }

}

async fn handle_connection(stream: tokio::net::TcpStream, addr: SocketAddr) {
    println!("Incoming connection from {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");
    println!("WebSocket connection established: {}", addr);

    let (outgoing, incoming) = ws_stream.split();

    while let Some(message) = incoming.next().await {
        match message {
            Ok(msg) => {
                // Process the message (can be text, binary, etc.)
                println!("Received: {:?}", msg);
            }
            Err(e) => {
                println!("Error while reading message: {:?}", e);
                break; // Exit the loop on error
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ServerState {
    db: Arc<Mutex<InMemoryDB>>,
}

impl ServerState {
    fn new() -> ServerState {
        ServerState {
            db: Arc::new(Mutex::new(InMemoryDB::new())),
        }
    }
}

async fn handle_send_message(
    State(mut state): State<ServerState>,
    Path(address): Path<String>,
    Json(payload): Json<Envelope>,
) {
    println!("Received message: {:?}", payload);
    match state
        .db
        .lock()
        .expect("Should not fail :)")
        .mailbox
        .get_mut(&address)
    {
        Some(mailbox) => {
            mailbox.push(payload);
        }
        None => {
            // Mailbox did not exist - Error.
            println!("No such address: '{}'", address);
        }
    }
}

async fn handle_publish_bundle() {
    println!("Publish bundle");
}

async fn handle_fetch_bundle() {
    println!("Fetch bundle");
}

struct ErrorResponse {
    status_code: StatusCode,
    error: String,
    message: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status_code.as_u16())
            .body(Body::from(self.message))
            .expect("should be able to create response.")
            .into_response()
    }
}

#[axum::debug_handler]
async fn handle_register_client(
    State(mut state): State<ServerState>,
    Json(payload): Json<RegistrationRequest>,
) -> Result<(), ErrorResponse> {
    println!("Register client");
    if payload.aci == "Darkros1245" {
        return Err(ErrorResponse {
            status_code: StatusCode::BAD_REQUEST,
            error: String::from("Bad username"),
            message: String::from("This is a bad username, please choose another"),
        });
    }

    let mut db = state.db.lock().expect("Should not fail :)");
    // Check that client does not already exist.
    if db.user.contains(payload.aci.as_str()) {
        println!("User already registered: '{}'", payload.aci);
        return Err(ErrorResponse {
            status_code: StatusCode::CONFLICT,
            error: String::from("Username already taken"),
            message: String::from(
                "The username 'example' is already in use. Please choose a different username.",
            ),
        });
    }
    println!("{:?}", db.user);
    db.user.insert(payload.aci.clone());
    db.mailbox
        .insert(format!("{:?}{:?}", payload.aci.clone(), 0), Vec::new());
    println!("{:?}", db.user);

    Ok(())
}

async fn handle_register_device() {
    println!("Register device");
}

async fn handle_update_client() {
    println!("Update client");
}

async fn handle_delete_client() {
    println!("Update");
}

async fn handle_delete_device() {
    println!("Delete device");
}
