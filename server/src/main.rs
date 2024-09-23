use axum::routing::put;
use axum::{Json, Router};

use common::signal_protobuf::Envelope;

/// Hello, world!
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/messages", put(handle_message));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:50051").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_message(Json(payload): Json<Envelope>) {
    println!("Received message: {:?}", payload);
}
