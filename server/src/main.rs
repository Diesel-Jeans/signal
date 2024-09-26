mod InMemoryDB;

use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use common::signal_protobuf::Envelope;

/// Hello, world!
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/messages", put(handle_send_message))
        .route("/bundle", post(handle_publish_bundle))
        .route("/bundle", get(handle_fetch_bundle))
        .route("/client", post(handle_register_client))
        .route("/client", put(handle_update_client))
        .route("/client", delete(handle_delete_client))
        .route("/device", post(handle_register_device))
        .route("/device", delete(handle_delete_device));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:12345").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_send_message(Json(payload): Json<Envelope>) {
    println!("Received message: {:?}", payload);
}

async fn handle_publish_bundle(){
    println!("Publish bundle");
}

async fn handle_fetch_bundle(){
    println!("Fetch bundle");
}

async fn handle_register_client(){
    println!("Register client");
}

async fn handle_register_device(){
    println!("Register device");
}

async fn handle_update_client(){
    println!("Update client");
}

async fn handle_delete_client(){
    println!("Update");
}

async fn handle_delete_device(){
    println!("Delete device");
}
