#![allow(unused)]
mod api_error;
pub mod database;
pub mod in_memory_db;
mod postgres;
mod server;
mod account;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
