#![allow(unused)]
mod account;
mod api_error;
pub mod database;
pub mod in_memory_db;
pub mod managers;
mod postgres;
mod server;
mod socket;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
