#![allow(unused)]
mod account;
mod account_authenticator;
pub mod database;
mod error;
pub mod in_memory_db;
pub mod managers;
mod message_cache;
mod postgres;
mod query;
mod server;
mod envelope;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
