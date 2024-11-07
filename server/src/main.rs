#![allow(unused)]
mod account;
mod account_authenticator;
pub mod database;
mod envelope;
mod error;
pub mod managers;
mod message_cache;
mod postgres;
mod query;
mod server;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
