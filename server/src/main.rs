#![allow(unused)]
use tracing_subscriber;

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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter("my_app=debug,tower_http=debug")
        .init();
    server::start_server().await.unwrap();
}
