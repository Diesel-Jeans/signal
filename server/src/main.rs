#![allow(unused)]
use chrono::prelude::*;
mod account;
mod account_authenticator;
pub mod database;
mod envelope;
mod error;
pub mod managers;
mod message_cache;
mod postgres;
mod query;
mod response;
mod server;
mod test_utils;
mod validators;

#[tokio::main]
pub async fn main() {
    //Starting logger
    tracing_subscriber::fmt()
        .log_internal_errors(true)
        .with_max_level(tracing::Level::DEBUG)
        .with_line_number(true)
        .init();
    server::start_server().await.unwrap();
}
