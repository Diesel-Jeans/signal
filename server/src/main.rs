#![allow(unused)]
use tracing_subscriber;
use tracing_appender;
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
mod server;

#[tokio::main]
pub async fn main() {
    let file_appender = tracing_appender::rolling::hourly("logs", format!("{}.log", Local::now().to_string()));
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .log_internal_errors(true)
        .with_max_level(tracing::Level::DEBUG)
        .with_line_number(true)
        .with_writer(non_blocking)
        .init();
    server::start_server().await.unwrap();
}
