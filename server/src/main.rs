#![allow(unused)]
mod account;
mod connection;
pub mod database;
mod error;
pub mod in_memory_db;
pub mod managers;
mod postgres;
mod query;
mod server;
mod socket;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
