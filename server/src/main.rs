#![allow(unused)]
mod account;
mod error;
pub mod database;
pub mod in_memory_db;
pub mod managers;
mod postgres;
mod server;
mod socket;
mod connection;
mod query;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
