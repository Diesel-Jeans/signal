mod create_server;
mod in_memory_db;
mod server;

#[tokio::main]
pub async fn main() {
    server::start_server().await.unwrap();
}
