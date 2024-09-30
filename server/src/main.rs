mod create_server;
mod in_memory_db;
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_server::start_signal_server().await
}
