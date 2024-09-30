mod in_memory_db;
mod create_server;
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_server::start_signal_server().await
}

