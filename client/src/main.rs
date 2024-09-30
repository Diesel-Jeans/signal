mod client;
mod server;
mod encryption;
mod contact_manager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello World");
    Ok(())
}
