mod client;
mod contact_manager;
mod encryption;
mod server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello World");
    Ok(())
}
