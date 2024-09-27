mod client;
mod server;
mod encoder;
mod contact_manager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello World");
    Ok(())
}
