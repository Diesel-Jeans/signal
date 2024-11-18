use std::error::Error;

use contact_manager::Contact;

use crate::client::Client;

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_management;
mod server;
mod storage;
mod websockets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv()?;

    let client = Client::login().await;
    let mut client = match client {
        Ok(c) => c,
        Err(_) => Client::register("name", "this is NOT my phone number".to_string()).await?,
    };
    println!("Logged in, sending message to Alice");

    let alice = Contact::new(uuid::uuid!("0d76041e-54ce-4cea-a128-ebfa32171c29").to_string());

    client.send_message("Hello, World!", &alice).await;

    Ok(())
}
