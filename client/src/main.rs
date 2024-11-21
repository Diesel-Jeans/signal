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
#[cfg(test)]
mod test;
mod websockets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::from_filename("client/.env")?;
    let mut client = Client::register("name", "a".to_string()).await.unwrap();

    println!("Logged in, sending message to myself");

    let me = Contact::new(client.aci().service_id_string());

    client.send_message("Hello, World!", &me).await.unwrap();
    println!("Sent message");

    println!("{}", client.receive_message().await.unwrap());

    Ok(())
}
