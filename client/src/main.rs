use std::error::Error;

use crate::client::Client;

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_manager;
mod server;
mod storage;
#[cfg(test)]
mod test_utils;
mod websockets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv()?;
    let client = Client::register("name", "this is NOT my phone number".to_string()).await?;
    //let client = Client::login().await?;
    Ok(())
}
