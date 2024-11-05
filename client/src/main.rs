#![allow(unused)]
use std::error::Error;

use crate::client::Client;

mod client;
mod contact_manager;
mod encryption;
mod key_management;
mod server;
mod storage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv()?;
    let client = Client::register("this is my phone number".to_string()).await?;
    Ok(())
}
