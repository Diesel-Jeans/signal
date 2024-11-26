use std::error::Error;

use client::Client;
use server::SignalBackend;
use storage::device::Device;

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_manager;
mod persistent_receiver;
mod server;
mod socket_manager;
mod storage;
#[cfg(test)]
mod test_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    Client::<Device, SignalBackend>::register("my_device", "b".into()).await?;

    Ok(())
}
