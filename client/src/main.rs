use core::panic;
use std::error::Error;

use client::Client;
use dotenv::dotenv;
use libsignal_core::{Aci, ServiceId};
use storage::device::Device;
use test_utils::user::{new_aci, new_uuid};

mod client;
mod contact_manager;
mod encryption;
mod errors;
mod key_manager;
mod persistent_receiver;
mod server;
mod socket_manager;
mod storage;
//#[cfg(test)]
mod test_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv()?;
    let db_url =
        "sqlite:///home/darkros/Documents/9_semester/Project/signal/client/client_db/charlie.db";
    let alice_service_id: ServiceId =
        Aci::parse_from_service_id_string("d4239e05-4c93-48ca-a3bf-d847634f4be9")
            .unwrap()
            .into();
    let bob_service_id: ServiceId =
        Aci::parse_from_service_id_string("b1191416-0905-427e-b28e-5f25748ed994")
            .unwrap()
            .into();

    //let mut charlie = Client::<Device>::register("my_device", "b".into(), db_url).await?;
    let mut charlie = Client::<Device>::login(db_url).await?;
    charlie
        .add_contact("alice", alice_service_id)
        .await
        .unwrap();
    charlie.add_contact("bob", bob_service_id).await.unwrap();

    Ok(())
}
