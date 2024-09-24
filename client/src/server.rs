use libsignal_protocol::*;
use common::signal_protobuf::Envelope;
use crate::contact::{Contact, Device};

struct ServerAPI {
    // data
}

pub trait Server {
    async fn publish_bundle(
        &self,
        registration_id: u32,
        bundle: &PreKeyBundle,
    ) -> Result<(), String>; // should take keys as parameter or struct
    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String>;
    async fn register_client(&self, client_info: &Contact) -> Result<Ok(), Err()>;
    async fn register_device(&self, device: &Device) -> Result<Ok(), Err()>;
    async fn send_msg(&self, envelope: Envelope) -> Result<Ok(), Err()>;
    async fn update_client(&self, new_client: &Contact) -> Result<Ok(), Err()>;
    async fn delete_client(&self, contact: &Contact) -> Result<Ok(), Err()>;
    async fn delete_device(&self, device: &Device) -> Result<Ok(), Err()>;
    async fn connect() -> Result<dyn Server, Err()>;
}

impl Server for ServerAPI {
    async fn publish_bundle(&self, registration_id: u32, bundle: &PreKeyBundle) -> Result<(), String> {
        todo!()
    }

    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String> {
        todo!()
    }

    async fn register_client(&self, client_info: &Contact) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn register_device(&self, device: &Device) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn send_msg(&self, envelope: Envelope) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn update_client(&self, new_client: &Contact) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn delete_client(&self, contact: &Contact) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn delete_device(&self, device: &Device) -> Result<Ok(), Err()> {
        todo!()
    }

    async fn connect() -> Result<dyn Server, Err()> {
        todo!()
    }
}
