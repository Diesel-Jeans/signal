use libsignal_protocol::*;
use surf::Url;
use common::signal_protobuf::Envelope;
use crate::contact::{Contact, Device};

struct ServerAPI {
    // data
}

pub trait Server {
    async fn connect();
    async fn publish_bundle(
        &self,
        registration_id: u32,
        bundle: &PreKeyBundle,
    ) -> Result<(), String>; // should take keys as parameter or struct
    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String>;
    async fn register_client(&self, client_info: &Contact);
    async fn register_device(&self, device: &Device);
    async fn send_msg(&self, envelope: Envelope);
    async fn update_client(&self, new_client: &Contact);
    async fn delete_client(&self, contact: &Contact);
    async fn delete_device(&self, device: &Device);
}

impl Server for ServerAPI {
    async fn connect(){
        let server_url = Url::parse("ws://127.0.0.1:50051").unwrap();




    }
    async fn publish_bundle(&self, registration_id: u32, bundle: &PreKeyBundle) -> Result<(), String> {
        todo!()
    }

    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String> {
        todo!()
    }

    async fn register_client(&self, client_info: &Contact){
        todo!()
    }

    async fn register_device(&self, device: &Device) {
        todo!()
    }

    async fn send_msg(&self, envelope: Envelope){
        todo!()
    }

    async fn update_client(&self, new_client: &Contact) {
        todo!()
    }

    async fn delete_client(&self, contact: &Contact) {
        todo!()
    }

    async fn delete_device(&self, device: &Device) {
        todo!()
    }


}
