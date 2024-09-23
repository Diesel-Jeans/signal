
use libsignal_protocol::*;

use crate::contact::Contact;

pub trait Server {
    async fn publish_bundle(&self, registration_id: u32, bundle: &PreKeyBundle) -> Result<(), String>; // should take keys as parameter or struct
    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String>;
    
}