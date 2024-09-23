
use std::collections::HashMap;
use std::cell::RefCell;

use libsignal_protocol::*;

use crate::contact::Contact;

pub trait Server {
    async fn publish_bundle(&self, uuid: String, bundle: &PreKeyBundle) -> Result<(), String>;
    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String>;
}


pub struct MockServer {
    bundles: RefCell<HashMap<String, PreKeyBundle>>
}

impl MockServer {
    pub fn new() -> Self{
        Self {
            bundles: RefCell::new(HashMap::new())
        }
    }
}

impl Server for MockServer {
    async fn fetch_bundle(&self, contact: &Contact) -> Result<PreKeyBundle, String> {
        match self.bundles.borrow().get(&contact.uuid) {
            None => Err("UUID is not in bundles!".to_string()),
            Some(x) => Ok(x.clone())
        }
    }

    async fn publish_bundle(&self, uuid: String, bundle: &PreKeyBundle) -> Result<(), String>{
        let mut bundles = self.bundles.borrow_mut();
        if bundles.contains_key(&uuid){
            Err("Already published".to_string())
        } else {
            bundles.insert(uuid, bundle.clone());
            Ok(())
        }
    }
}





//server stuff
/* this is for sealed sender 
let trust_root = KeyPair::generate(&mut rng);
let server_key = KeyPair::generate(&mut rng);

let server_cert =
ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;
let expires = Timestamp::from_epoch_millis(2231735116); //2040

*/