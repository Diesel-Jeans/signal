use libsignal_protocol::*;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::contact::Contact;
use crate::contact::Device;

use crate::client_common::create_pre_key_bundle;

enum ProtocolKey {
    SignedPreKey,
    KyberPreKey,
    OneTimePreKey,
}

pub struct Client<R: Rng + CryptoRng> {
    pub info: Contact,
    device: Device,

    contacts: HashMap<String, Contact>,
    store: InMemSignalProtocolStore,
    rng: R,
}

impl<R: Rng + CryptoRng> Client<R> {
    pub fn new(uuid: String, device: Device, store: InMemSignalProtocolStore, rng: R) -> Client<R> {
        Self {
            info: Contact::new(uuid),
            device: device,
            contacts: HashMap::new(),
            store: store,
            rng: rng,
        }
    }

    pub async fn create_bundle(&mut self) -> Result<PreKeyBundle, SignalProtocolError> {
        create_pre_key_bundle(&mut self.store, &mut self.rng).await
    }

    pub async fn verify_contact_devices(
        &mut self,
        contact: &mut Contact,
    ){
        let mut invalid_devices: Vec<u32> = Vec::new();

        for device in &mut *contact {
            let bundle = match &device.bundle {
                Some(x) => x,
                None => continue,
            };

            let _ = match process_prekey_bundle(
                &device.address,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                bundle,
                SystemTime::now(),
                &mut self.rng,
            )
            .await
            {
                Ok(_) => continue,
                Err(_) => {
                    device.bundle = None;
                    invalid_devices.push(device.address.device_id().into());
                }
            };
        }

        for device_id in invalid_devices{
            contact.remove_device(&device_id);
        }
    }

    pub async fn encrypt(mut self, to: &Contact, msg: &str) -> Vec<CiphertextMessage> {
        let mut msgs: Vec<CiphertextMessage> = Vec::new();
        for device in to {
            match device.bundle {
                Some(_) => match message_encrypt(
                    msg.as_bytes(),
                    &device.address,
                    &mut self.store.session_store,
                    &mut self.store.identity_store,
                    SystemTime::now(),
                )
                .await
                {
                    Ok(x) => msgs.push(x),
                    Err(_) => continue,
                },
                None => continue,
            }
        }
        msgs
    }

    pub async fn decrypt(
        &mut self,
        from_device: &Device,
        msg: &CiphertextMessage,
    ) -> Result<Vec<u8>, SignalProtocolError> {
        message_decrypt(
            msg,
            &from_device.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut self.rng,
        )
        .await
    }

    pub async fn add_contact(&mut self, name: &String, contact: &mut Contact) -> Result<(), String>{
        if self.contacts.contains_key(name) {
            return Err(format!("Contact with name '{name}' already exists!"));
        }

        self.verify_contact_devices(contact).await;

        self.contacts.insert(name.to_string(), contact.clone());
        Ok(())
    }

    pub fn get_contact(&mut self, name: &String) -> Result<&mut Contact, String>{
        self.contacts
            .get_mut(name)
            .ok_or(format!("No contact with name '{name}' exists!"))
    }

    pub fn remove_contact(&mut self, name: &String) -> Result<Contact, String>{
        self.contacts
            .remove(name)
            .ok_or(format!("No contact with name '{name}' exists!"))
    }

    pub fn contains_contact(&self, name: &String) -> bool{
        self.contacts.contains_key(name)
    }
    fn benis(){
        print!("b")
    }

}

#[cfg(test)]
mod test {
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use uuid::Uuid;
    use crate::client::Client;
    use crate::client::Contact;
    use crate::contact::Device;


    fn client(reg: u32) -> Client<OsRng>{
        let uuid = Uuid::new_v4().to_string();
        let device = Device::new(uuid.clone(), 0, None);
        let pair =  KeyPair::generate(&mut OsRng).into();
        let store = InMemSignalProtocolStore::new(pair, reg).unwrap();
       
        Client::new(uuid, device, store, OsRng)
    }

    #[tokio::test]
    async fn test_contact(){
        let mut client = client(0);
        let bob = "Bob".to_string();
        let mut contact = Contact::new(Uuid::new_v4().to_string());
        client.add_contact(&bob, &mut contact).await.unwrap();
        
        assert!(client.contains_contact(&bob), "client did not contain Bob contact!");

        let ok = client.remove_contact(&bob).is_ok();
        assert!(ok && !client.contains_contact(&bob))
    }

    async fn test_encryption(){
        let mut alice = client(0);
        let mut bob = client(1);

        bob.device.bundle = Some(bob.create_bundle().await.expect("error"));
        
        let mut alice_contact = alice.info.clone();
        let mut bob_contact = bob.info.clone();


    }

}
