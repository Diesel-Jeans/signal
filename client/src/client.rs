use anyhow::Result;
use libsignal_protocol::*;
use rand::{CryptoRng, Rng};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::contact::Contact;
use crate::contact::Device;

use crate::client_common::create_pre_key_bundle;

pub enum PreKey {
    Signed,
    Kyber,
    OneTime,
}

pub enum KeyType {
    KemKey(kem::KeyPair),
    KeyPair(KeyPair),
}

pub struct Client<R: Rng + CryptoRng> {
    pub info: Contact,
    device: Device,

    contacts: HashMap<String, Contact>,
    store: InMemSignalProtocolStore,
    rng: R,
    one_time_key_incrementer: u32,
    signed_pre_key_incrementer: u32,
    kyper_pre_key_incrementer: u32,
}

impl<R: Rng + CryptoRng> Client<R> {
    pub fn new(uuid: String, device: Device, store: InMemSignalProtocolStore, rng: R) -> Client<R> {
        Self {
            info: Contact::new(uuid),
            device: device,
            contacts: HashMap::new(),
            store: store,
            rng: rng,
            one_time_key_incrementer: 0,
            signed_pre_key_incrementer: 0,
            kyper_pre_key_incrementer: 0,
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

    pub async fn generate_key(&mut self, key_type: PreKey) -> Result<(KeyType, Option<Box<[u8]>>)> {
        match key_type {
            PreKey::Kyber => {
                let kyper_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);
                let signature = self
                    .store
                    .get_identity_key_pair()
                    .await?
                    .private_key()
                    .calculate_signature(
                        &kyper_pre_key_pair.public_key.serialize(),
                        &mut self.rng,
                    )?;
                let id = self.get_new_key_id(key_type);
                self.store
                    .save_kyber_pre_key(
                        id.into(),
                        &KyberPreKeyRecord::new(
                            id.into(),
                            Timestamp::from_epoch_millis(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                                    .try_into()?,
                            ),
                            &kyper_pre_key_pair,
                            &signature,
                        ),
                    )
                    .await?;
                Ok((KeyType::KemKey(kyper_pre_key_pair), Some(signature)))
            }
            PreKey::Signed => {
                let signed_pre_key_pair = KeyPair::generate(&mut self.rng);
                let signature = self
                    .store
                    .get_identity_key_pair()
                    .await?
                    .private_key()
                    .calculate_signature(
                        &signed_pre_key_pair.public_key.serialize(),
                        &mut self.rng,
                    )?;
                let id = self.get_new_key_id(key_type);
                self.store
                    .save_signed_pre_key(
                        id.into(),
                        &SignedPreKeyRecord::new(
                            id.into(),
                            Timestamp::from_epoch_millis(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                                    .try_into()?,
                            ),
                            &signed_pre_key_pair,
                            &signature,
                        ),
                    )
                    .await?;
                Ok((KeyType::KeyPair(signed_pre_key_pair), Some(signature)))
            }
            PreKey::OneTime => {
                let onetime_pre_key_pair = KeyPair::generate(&mut self.rng);
                let id = self.get_new_key_id(key_type);
                self.store
                    .save_pre_key(
                        id.into(),
                        &PreKeyRecord::new(id.into(), &onetime_pre_key_pair),
                    )
                    .await?;
                Ok((KeyType::KeyPair(onetime_pre_key_pair), None))
            }
        }
    }

    fn get_new_key_id(&mut self, key_type: PreKey) -> u32 {
        let id = match key_type {
            PreKey::Kyber => {
                self.kyper_pre_key_incrementer += 1;
                self.kyper_pre_key_incrementer
            }
            PreKey::Signed => {
                self.signed_pre_key_incrementer += 1;
                self.signed_pre_key_incrementer
            }
            PreKey::OneTime => {
                self.one_time_key_incrementer += 1;
                self.one_time_key_incrementer
            }
        };
        id - 1
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