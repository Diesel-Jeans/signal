
use libsignal_protocol::*;
use std::collections::HashMap;
use std::time::SystemTime;
use rand::{CryptoRng, Rng};

use crate::contact::Contact;
use crate::contact::Device;

use crate::client_common::create_pre_key_bundle;

enum ProtocolKey{
    SignedPreKey,
    KyberPreKey,
    OneTimePreKey,
}

pub struct Client <R: Rng + CryptoRng>{
    pub contact: Contact,
    store: InMemSignalProtocolStore,
    rng: R,
}

impl <R: Rng + CryptoRng> Client<R>{
    pub fn new(uuid: String, store: InMemSignalProtocolStore, rng: R) -> Client<R> {
        Self {
            contact: Contact::new(uuid),
            store: store,
            rng: rng,
        }
    }

    pub async fn create_bundle(&mut self) -> Result<PreKeyBundle, SignalProtocolError>{
        create_pre_key_bundle(&mut self.store, &mut self.rng).await
    }



    pub async fn verify_contact_devices(&mut self, contact: &mut Contact) -> Result<(), SignalProtocolError>{
        for device in contact {
            let bundle = match &device.bundle {
                Some(x) => x,
                None => continue
            };

            let _ = match process_prekey_bundle(
                &device.address, 
                &mut self.store.session_store,
                &mut self.store.identity_store, 
                bundle, 
                SystemTime::now(), 
                &mut self.rng
            ).await {
                Ok(_) => Ok::<(), SignalProtocolError>(()),
                Err(_) => {
                    device.bundle = None;
                    Ok(())
                }
            };
        }
        Ok(())
    }

    pub async fn encrypt(mut self, to: &Contact, msg: &str) ->Vec<CiphertextMessage>{
        let mut msgs: Vec<CiphertextMessage> = Vec::new();
        for device in to{
            match message_encrypt(
                msg.as_bytes(),
                &device.address,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                SystemTime::now(),
            )
            .await {
                Ok(x) => {msgs.push(x)},
                Err(_) => continue
            }
        }
        msgs
    }

    pub async fn decrypt(mut self, from_device: &Device, msg: &CiphertextMessage) -> Result<Vec<u8>, SignalProtocolError>{
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
}