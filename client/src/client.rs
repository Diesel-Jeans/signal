
use libsignal_protocol::*;
use std::time::SystemTime;
use rand::{CryptoRng, Rng};

use crate::contact::Contact;

use crate::client_common::create_pre_key_bundle;

pub struct Client <R: Rng + CryptoRng>{
    device_id: DeviceId,
    pub uuid: String,
    e164: String, // phone number
    idkey_pair: IdentityKeyPair,
    store: InMemSignalProtocolStore,
    rng: R,
    //sender_cert: Option<SenderCertificate>
}

impl <R: Rng + CryptoRng> Client<R>{
    pub fn new(id: u32, uuid: String, e164: String, pair: IdentityKeyPair, store: InMemSignalProtocolStore, rng: R) -> Client<R> {
        Self {
            device_id: id.into(),
            uuid: uuid,
            e164: e164,
            idkey_pair: pair,
            store: store,
            rng: rng,
            //sender_cert: None
        }
    }

    pub async fn create_bundle(&mut self) -> Result<PreKeyBundle, SignalProtocolError>{
        create_pre_key_bundle(&mut self.store, &mut self.rng).await
    }

    pub async fn set_contact_bundle(
        &mut self, 
        contact: &mut Contact, 
        bundle: PreKeyBundle) -> Result<(), SignalProtocolError>{
        let res = process_prekey_bundle(
            &contact.address, 
            &mut self.store.session_store,
            &mut self.store.identity_store, 
            &bundle, 
            SystemTime::now(), 
            &mut self.rng
        ).await;

        match res {
            Ok(_) => {
                contact.bundle = Some(bundle);
                Ok(())
            },
            Err(x) => Err(x)
        }
    }

    pub async fn encrypt(mut self, to: &Contact, msg: &str) -> Result<CiphertextMessage, SignalProtocolError>{
        message_encrypt(
            msg.as_bytes(),
            &to.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
        )
        .await
    }

    pub async fn decrypt(mut self, from: Contact, msg: &CiphertextMessage) -> Result<Vec<u8>, SignalProtocolError>{
        message_decrypt(
            msg,
            &from.address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut self.rng,
        )
        .await
    }

    /*pub async fn fetch_sender_certificate(&mut self) -> Result<(), Box<dyn std::error::Error>>{
        //TODO: THIS IS TEMPORARY THIS SHOULD FETCH FROM SERVER
        let trust_root = KeyPair::generate(&mut self.rng);
        let server_key = KeyPair::generate(&mut self.rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut self.rng)?;

        self.sender_cert = Some(SenderCertificate::new(
            self.uuid.clone(),
            Some(self.e164.clone()),
            *self.store.get_identity_key_pair().await?.public_key(),
            self.device_id,
            Timestamp::from_epoch_millis(2231735116),
            server_cert,
            &server_key.private_key,
            &mut self.rng,
        )?);
        Ok(())
    }

    pub async fn ss_encrypt(&mut self, contact: Contact, msg: &str) -> error::Result<Vec<u8>>{
        //TODO: THIS SHOULD BE HANDLED BETTER
        
        let cert = match &self.sender_cert {
            None => {
                self.fetch_sender_certificate().await.expect("Please Fix this");
                self.sender_cert.as_mut().unwrap()
            },
            Some(c) => c
        };

        sealed_sender_encrypt(
            &contact.address,
            cert,
            &msg.to_string().into_bytes(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut self.rng,
        ).await    
    }

    pub async fn ss_decrypt(&mut self, msg: &str) -> error::Result<SealedSenderDecryptionResult>{
        //TODO: FIX THIS
        let trust_root = KeyPair::generate(&mut self.rng); // this will fail
        
        sealed_sender_decrypt(
            &msg.to_string().as_bytes(),
            &trust_root.public_key,
            Timestamp::from_epoch_millis(2231735116), //TODO: this should be fixed
            Some(self.e164.clone()),
            self.uuid.clone(),
            self.device_id,
            &mut self.store.identity_store,
            &mut self.store.session_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
        ).await
    }*/

}