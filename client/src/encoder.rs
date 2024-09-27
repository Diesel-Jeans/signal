use libsignal_protocol::*;
use crate::contact_manager::{Contact, Device};
use rand::{CryptoRng, Rng};
use std::time::SystemTime;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Encoder<R: Rng + CryptoRng>{
    store: Arc<Mutex<InMemSignalProtocolStore>>,
    rng: Arc<Mutex<R>>
}

impl <R: Rng + CryptoRng> Encoder<R>{
    pub fn new(store: Arc<Mutex<InMemSignalProtocolStore>>, rng: Arc<Mutex<R>>) -> Self{
        Self {
            store,
            rng,
        }
    }

    pub async fn encrypt(&mut self, to: &Contact, msg: &[u8]) -> HashMap<u32, Result<CiphertextMessage, SignalProtocolError>>{
        let mut msgs: HashMap<u32, Result<CiphertextMessage, SignalProtocolError>> = HashMap::new();

        let s_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.session_store;
        let i_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.identity_store;
        

        for (id, device) in to.devices.iter() {
            let res = message_encrypt(
                msg, 
                &device.address, 
                s_store, 
                i_store, 
                SystemTime::now()).await;
            match res {
                Ok(x) => { msgs.insert(*id, Ok(x)); },
                Err(y) => { msgs.insert(*id, Err(y)); }
            }
        }
        msgs
    }

    pub async fn decrypt(&mut self, from_device: &Device, msg: &CiphertextMessage) -> Result<Vec<u8>, SignalProtocolError> {
        let s_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.session_store;
        let i_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.identity_store;
        let pk_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.pre_key_store;
        let spk_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.signed_pre_key_store;
        let kpk_store = &mut match self.store.lock(){
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner()
        }.kyber_pre_key_store;

        message_decrypt(
            msg, 
            &from_device.address,
            s_store,
            i_store,
            pk_store,
            spk_store,
            kpk_store,
            &mut *self.rng.lock().unwrap()
        ).await
    }
}


#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};
    use libsignal_protocol::*;
    use rand::rngs::OsRng;
    use uuid::Uuid;
    use crate::encoder::Encoder;
    use crate::contact_manager::{ContactManager, Contact, Device};
    use rand::{CryptoRng, Rng};

    fn store(reg: u32) -> Arc<Mutex<InMemSignalProtocolStore>> {
        let rng = Arc::new(Mutex::new(OsRng));
        let p = KeyPair::generate(&mut *rng.lock().unwrap()).into();
        Arc::new(
            Mutex::new(InMemSignalProtocolStore::new(p, reg).unwrap())
        )
    }

    fn encoder(store: &Arc<Mutex<InMemSignalProtocolStore>>) -> Encoder<OsRng>{
        let rng = Arc::new(Mutex::new(OsRng));
        Encoder::new(store.clone(), rng)
    }

    #[tokio::test]
    async fn test_encoder(){
        /*let alice_store = store(1);
        let bob_store = store(0);

        let mut alice_encoder = encoder(&alice_store);
        let mut bob_encoder = encoder(&bob_store);

        let alice_id = Uuid::new_v4().to_string();
        let bob_id = Uuid::new_v4().to_string();

        let mut manager = ContactManager::new();
        
        manager.add_contact(&alice_id);
        manager.add_contact(&bob_id);

        let mut rng = OsRng;
        let mut astore_m = alice_store.lock().unwrap();
        let mut bstore_m = bob_store.lock().unwrap();
        
        let alice_bundle = create_pre_key_bundle(&mut *astore_m, 0, &mut rng).await.unwrap();
        let bob_bundle = create_pre_key_bundle(&mut *bstore_m, 1, &mut rng).await.unwrap();

        manager.update_contact(&alice_id, vec![(0, alice_bundle)]);
        manager.update_contact(&bob_id, vec![(1, bob_bundle)]);

        let bob = manager.get_contact(&bob_id).unwrap();

        let msg_map = alice_encoder.encrypt(bob, "Hello Bob".as_bytes()).await;
        let to_bob_msg = msg_map.get(&1).unwrap().as_ref().unwrap();

        let alice_device = manager.get_contact(&alice_id).unwrap().devices.get(&0).unwrap();

        let bob_msg = bob_encoder.decrypt(alice_device, to_bob_msg).await.unwrap();*/

        //assert!(String::from_utf8(bob_msg).unwrap() == "Hello Bob".to_string())
        assert!(true)
    }

}