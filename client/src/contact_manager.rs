use libsignal_protocol::*;
use std::collections::HashMap;

pub struct Device {
    pub address: ProtocolAddress,
    pub bundle: PreKeyBundle,
}

impl Device {
    pub fn new(uuid: String, device_id: u32, bundle: PreKeyBundle) -> Device {
        Self {
            address: ProtocolAddress::new(uuid, device_id.into()),
            bundle,
        }
    }
}

pub struct Contact {
    pub uuid: String,
    pub devices: HashMap<u32, Device>,
}

impl Contact {
    pub fn new(uuid: String) -> Contact {
        Self {
            uuid,
            devices: HashMap::new(),
        }
    }
}

pub struct ContactManager {
    contacts: HashMap<String, Contact>,
}

impl ContactManager {
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
        }
    }

    pub fn add_contact(&mut self, uuid: &String) -> Result<(), String> {
        if self.contacts.contains_key(uuid) {
            return Err(format!("Contact with UUID '{uuid}' not found"));
        }
        self.contacts
            .insert(uuid.clone(), Contact::new(uuid.clone()));
        Ok(())
    }

    pub fn get_contact(&self, uuid: &String) -> Result<&Contact, String> {
        if let Some(contact) = self.contacts.get(uuid) {
            Ok(contact)
        } else {
            Err(format!("Contact with UUID '{uuid}' not found"))
        }
    }

    fn get_contact_mut(&mut self, uuid: &String) -> Result<&mut Contact, String> {
        if let Some(contact) = self.contacts.get_mut(uuid) {
            Ok(contact)
        } else {
            Err(format!("Contact with UUID '{uuid}' not found"))
        }
    }

    pub fn remove_contact(&mut self, uuid: &String) -> Result<(), String> {
        if !self.contacts.contains_key(uuid) {
            return Err(format!("Contact with UUID '{uuid}' not found"));
        }
        self.contacts.remove(uuid);
        Ok(())
    }

    pub fn update_contact(
        &mut self,
        uuid: &String,
        devices: Vec<(u32, PreKeyBundle)>,
    ) -> Result<(), String> {
        self.get_contact_mut(uuid).map(|x| {
            for (id, bundle) in devices {
                x.devices
                    .insert(id, Device::new(uuid.to_string(), id, bundle));
            }
            ()
        })
    }
}

#[cfg(test)]
mod test {
    use crate::contact_manager::{Contact, ContactManager, Device};
    use crate::encryption::test::{create_pre_key_bundle, store};
    use rand::rngs::OsRng;
    use uuid::Uuid;

    #[test]
    fn test_cm_add() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();
        match cm.add_contact(&charlie) {
            Ok(_) => assert!(true),
            Err(x) => assert!(false, "{}", x),
        };
    }

    #[test]
    fn test_cm_remove() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();

        let _ = cm.add_contact(&charlie);

        match cm.remove_contact(&charlie) {
            Ok(_) => assert!(true),
            Err(x) => assert!(false, "{}", x),
        }
    }

    #[test]
    fn test_cm_get() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();

        let _ = cm.add_contact(&charlie);

        match cm.get_contact(&charlie) {
            Ok(c) => assert!(c.uuid == charlie && c.devices.len() == 0),
            Err(x) => assert!(false, "{}", x),
        };
    }

    #[tokio::test]
    async fn test_cm_update() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();

        let _ = cm.add_contact(&charlie);

        let mut store = store(1);
        let bundle = create_pre_key_bundle(&mut store, 1, &mut OsRng)
            .await
            .unwrap();
        match cm.update_contact(&charlie, vec![(1, bundle)]) {
            Ok(_) => assert!(true),
            Err(x) => assert!(false, "{}", x),
        }

        assert!(cm.get_contact(&charlie).is_ok(), "Charlie was not ok")
    }
}
