use crate::key_management::bundle::KeyBundleContent;
use libsignal_protocol::ProtocolAddress;
use std::collections::HashMap;

pub struct Device {
    pub address: ProtocolAddress,
    pub bundle: KeyBundleContent,
}

impl Device {
    pub fn new(uuid: String, device_id: u32, bundle: KeyBundleContent) -> Device {
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
        self.contacts
            .get(uuid)
            .ok_or_else(|| format!("Contact with UUID '{uuid}' not found"))
    }

    fn get_contact_mut(&mut self, uuid: &String) -> Result<&mut Contact, String> {
        self.contacts
            .get_mut(uuid)
            .ok_or_else(|| format!("Contact with UUID '{uuid}' not found"))
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
        devices: Vec<(u32, KeyBundleContent)>,
    ) -> Result<(), String> {
        self.get_contact_mut(uuid).map(|contact| {
            for (id, bundle) in devices {
                contact
                    .devices
                    .insert(id, Device::new(uuid.to_string(), id, bundle));
            }
        })
    }
}

#[cfg(test)]
mod test {
    use crate::contact_manager::ContactManager;
    use crate::encryption::test::{create_pre_key_bundle, store};
    use rand::rngs::OsRng;
    use uuid::Uuid;

    #[test]
    fn test_cm_add() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();

        cm.add_contact(&charlie).unwrap();
    }

    #[test]
    fn test_cm_remove() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();
        cm.add_contact(&charlie).unwrap();

        cm.remove_contact(&charlie).unwrap()
    }

    #[test]
    fn test_cm_get() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();
        cm.add_contact(&charlie).unwrap();

        let c = cm.get_contact(&charlie).unwrap();
        assert!(c.uuid == charlie);
        assert!(c.devices.is_empty());
    }

    #[tokio::test]
    async fn test_cm_update() {
        let mut cm = ContactManager::new();
        let charlie = Uuid::new_v4().to_string();
        cm.add_contact(&charlie).unwrap();

        let mut store = store(1);
        let bundle = create_pre_key_bundle(&mut store, 1, &mut OsRng)
            .await
            .unwrap();
        cm.update_contact(&charlie, vec![(1, bundle.try_into().unwrap())])
            .unwrap();
        assert!(cm.get_contact(&charlie).is_ok(), "Charlie was not ok")
    }
}
