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


pub struct ContactManager{
    contacts: HashMap<String, Contact>
}

impl ContactManager {
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new()
        }
    }

    pub fn add_contact(&mut self, uuid: &String) -> Result<(), String>{
        if self.contacts.contains_key(uuid){
            return Err(format!("Contact with UUID '{uuid}' not found"));
        }
        self.contacts.insert(uuid.clone(), Contact::new(uuid.clone()));
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

    pub fn remove_contact(&mut self, uuid: &String) -> Result<(), String>{
        if !self.contacts.contains_key(uuid){
            return Err(format!("Contact with UUID '{uuid}' not found"));
        }
        self.contacts.remove(uuid);
        Ok(())
    }

    pub fn update_contact(&mut self, uuid: &String, devices: Vec<(u32, PreKeyBundle)>) -> Result<(), String>{
        self.get_contact_mut(uuid).map(|x| {
            for (id, bundle) in devices{
                x.devices.insert(id, Device::new(uuid.to_string(), id, bundle));
            }
            ()
        })
    }

}