use libsignal_core::{DeviceId, ProtocolAddress, ServiceId};
use std::collections::{HashMap, HashSet};

use crate::errors::{ContactManagerError, SignalClientError};

pub struct Contact {
    pub service_id: ServiceId,
    pub device_ids: HashSet<DeviceId>,
}

impl Contact {
    pub fn new(service_id: ServiceId, device_id: DeviceId) -> Contact {
        let mut set = HashSet::new();
        set.insert(device_id);
        Self {
            service_id,
            device_ids: set,
        }
    }
    pub fn get_address(&self, device_id: &DeviceId) -> Result<ProtocolAddress, SignalClientError> {
        Ok(ProtocolAddress::new(
            self.service_id.service_id_string(),
            *self
                .device_ids
                .get(device_id)
                .ok_or(ContactManagerError::DeviceNotFound(device_id.to_owned()))?,
        ))
    }
}

pub struct ContactManager {
    contacts: HashMap<ServiceId, Contact>,
}

impl ContactManager {
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
        }
    }

    pub fn add_contact(
        &mut self,
        service_id: &ServiceId,
        device_id: DeviceId,
    ) -> Result<(), String> {
        if self.contacts.contains_key(service_id) {
            return Err(format!(
                "Contact with service id: '{}', already exists",
                service_id.service_id_string()
            ));
        }
        self.contacts
            .insert(*service_id, Contact::new(*service_id, device_id));
        Ok(())
    }

    pub fn get_contact(&self, service_id: &ServiceId) -> Result<&Contact, String> {
        self.contacts.get(service_id).ok_or_else(|| {
            format!(
                "Contact with service id: '{}', not found",
                service_id.service_id_string()
            )
        })
    }

    fn get_contact_mut(&mut self, service_id: &ServiceId) -> Result<&mut Contact, String> {
        self.contacts.get_mut(service_id).ok_or_else(|| {
            format!(
                "Contact with service id: '{}', not found",
                service_id.service_id_string()
            )
        })
    }

    pub fn remove_contact(&mut self, service_id: &ServiceId) -> Result<(), String> {
        if !self.contacts.contains_key(service_id) {
            return Err(format!(
                "Contact with service id: '{}', not found",
                service_id.service_id_string()
            ));
        }
        self.contacts.remove(service_id);
        Ok(())
    }

    pub fn update_contact(
        &mut self,
        service_id: &ServiceId,
        device_ids: Vec<DeviceId>,
    ) -> Result<(), String> {
        self.get_contact_mut(service_id).map(|contact| {
            for id in device_ids {
                contact.device_ids.insert(id);
            }
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{contact_manager::ContactManager, test_utils::user::new_service_id};
    use libsignal_core::DeviceId;

    #[test]
    fn test_cm_add() {
        let mut cm = ContactManager::new();
        let charlie = new_service_id();
        let device_id: DeviceId = 0.into();

        cm.add_contact(&charlie, device_id).unwrap();
    }

    #[test]
    fn test_cm_remove() {
        let mut cm = ContactManager::new();
        let charlie = new_service_id();
        let device_id: DeviceId = 0.into();
        cm.add_contact(&charlie, device_id).unwrap();

        cm.remove_contact(&charlie).unwrap()
    }

    #[test]
    fn test_cm_get() {
        let mut cm = ContactManager::new();
        let charlie = new_service_id();
        let device_id: DeviceId = 0.into();
        cm.add_contact(&charlie, device_id).unwrap();

        let c = cm.get_contact(&charlie).unwrap();
        assert!(c.service_id == charlie);
        c.device_ids.get(&device_id).unwrap();
    }

    #[tokio::test]
    async fn test_cm_update() {
        let mut cm = ContactManager::new();
        let charlie = new_service_id();
        let device_id: DeviceId = 0.into();
        cm.add_contact(&charlie, device_id).unwrap();

        let new_device_id: DeviceId = 1.into();
        cm.update_contact(&charlie, vec![new_device_id]).unwrap();
        assert!(cm.get_contact(&charlie).is_ok(), "Charlie was not ok");
        assert!(cm
            .get_contact(&charlie)
            .unwrap()
            .device_ids
            .get(&device_id)
            .is_some());
        assert!(cm
            .get_contact(&charlie)
            .unwrap()
            .device_ids
            .get(&new_device_id)
            .is_some())
    }
}
