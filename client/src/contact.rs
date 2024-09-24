use libsignal_protocol::*;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Device {
    pub address: ProtocolAddress,
    pub bundle: Option<PreKeyBundle>,
}

impl Device {
    pub fn new(uuid: String, device_id: u32, bundle: Option<PreKeyBundle>) -> Device {
        Self {
            address: ProtocolAddress::new(uuid, device_id.into()),
            bundle: bundle,
        }
    }
}

#[derive(Clone)]
pub struct Contact {
    pub uuid: String,
    devices: HashMap<u32, Device>,
}

impl Contact {
    pub fn new(uuid: String) -> Contact {
        Self {
            uuid: uuid,
            devices: HashMap::new(),
        }
    }

    pub fn new_with_devices(uuid: String, devices: &Vec<Device>) -> Contact {
        let mut contact = Contact::new(uuid);
        for device in devices {
            contact.add_device(device.clone());
        }
        contact
    }

    pub fn add_device(&mut self, device: Device) {
        self.devices
            .insert(device.address.device_id().into(), device);
    }

    pub fn remove_device(&mut self, device_id: &u32) {
        self.devices.remove(device_id);
    }
}

impl<'a> IntoIterator for &'a Contact {
    type Item = &'a Device;
    type IntoIter = std::collections::hash_map::Values<'a, u32, Device>;

    fn into_iter(self) -> Self::IntoIter {
        self.devices.values()
    }
}

impl<'a> IntoIterator for &'a mut Contact {
    type Item = &'a mut Device;
    type IntoIter = std::collections::hash_map::ValuesMut<'a, u32, Device>;

    fn into_iter(self) -> Self::IntoIter {
        self.devices.values_mut()
    }
}
