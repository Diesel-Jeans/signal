use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};
use rand::{rngs::StdRng, Rng, SeedableRng};
use uuid::Uuid;

use crate::contact_manager::Contact;

pub fn new_protocol_address() -> ProtocolAddress {
    let name = new_aci();
    ProtocolAddress::new(name.service_id_string(), new_device_id())
}

pub fn new_service_id() -> ServiceId {
    new_aci().into()
}

pub fn new_aci() -> Aci {
    Aci::from(new_uuid())
}

pub fn new_pni() -> Pni {
    Pni::from(new_uuid())
}

pub fn new_device_id() -> DeviceId {
    new_rand_number().into()
}

pub fn new_rand_number() -> u32 {
    StdRng::from_entropy().gen::<u32>()
}

pub fn new_uuid() -> Uuid {
    Uuid::new_v4()
}

pub fn new_contact() -> Contact {
    Contact::new(new_service_id())
}
