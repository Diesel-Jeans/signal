use libsignal_protocol::{Aci, DeviceId, Pni, ServiceId};
use rand::{rngs::StdRng, Rng, SeedableRng};
use uuid::Uuid;

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
