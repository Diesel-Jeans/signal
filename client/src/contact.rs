use libsignal_protocol::*;

pub struct Contact {
    device_id: DeviceId,
    uuid: String,
    e164: String, // phone number
    pub address: ProtocolAddress,
    pub bundle: Option<PreKeyBundle>
}

impl Contact {
    pub fn new(id: u32, uuid: String, e164: String) -> Contact{
        let device_id = id.into();
        let address = ProtocolAddress::new(uuid.clone(), device_id);
        Self {
            device_id: device_id,
            uuid: uuid,
            e164: e164,
            address: address,
            bundle: None
        }
    }
}