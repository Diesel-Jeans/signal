use common::web_api::{SignalMessage, SignalMessages};
use common::signal_protobuf::{envelope, Envelope};
use crate::account::Account;
use libsignal_core::{DeviceId, ServiceId};

pub trait ToEnvelope {
    fn to_envelope(
        &mut self,
        destination_id: ServiceId,
        account: Option<Account>,
        src_device_id: Option<DeviceId>,
        timestamp: i64,
        story: bool,
        urgent: bool,
    ) -> Envelope;
}

impl ToEnvelope for SignalMessage {
    fn to_envelope(
        &mut self,
        destination_id: ServiceId,
        account: Option<Account>,
        src_device_id: Option<DeviceId>,
        timestamp: i64,
        story: bool,
        urgent: bool,
    ) -> Envelope {
        let typex = envelope::Type::try_from(self.r#type as i32).unwrap();
        todo!() // TODO: make this when Account has been implemented correctly
    }
}
