use std::time::{SystemTime, UNIX_EPOCH};

use crate::account::Account;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use common::{signal_protobuf::Envelope, web_api::SignalMessage};
use libsignal_core::ServiceId;

pub trait ToEnvelope {
    fn to_envelope(
        &self,
        destination_id: &ServiceId,
        source_account: &Account,
        source_device_id: u8,
        timestamp: u64,
        urgent: bool,
    ) -> Envelope;
}

impl ToEnvelope for SignalMessage {
    fn to_envelope(
        &self,
        destination_id: &ServiceId,
        source_account: &Account,
        source_device_id: u8,
        timestamp: u64,
        urgent: bool,
    ) -> Envelope {
        Envelope {
            r#type: Some(self.r#type),
            source_service_id: Some(source_account.aci().service_id_string()),
            source_device: Some(source_device_id as u32),
            client_timestamp: Some(timestamp),
            content: Some(BASE64_STANDARD.decode(&self.content).unwrap()),
            server_guid: None,
            server_timestamp: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64,
            ),
            ephemeral: None,
            destination_service_id: Some(destination_id.service_id_string()),
            urgent: Some(urgent),
            updated_pni: None,
            story: None,
            report_spam_token: None,
            shared_mrm_key: None,
        }
    }
}
