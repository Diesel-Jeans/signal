use anyhow::{bail, Result};
use std::iter::zip;

use common::web_api::{SignalMessage, SignalMessages};

use crate::account::Account;

pub struct DestinationDeviceValidator;

impl DestinationDeviceValidator {
    pub fn validate_registration_id_from_messages(
        account: &Account,
        messages: &[SignalMessage],
        use_phone_number_identity: bool,
    ) -> Result<()> {
        let device_id_and_registration_id: Vec<(u32, u32)> = messages
            .iter()
            .map(|message| {
                (
                    message.destination_device_id,
                    message.destination_registration_id,
                )
            })
            .collect();
        Self::validate_registration_id_from_id_tuple(
            account,
            &device_id_and_registration_id,
            use_phone_number_identity,
        )
    }

    pub fn validate_registration_id_from_id_tuple(
        account: &Account,
        device_ids_and_registration_ids: &[(u32, u32)],
        use_phone_number_identity: bool,
    ) -> Result<()> {
        let stale_devices: Vec<u32> = device_ids_and_registration_ids
            .iter()
            .filter(|device_id_and_registration_id| device_id_and_registration_id.1 > 0)
            .filter(|device_id_and_registration_id| {
                let device_id = device_id_and_registration_id.0;
                let registration_id = device_id_and_registration_id.1;
                let registration_id_matches: bool = if let Some(device) = account
                    .devices()
                    .iter()
                    .find(|device| (u32::from(device.device_id()) == device_id))
                {
                    registration_id
                        == if use_phone_number_identity {
                            device.pni_registration_id()
                        } else {
                            device.registration_id()
                        }
                } else {
                    false
                };
                !registration_id_matches
            })
            .map(|device_id_and_registration_id| device_id_and_registration_id.0)
            .collect();

        if !stale_devices.is_empty() {
            bail!("Stale devices.")
        }
        Ok(())
    }

    pub fn validate_complete_device_list(
        account: &Account,
        message_device_ids: &[u32],
        excluded_device_ids: &[u32],
    ) -> Result<()> {
        let account_device_ids: Vec<u32> = account
            .devices()
            .iter()
            .map(|device| device.device_id().into())
            .filter(|device_id| !excluded_device_ids.contains(device_id))
            .collect();
        let missing_device_ids: Vec<u32> = account_device_ids
            .iter()
            .filter(|account_device_id| !message_device_ids.contains(account_device_id))
            .cloned()
            .collect();
        let extra_device_ids: Vec<u32> = message_device_ids
            .iter()
            .filter(|message_device_id| !account_device_ids.contains(message_device_id))
            .cloned()
            .collect();

        if !missing_device_ids.is_empty() || !extra_device_ids.is_empty() {
            bail!("Mismatched devices.")
        }
        Ok(())
    }
}
