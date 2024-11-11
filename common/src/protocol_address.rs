use core::fmt;
use std::{error::Error, fmt::Display, num::ParseIntError};

use anyhow::{anyhow, Ok, Result};
use libsignal_protocol::{ProtocolAddress, SignalProtocolError};

#[derive(Debug)]
enum ParseProtocolAddressError {
    /// The protocol address did not contain a '.' character.
    InvalidFormat,
    /// The device ID could not be parsed. Must be a valid u32.
    InvalidDeviceId,
}

impl Display for ParseProtocolAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidFormat => "The protocol address did not contain a '.' character.",
            Self::InvalidDeviceId => "The device ID could not be parsed. Must be a valid u32.",
        };
        write!(f, "Could not register account - {}", message)
    }
}
impl Error for ParseProtocolAddressError {}

pub fn parse_protocol_address(address: &str) -> Result<ProtocolAddress> {
    let (username, device_part) = address.split_at(
        address
            .find(".")
            .ok_or(anyhow!("No '.' character in ProtocolAddress."))?,
    );
    let device_id: u32 = device_part
        .strip_prefix(".")
        .expect("should contain a '.' since it was there when we split the string.")
        .parse()
        .map_err(|err: ParseIntError| anyhow!(err))?;
    Ok(ProtocolAddress::new(username.to_owned(), device_id.into()))
}
