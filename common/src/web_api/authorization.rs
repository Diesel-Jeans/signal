use anyhow::{anyhow, bail, Error, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, num::ParseIntError, str::FromStr};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicAuthorizationHeader {
    /// [username] is sometimes a phone number sometimes not.
    username: String,
    device_id: u32,
    password: String,
}

impl BasicAuthorizationHeader {
    pub fn new(username: String, device_id: u32, password: String) -> Self {
        Self {
            username,
            device_id,
            password,
        }
    }

    /// Signal calls this field "username" but in reality it is a phone number
    /// when sending a [RegistrationRequest] and otherwise it may be an ACI.
    pub fn username(&self) -> &String {
        &self.username
    }
    pub fn device_id(&self) -> u32 {
        self.device_id
    }
    pub fn password(&self) -> &String {
        &self.password
    }
    pub fn encode(&self) -> String {
        let encoded = BASE64_STANDARD.encode(format!(
            "{}.{}:{}",
            self.username, self.device_id, self.password
        ));
        format!("Basic {}", encoded)
    }
    pub fn decode(s: &str) -> Result<BasicAuthorizationHeader> {
        if !s.starts_with("Basic") {
            bail!("Invalid authorization header type.")
        }
        let space_index = s
            .find(" ")
            .ok_or_else(|| anyhow!("No ' ' character in AuthorizationHeader."))?;
        let s = String::from_utf8(
            BASE64_STANDARD
                .decode(&s[space_index + 1..])
                .map_err(|err| anyhow!(err))?,
        )
        .map_err(|err| anyhow!(err))?;

        let colon_index = s
            .find(":")
            .ok_or_else(|| anyhow!("No ':' character in AuthorizationHeader."))?;
        let dot_index = s
            .find(".")
            .ok_or_else(|| anyhow!("No '.' character in AuthorizationHeader."))?;
        let (address_part, password) = s.split_at(colon_index);
        let password = &password[1..];
        let (username, device_part) = address_part.split_at(dot_index);
        let device_id = device_part
            .strip_prefix(".")
            .expect("should contain a '.' since it was there when we split the string.")
            .parse()
            .map_err(|err: ParseIntError| anyhow!(err))?;
        Ok(BasicAuthorizationHeader::new(
            username.to_owned(),
            device_id,
            password.to_owned(),
        ))
    }
}

impl FromStr for BasicAuthorizationHeader {
    type Err = Error;

    /// [BasicAuthorizationHeader] is serialized to string as 'Basic username.device_id:password'
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BasicAuthorizationHeader::decode(s)
    }
}

impl Display for BasicAuthorizationHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Basic {}.{}:{}",
            self.username, self.device_id, self.password
        )
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::DeviceId;

    use super::BasicAuthorizationHeader;
    fn username() -> String {
        "Darkros1245".to_owned()
    }
    fn device_id() -> u32 {
        1
    }
    fn password() -> String {
        "mig123123".to_owned()
    }

    #[test]
    fn test_can_encode() {
        let header = BasicAuthorizationHeader::new(username(), device_id(), password());

        let serialized = header.encode();
        assert_eq!(serialized, "Basic RGFya3JvczEyNDUuMTptaWcxMjMxMjM=")
    }

    #[test]
    fn test_can_decode() {
        let header = BasicAuthorizationHeader::new(username(), device_id(), password());

        let serialized = "Basic RGFya3JvczEyNDUuMTptaWcxMjMxMjM=";
        assert_eq!(
            serialized.parse::<BasicAuthorizationHeader>().unwrap(),
            header
        )
    }

    #[test]
    fn test_displays_friendly() {
        let header = BasicAuthorizationHeader::new(username(), device_id(), password());

        assert_eq!(
            header.to_string(),
            format!("Basic {}.{}:{}", username(), device_id(), password())
        )
    }
}
