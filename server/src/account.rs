use libsignal_core::ServiceId;
use libsignal_protocol::IdentityKey;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Account {
    pub aci: Option<String>,
    pub pni: Option<String>,
    pub auth_token: String,
    pub identity_key: IdentityKey,
}

impl Account {
    /// Get the service id for this account.
    ///
    /// An account has an ACI (Account Identifier), or
    /// a PNI (Phone Number Identifier) or both.
    pub fn service_id(&self) -> ServiceId {
        let id = self
            .aci
            .as_ref()
            .or(self.pni.as_ref())
            .expect("An account must have an Aci, a Pni or both");
        ServiceId::parse_from_service_id_string(id).unwrap()
    }
}
