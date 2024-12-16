use std::error::Error;
use std::fmt;
use std::fmt::Display;

use common::protocol_address::ParseProtocolAddressError;
use derive_more::derive::{Display, Error, From};
use libsignal_core::{DeviceId, ServiceId};
use libsignal_protocol::SignalProtocolError;

use crate::key_manager::KeyManagerError;

pub type Result<T> = std::result::Result<T, SignalClientError>;

#[derive(Debug, Display, From)]
pub enum SignalClientError {
    #[from]
    ContactManagerError(ContactManagerError),
    KeyError(String),
    #[from]
    KeyManagerError(KeyManagerError),
    #[from]
    RegistrationError(RegistrationError),
    #[from]
    SendMessageError(SendMessageError),
    WebSocketError(String),
    #[from]
    DatabaseError(DatabaseError),
    DotenvError(String),
    #[from]
    ReceiveMessageError(ReceiveMessageError),
    #[from]
    ProcessPreKeyBundle(ProcessPreKeyBundleError),
    #[display("Tried to get a session that does not exist")]
    NoSession,
    #[from]
    Protocol(SignalProtocolError),
}

impl Error for SignalClientError {}

#[derive(Debug, Display, From, Error)]
pub struct ProcessPreKeyBundleError(pub SignalProtocolError);

#[derive(Debug, Display, From)]
pub enum ContactManagerError {
    #[from]
    DeviceNotFound(DeviceId),
    #[display("Contact with service id: '{}', not found", 0)]
    ServiceIDNotFound(ServiceId),
    #[display("Contact with service id: '{}', already exists", 0)]
    ServiceIDAlreadyExists(ServiceId),
}

impl Error for ContactManagerError {}

pub enum RegistrationError {
    PhoneNumberTaken,
    NoResponse,
    BadResponse(String),
}

impl fmt::Debug for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PhoneNumberTaken => "Phone number was already taken.".to_owned(),
            Self::NoResponse => {
                "The server did not respond to the registration request.".to_owned()
            }
            Self::BadResponse(s) => {
                format!("Bad response from server: {s}")
            }
        };
        write!(f, "Could not register account - {}", message)
    }
}

impl Error for RegistrationError {}

pub enum SendMessageError {
    EncryptionError(SignalProtocolError),
    WebSocketError(String),
}

impl fmt::Debug for SendMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for SendMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EncryptionError(err) => format!("{err}"),
            Self::WebSocketError(err) => err.to_owned(),
        };
        write!(f, "Could not send message - {}", message)
    }
}

impl Error for SendMessageError {}

#[derive(Debug, Display, Error)]
pub enum ReceiveMessageError {
    Base64DecodeError(base64::DecodeError),
    NoMessageTypeInEnvelope,
    InvalidMessageTypeInEnvelope,
    CiphertextDecodeError(SignalProtocolError),
    ParseProtocolAddressError(ParseProtocolAddressError),
    DecryptMessageError(SignalProtocolError),
    ProtobufDecodeContentError(prost::DecodeError),
    InvalidMessageContent,
    NoMessageReceived,
    EnvelopeDecodeError,
}

impl From<ParseProtocolAddressError> for SignalClientError {
    fn from(value: ParseProtocolAddressError) -> Self {
        SignalClientError::ReceiveMessageError(ReceiveMessageError::ParseProtocolAddressError(
            value,
        ))
    }
}

#[derive(Debug, Display)]
pub enum DatabaseError {
    AlreadyExists,
    Custom(Box<dyn std::error::Error + 'static>),
}

impl<E: std::error::Error + 'static> From<E> for DatabaseError {
    fn from(value: E) -> Self {
        Self::Custom(Box::new(value))
    }
}
