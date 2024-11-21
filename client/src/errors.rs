use std::error::Error;
use std::fmt::{self, Debug, Display};

use common::protocol_address::ParseProtocolAddressError;
use libsignal_protocol::SignalProtocolError;

pub enum ClientError {
    RegistrationError(RegistrationError),
    LoginError(LoginError),
    EncryptionError(SignalProtocolError),
    DecryptionError(SignalProtocolError),
    PaddingError,
    NoMessageType,
    InvalidMessageType(i32),
    InvalidContent,
    ProtobufMessageDecodeError(prost::DecodeError),
    Base64MessageDecodeError(base64::DecodeError),
    CiphertextMessageDecodeError,
    ParseProtocolAddress(ParseProtocolAddressError),
    NoPendingMessage,
}

impl Debug for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RegistrationError(err) => format!("{err}"),
                Self::LoginError(err) => format!("{err}"),
                Self::EncryptionError(err) => format!("Could not encrypt message: {}", err),
                Self::PaddingError =>
                    "Could not unpad message: missing termination char 0x80".to_owned(),
                Self::InvalidMessageType(t) => format!("The message type {} is not supported.", t),
                Self::ProtobufMessageDecodeError(err) =>
                    format!("Could not decode protobuf received from server: {}", err),
                Self::Base64MessageDecodeError(err) =>
                    format!("Could not decode base64 received from server: {}", err),
                Self::ParseProtocolAddress(err) => format!("{err}"),
                Self::CiphertextMessageDecodeError =>
                    "Could not decode ciphertext message.".to_owned(),
                Self::InvalidContent => "Content must contain a DataMessage".to_owned(),
                Self::NoMessageType => "Envelope did not contain a message type.".to_owned(),
                Self::DecryptionError(err) => format!("Could not encrypt message: {}", err),
                Self::NoPendingMessage => "No new messages received".to_owned(),
            }
        )
    }
}

pub enum RegistrationError {
    PhoneNumberTaken,
    NoResponse,
    BadResponse,
}

impl Debug for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PhoneNumberTaken => "Phone number was already taken.",
            Self::NoResponse => "The server did not respond to the registration request.",
            Self::BadResponse => {
                "The server responded to the request, but the response could not be parsed."
            }
        };
        write!(f, "Could not register account - {}", message)
    }
}

impl Error for RegistrationError {}

pub enum LoginError {
    NoAccountInformation,
    MissingAccountInformation,
    LoadInfoError,
}

impl Error for LoginError {}

impl Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoAccountInformation => {
                "No account information is saved locally. Did you ever register this device?"
            }
            Self::MissingAccountInformation => {
                "Insufficient account information to login. Fields were missing in the credentials file."
            }
            Self::LoadInfoError => "Could not load stored credentials. Maybe your credentials were corrupted.",
        };
        write!(f, "Could not register account - {}", message)
    }
}
