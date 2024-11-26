use std::error::Error;
use std::fmt;
use std::fmt::Display;

use common::protocol_address::ParseProtocolAddressError;
use libsignal_core::DeviceId;
use libsignal_protocol::SignalProtocolError;

type Result<T> = std::result::Result<T, SignalClientError>;

pub enum SignalClientError {
    ContactManagerError(ContactManagerError),
    RegistrationError(RegistrationError),
    LoginError(LoginError),
    SendMessageError(SendMessageError),
    WebSocketError(String),
    DatabaseError(String),
    DotenvError(String),
    ReceiveMessageError(ReceiveMessageError),
    ServerRequestError(ServerRequestError),
}

#[derive(Debug)]
pub enum ServerRequestError {
    /// The status code was not 200 - OK
    StatusCodeError(u16, String),
    BodyDecodeError(String),
    TransmissionError(String),
}

impl Display for ServerRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusCodeError(code, body) => write!(f, "Response was {}: {}", code, body),
            Self::BodyDecodeError(err) => {
                write!(f, "Could not decode response body: {err}")
            }
            Self::TransmissionError(err) => {
                write!(f, "HTTP communication with server failed: {err}")
            }
        }
    }
}

impl Error for ServerRequestError {}

impl fmt::Debug for SignalClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for SignalClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContactManagerError(err) => write!(f, "{err}"),
            Self::RegistrationError(err) => write!(f, "{err}"),
            Self::LoginError(err) => write!(f, "{err}"),
            Self::SendMessageError(err) => write!(f, "{err}"),
            Self::WebSocketError(err) => write!(f, "{err}"),
            Self::DatabaseError(err) => write!(f, "{err}"),
            Self::DotenvError(err) => write!(f, "{err}"),
            Self::ReceiveMessageError(err) => write!(f, "{err}"),
            Self::ServerRequestError(err) => write!(f, "{err}"),
        }
    }
}

impl Error for SignalClientError {}

pub enum ContactManagerError {
    DeviceNotFound(DeviceId),
}

impl fmt::Debug for ContactManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for ContactManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DeviceNotFound(id) => format!("The user did does not have a device with id {id}"),
        };
        write!(f, "Error in ContactManager - {}", message)
    }
}

impl Error for ContactManagerError {}

impl From<ContactManagerError> for SignalClientError {
    fn from(value: ContactManagerError) -> Self {
        SignalClientError::ContactManagerError(value)
    }
}

pub enum RegistrationError {
    PhoneNumberTaken,
    NoResponse,
    BadResponse,
}

impl fmt::Debug for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for RegistrationError {
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

impl From<RegistrationError> for SignalClientError {
    fn from(value: RegistrationError) -> Self {
        SignalClientError::RegistrationError(value)
    }
}

pub enum LoginError {
    NoAccountInformation,
    MissingAccountInformation,
    LoadInfoError,
}

impl fmt::Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for LoginError {
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
        write!(f, "Could not log in - {}", message)
    }
}

impl Error for LoginError {}

impl From<LoginError> for SignalClientError {
    fn from(value: LoginError) -> Self {
        SignalClientError::LoginError(value)
    }
}

pub enum SendMessageError {
    EncryptionError(SignalProtocolError),
}

impl fmt::Debug for SendMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for SendMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EncryptionError(err) => err,
        };
        write!(f, "Could not send message - {}", message)
    }
}

impl Error for SendMessageError {}

impl From<SendMessageError> for SignalClientError {
    fn from(value: SendMessageError) -> Self {
        SignalClientError::SendMessageError(value)
    }
}

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
}

impl fmt::Debug for ReceiveMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for ReceiveMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Base64DecodeError(err) => format!("{err}"),
            Self::NoMessageTypeInEnvelope => {
                "A message was received but it did not contain the type of the message.".to_owned()
            }
            Self::InvalidMessageTypeInEnvelope => {
                format!("A message was received but it had an invalid message type")
            }
            Self::CiphertextDecodeError(err) => format!("{err}"),
            Self::ParseProtocolAddressError(err) => format!("{err}"),
            Self::DecryptMessageError(err) => format!("{err}"),
            Self::ProtobufDecodeContentError(err) => {
                format!("The decrypted message content could not be decoded: {err}")
            }
            Self::InvalidMessageContent => {
                "The message content did not contain a DataMessage".to_owned()
            }
            Self::NoMessageReceived => "No message was received.".to_owned(),
        };
        write!(f, "Could not receive message - {}", message)
    }
}

impl Error for ReceiveMessageError {}

impl From<ReceiveMessageError> for SignalClientError {
    fn from(value: ReceiveMessageError) -> Self {
        SignalClientError::ReceiveMessageError(value)
    }
}

impl From<ParseProtocolAddressError> for SignalClientError {
    fn from(value: ParseProtocolAddressError) -> Self {
        SignalClientError::ReceiveMessageError(ReceiveMessageError::ParseProtocolAddressError(
            value,
        ))
    }
}
