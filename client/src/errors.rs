use std::error::Error;
use std::fmt;
use std::fmt::Display;

use libsignal_core::DeviceId;
use libsignal_protocol::SignalProtocolError;

pub enum SignalClientError {
    ContactManagerError(ContactManagerError),
    RegistrationError(RegistrationError),
    LoginError(LoginError),
    SendMessageError(SendMessageError),
    WebSocketError(String),
    DatabaseError(String),
    DotenvError(String),
}

impl fmt::Debug for SignalClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl fmt::Display for SignalClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ContactManagerError(err) => format!("{err}"),
            Self::RegistrationError(err) => format!("{err}"),
            Self::LoginError(err) => format!("{err}"),
            Self::SendMessageError(err) => format!("{err}"),
            Self::WebSocketError(err) => err.to_string(),
            Self::DatabaseError(err) => format!("{err}"),
            Self::DotenvError(err) => format!("{err}"),
        };
        write!(f, "Could not register account - {}", message)
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
