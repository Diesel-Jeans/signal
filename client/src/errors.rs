use std::error::Error;
use std::fmt;
use std::fmt::Display;

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

pub enum LoginError {
    NoAccountInformation,
    MissingAccountInformation,
    LoadInfoError,
}

impl Error for LoginError {}

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
        write!(f, "Could not register account - {}", message)
    }
}

trait ClientError: Error {}

#[derive(Debug)]
pub struct MissingFieldError {
    field: String,
}
impl MissingFieldError {
    pub fn new(field: String) -> Self {
        Self { field }
    }
}

impl From<&str> for MissingFieldError {
    fn from(value: &str) -> Self {
        MissingFieldError::new(value.to_owned())
    }
}
