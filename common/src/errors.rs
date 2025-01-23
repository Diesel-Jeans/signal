use derive_more::derive::{Display, Error, From};
use libsignal_protocol::SignalProtocolError;
use prost::DecodeError;
use std::error::Error;

#[derive(Debug, Display, Error, From)]
pub enum SignalError {
    DecodeEnvelope(DecodeEnvelopeError),
    DecodeContent(DecodeContentError),
    DecodeDataMessage(DecodeDataMessageError),
    ProstDecode(DecodeError),
    UnpadError,
    Protocol(SignalProtocolError),
}

#[derive(Debug, Display, From)]
pub struct DecodeEnvelopeError(pub String);

impl Error for DecodeEnvelopeError {}

#[derive(Debug, Display, From)]
pub struct DecodeContentError(pub String);

impl Error for DecodeContentError {}

#[derive(Debug, Display, From)]
pub struct DecodeDataMessageError(pub String);

impl Error for DecodeDataMessageError {}
