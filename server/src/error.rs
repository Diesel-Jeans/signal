use core::fmt;
use std::net::SocketAddr;

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status_code: StatusCode,
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.status_code;
        (
            status_code,
            [(header::CONTENT_TYPE, "application/json")],
            Json(json!({"StatusCode": status_code.as_u16(), "Message": self.message})),
        )
            .into_response()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API Error {}: {}", self.status_code, self.message)
    }
}

#[derive(Debug)]
pub enum SocketManagerError {
    SocketClosed,
    NoAddress(SocketAddr),
    Axum(axum::Error)
}

impl fmt::Display for SocketManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketManagerError::SocketClosed => write!(f, "Socket was closed"),
            SocketManagerError::NoAddress(who) =>write!(f, "use_ws ERROR: no address '{}'", who),
            SocketManagerError::Axum(err) => write!(f, "{}", err)
        }
    }
}

impl std::error::Error for SocketManagerError {}