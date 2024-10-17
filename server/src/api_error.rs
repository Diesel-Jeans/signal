use axum::{
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

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
