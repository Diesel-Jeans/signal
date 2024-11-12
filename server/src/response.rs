use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub needs_sync: bool,
}

impl IntoResponse for SendMessageResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}
