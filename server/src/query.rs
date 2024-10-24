use serde::Deserialize;
#[derive(Deserialize)]
pub struct PutV1MessageParams {
    pub story: bool
}