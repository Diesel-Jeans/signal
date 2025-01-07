#[cfg(test)]
pub(crate) mod database;
#[cfg(test)]
pub(crate) mod key;
#[cfg(test)]
pub(crate) mod message_cache;
#[cfg(test)]
pub(crate) mod user;
#[cfg(test)]
pub(crate) mod websocket;

use rand::{distributions::Alphanumeric, Rng};

#[cfg(test)]
pub fn random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
