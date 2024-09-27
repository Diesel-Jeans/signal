use common::signal_protobuf::Envelope;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub(crate) struct InMemoryDB {
    pub user: HashSet<String>,
    pub mailbox: HashMap<String, Vec<Envelope>>,
}

impl InMemoryDB {
    pub(crate) fn new() -> Self {
        InMemoryDB {
            user: HashSet::new(),
            mailbox: HashMap::new(),
        }
    }
}
