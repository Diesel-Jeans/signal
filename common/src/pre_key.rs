#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum PreKey {
    Signed,
    Kyber,
    OneTime,
    Identity,
}
