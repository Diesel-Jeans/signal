#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum PreKeyType {
    Signed,
    Kyber,
    OneTime,
    Identity,
}
