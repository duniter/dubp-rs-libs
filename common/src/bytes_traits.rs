use crate::*;

pub trait FromBytes: Sized {
    type Err: Error;

    /// Create Self from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Err>;
}

pub trait AsBytes<E: Error> {
    fn as_bytes<T, F: FnMut(&[u8]) -> Result<T, E>>(&self, f: F) -> Result<T, E>;
}
