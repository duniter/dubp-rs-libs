use crate::*;

/// Wrapper of a block hash.
#[derive(
    Copy, Clone, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Shrinkwrap,
)]
pub struct BlockHash(pub Hash);

impl Display for BlockHash {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{}", self.0.to_hex())
    }
}

impl Debug for BlockHash {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "BlockHash({})", self)
    }
}
