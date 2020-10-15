use crate::*;

/// A block number.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    zerocopy::AsBytes,
    zerocopy::FromBytes,
)]
#[repr(transparent)]
pub struct BlockNumber(pub u32);

impl Display for BlockNumber {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{}", self.0)
    }
}

impl FromStr for BlockNumber {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u32::from_str(s).map(BlockNumber)
    }
}
