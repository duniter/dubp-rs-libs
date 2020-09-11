//! Wrapper for blockstamp

use crate::*;

#[derive(Clone, Copy, Debug, Error, PartialEq)]
/// Error when converting bytes to Blockstamp
pub enum BlockstampFromBytesError {
    /// Given bytes have invalid length
    #[error("Given bytes have invalid length")]
    InvalidLen,
}

/// Type of errors for [`Blockstamp`] parsing.
///
/// [`Blockstamp`]: struct.Blockstamp.html
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BlockstampParseError {
    /// Given bytes have invalid length
    #[error("Given bytes have invalid length")]
    InvalidLen,
    /// Given string have invalid format
    #[error("Given string have invalid format")]
    InvalidFormat,
    /// [`BlockNumber`](struct.BlockHash.html) part is not a valid number.
    #[error("BlockNumber part is not a valid number.")]
    InvalidBlockNumber,
    /// [`BlockHash`](struct.BlockHash.html) part is not a valid hex number.
    #[error("BlockHash part is not a valid hex number.")]
    InvalidBlockHash(BaseConversionError),
}

/// A blockstamp (Unique ID).
///
/// It's composed of the [`BlockNumber`] and
/// the [`BlockHash`] of the block.
///
/// Thanks to blockchain immutability and frequent block production, it can
/// be used to date information.
///
/// [`BlockNumber`]: struct.BlockNumber.html
/// [`BlockHash`]: struct.BlockHash.html

#[derive(Copy, Clone, Default, Deserialize, PartialEq, Eq, Hash, Serialize)]
pub struct Blockstamp {
    /// Block Id.
    pub number: BlockNumber,
    /// Block hash.
    pub hash: BlockHash,
}

/// Previous blockstamp (BlockNumber-1, previous_hash)
pub type PreviousBlockstamp = Blockstamp;

impl Blockstamp {
    /// Blockstamp size (in bytes).
    pub const SIZE_IN_BYTES: usize = 36;
}

impl Into<[u8; Self::SIZE_IN_BYTES]> for Blockstamp {
    fn into(self) -> [u8; Self::SIZE_IN_BYTES] {
        let mut bytes = [0u8; Self::SIZE_IN_BYTES];

        bytes[..4].copy_from_slice(&self.number.0.to_be_bytes());

        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.hash.0).0.as_ptr(),
                bytes[4..].as_mut_ptr(),
                Hash::SIZE_IN_BYTES,
            );
        }

        bytes
    }
}

impl Display for Blockstamp {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "{}-{}", self.number, self.hash)
    }
}

impl Debug for Blockstamp {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "Blockstamp({})", self)
    }
}

impl PartialOrd for Blockstamp {
    fn partial_cmp(&self, other: &Blockstamp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Blockstamp {
    fn cmp(&self, other: &Blockstamp) -> Ordering {
        if self.number == other.number {
            self.hash.cmp(&other.hash)
        } else {
            self.number.cmp(&other.number)
        }
    }
}

impl crate::bytes_traits::FromBytes for Blockstamp {
    type Err = BlockstampFromBytesError;

    /// Create a `Blockstamp` from bytes.
    fn from_bytes(src: &[u8]) -> Result<Blockstamp, BlockstampFromBytesError> {
        if src.len() != Blockstamp::SIZE_IN_BYTES {
            Err(BlockstampFromBytesError::InvalidLen)
        } else {
            let mut id_bytes = [0u8; 4];
            id_bytes.copy_from_slice(&src[..4]);
            let mut hash_bytes = [0u8; 32];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src[4..].as_ptr(),
                    hash_bytes.as_mut_ptr(),
                    Hash::SIZE_IN_BYTES,
                );
            }
            Ok(Blockstamp {
                number: BlockNumber(u32::from_be_bytes(id_bytes)),
                hash: BlockHash(Hash(hash_bytes)),
            })
        }
    }
}

impl FromStr for Blockstamp {
    type Err = BlockstampParseError;

    fn from_str(src: &str) -> Result<Blockstamp, BlockstampParseError> {
        let mut split = src.split('-');

        match (split.next(), split.next(), split.next()) {
            (Some(id), Some(hash), None) => {
                let hash = Hash::from_hex(hash).map_err(BlockstampParseError::InvalidBlockHash)?;

                if let Ok(id) = id.parse::<u32>() {
                    Ok(Blockstamp {
                        number: BlockNumber(id),
                        hash: BlockHash(hash),
                    })
                } else {
                    Err(BlockstampParseError::InvalidBlockNumber)
                }
            }
            _ => Err(BlockstampParseError::InvalidFormat),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bytes_traits::FromBytes;
    use unwrap::unwrap;

    #[test]
    fn blockstamp_default() {
        assert_eq!(
            Blockstamp::default(),
            Blockstamp {
                number: BlockNumber(0),
                hash: BlockHash(Hash([0u8; 32])),
            }
        )
    }

    #[test]
    fn blockstamp_ord() {
        let b1 = unwrap!(Blockstamp::from_str(
            "123-000003176306959F8674C25757BCE1CD27768E29A9B2F6DD2A4AACEAFF8C9413"
        ));
        let b2 = unwrap!(Blockstamp::from_str(
            "124-000003176306959F8674C25757BCE1CD27768E29A9B2F6DD2A4AACEAFF8C9413"
        ));
        let b3 = unwrap!(Blockstamp::from_str(
            "124-000003176306959F8674C25757BCE1CD27768E29A9B2F6DD2A4AACEAFF8C9415"
        ));

        assert!(b1 < b2);
        assert!(b2 < b3);
    }

    #[test]
    fn blockstamp_from_str_errors() {
        assert_eq!(
            Err(BlockstampParseError::InvalidFormat),
            Blockstamp::from_str("invalid_format")
        );
        assert_eq!(
            Err(BlockstampParseError::InvalidBlockNumber),
            Blockstamp::from_str(
                "not_a_number-000003176306959F8674C25757BCE1CD27768E29A9B2F6DD2A4AACEAFF8C9413"
            )
        );
        assert_eq!(
            Err(BlockstampParseError::InvalidBlockHash(
                BaseConversionError::InvalidLength {
                    expected: 64,
                    found: 3,
                }
            )),
            Blockstamp::from_str("123-ZZZ")
        );
    }

    #[test]
    fn blockstamp_from_bytes() -> Result<(), BlockstampFromBytesError> {
        assert_eq!(
            Blockstamp::from_bytes(&[]),
            Err(BlockstampFromBytesError::InvalidLen)
        );

        assert_eq!(
            Blockstamp::default(),
            Blockstamp::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ])?
        );

        assert_eq!(
            Blockstamp {
                number: BlockNumber(3),
                hash: BlockHash(Hash([2u8; 32])),
            },
            Blockstamp::from_bytes(&[
                0, 0, 0, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2,
            ])?
        );

        Ok(())
    }

    #[test]
    fn blockstamp_into_bytes() {
        let bytes: [u8; Blockstamp::SIZE_IN_BYTES] = Blockstamp::default().into();
        assert_eq!(&bytes[..4], &[0, 0, 0, 0,]);
        assert_eq!(
            &bytes[4..],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        );

        let bytes: [u8; Blockstamp::SIZE_IN_BYTES] = Blockstamp {
            number: BlockNumber(3),
            hash: BlockHash(Hash([2u8; 32])),
        }
        .into();
        assert_eq!(&bytes[..4], &[0, 0, 0, 3,]);
        assert_eq!(
            &bytes[4..],
            &[
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2,
            ]
        );
    }
}
