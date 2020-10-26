use crate::*;

pub mod certifications;
pub mod identities;
pub mod memberships;
pub mod revoked;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ParseCompactDocError {
    #[error("wrong blockstamp : {0}")]
    BlockNumber(ParseIntError),
    #[error("wrong blockstamp : {0}")]
    Blockstamp(BlockstampParseError),
    #[error("wrong issuer : {0}")]
    Issuer(BaseConversionError),
    #[error("wrong target : {0}")]
    Target(BaseConversionError),
    #[error("wrong sig : {0}")]
    Sig(BaseConversionError),
    #[error("wrong format !")]
    WrongFormat,
}
