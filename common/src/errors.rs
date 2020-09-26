//! Define DUBP Documents errors types.

use crate::*;

#[derive(Clone, Debug, Error, PartialEq)]
#[error("{0}")]
pub struct StringErr(pub String);

/// List of possible errors for document signatures verification.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum DocumentSigsErr {
    /// Not same amount of issuers and signatures.
    /// (issuers count, signatures count)
    #[error("Not same amount of issuers and signatures: found {0} issuers and {1} signatures.")]
    IncompletePairs(usize, usize),
    /// Signatures don't match.
    /// List of mismatching pairs indexes.
    #[error("Signatures don\'t match: {0:?}")]
    Invalid(HashMap<usize, SigError>),
}
