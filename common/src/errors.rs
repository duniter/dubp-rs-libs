//! Define DUBP Documents errors types.

use crate::*;

#[derive(Clone, Debug, Error, PartialEq)]
#[error("{0}")]
pub struct StringErr(pub String);

/// List of possible errors for document signatures verification.
#[derive(Debug, Eq, PartialEq)]
pub enum DocumentSigsErr {
    /// Not same amount of issuers and signatures.
    /// (issuers count, signatures count)
    IncompletePairs(usize, usize),
    /// Signatures don't match.
    /// List of mismatching pairs indexes.
    Invalid(HashMap<usize, SigError>),
}
