use crate::*;

#[derive(Clone, Debug, Error, PartialEq)]
#[error("{0}")]
pub struct StringErr(pub String);
