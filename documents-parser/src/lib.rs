//  Copyright (C) 2020  Éloïs SANCHEZ.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Provide parser for DUBP documents.

#![deny(
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces
)]

mod compact_text;
mod json;
mod raw_text;
mod transaction_utils;

// Prelude
pub mod prelude {
    pub use crate::compact_text::certifications::parse_compact_certifications;
    pub use crate::compact_text::identities::parse_compact_identities;
    pub use crate::compact_text::memberships::parse_compact_memberships;
    pub use crate::compact_text::revoked::parse_compact_revocations;
    pub use crate::compact_text::ParseCompactDocError;
    pub use crate::json::transactions::{parse_json_transactions, ParseJsonTxError};
    pub use crate::raw_text::{ParseFromRawText, Rule};
}

// Export technical types
pub use crate::json::serde_json_value_to_pest_json_value;

// Export profession types

// Crate imports
pub(crate) use crate::json::DefaultHasher;
pub(crate) use crate::prelude::*;
pub(crate) use crate::raw_text::{FromPestPair, RawDocumentsParser};
pub(crate) use crate::transaction_utils::{
    tx_input_v10_from_str, tx_output_v10_from_str, tx_unlock_v10_from_str,
};
pub(crate) use dubp_common::crypto::bases::BaseConversionError;
pub(crate) use dubp_common::crypto::hashs::Hash;
pub(crate) use dubp_common::crypto::keys::*;
pub(crate) use dubp_common::prelude::*;
pub(crate) use dubp_documents::certification::{
    v10::CertificationDocumentV10Builder, CertificationDocument, CertificationDocumentV10,
    CompactCertificationDocumentV10,
};
pub(crate) use dubp_documents::identity::{
    IdentityDocument, IdentityDocumentV10, IdentityDocumentV10Builder,
};
pub(crate) use dubp_documents::membership::{
    MembershipDocument, MembershipDocumentV10, MembershipDocumentV10Builder, MembershipType,
};
pub(crate) use dubp_documents::prelude::*;
pub(crate) use dubp_documents::revocation::{
    v10::RevocationDocumentV10Builder, CompactRevocationDocumentV10, RevocationDocument,
    RevocationDocumentV10,
};
pub(crate) use dubp_documents::smallvec::{smallvec as svec, SmallVec};
pub(crate) use dubp_documents::transaction::{
    v10::TransactionInputUnlocksV10, OutputIndex, TransactionDocument, TransactionDocumentBuilder,
    TransactionDocumentV10, TransactionDocumentV10Builder, TransactionInputV10,
    TransactionOutputCondition, TransactionOutputV10, TransactionUnlockProof, TxAmount, TxBase,
    UTXOConditions, UTXOConditionsGroup,
};
//pub(crate) use dubp_documents::documents::c
pub(crate) use json_pest_parser::{JSONValue, Number};
pub(crate) use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
pub(crate) use pest_derive::Parser;
pub(crate) use serde_json::Value;
pub(crate) use std::{collections::HashMap, net::AddrParseError, num::ParseIntError, str::FromStr};
pub(crate) use thiserror::Error;
pub(crate) use unwrap::unwrap;

/// Error with pest parser (grammar)
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("Grammar error: {0}")]
pub struct PestError(pub String);

impl<T: pest::RuleType> From<pest::error::Error<T>> for PestError {
    fn from(e: pest::error::Error<T>) -> Self {
        PestError(format!("{}", e))
    }
}

/// List of possible errors while parsing a text document.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum RawTextParseError {
    /// The given source don't have a valid specific document format (document type).
    #[error("TextDocumentParseError: Invalid inner format: {0}")]
    InvalidInnerFormat(String),
    /// Ip address parse error
    #[error("TextDocumentParseError: invalid ip: {0}")]
    IpAddrError(AddrParseError),
    /// Error with pest parser
    #[error("TextDocumentParseError: {0}")]
    PestError(PestError),
    /// Unexpected rule
    #[error("TextDocumentParseError: Unexpected rule: '{0}'")]
    UnexpectedRule(String),
    /// Unexpected version
    #[error("TextDocumentParseError: Unexpected version: '{0}'")]
    UnexpectedVersion(String),
    /// Unknown type
    #[error("TextDocumentParseError: UnknownType.")]
    UnknownType,
}

impl From<AddrParseError> for RawTextParseError {
    fn from(e: AddrParseError) -> Self {
        RawTextParseError::IpAddrError(e)
    }
}

impl From<PestError> for RawTextParseError {
    fn from(e: PestError) -> Self {
        RawTextParseError::PestError(e)
    }
}

impl<T: pest::RuleType> From<pest::error::Error<T>> for RawTextParseError {
    fn from(e: pest::error::Error<T>) -> Self {
        RawTextParseError::PestError(e.into())
    }
}
