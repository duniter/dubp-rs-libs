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

use crate::*;

pub(super) mod certification;
pub(super) mod document;
pub(super) mod identity;
pub(super) mod membership;
pub(super) mod revocation;
pub(super) mod transaction;
pub(super) mod wallet_script;

#[derive(Debug, Clone, Copy, Parser)]
#[grammar = "documents_grammar.pest"]
/// Parser for Documents
pub(crate) struct RawDocumentsParser;

pub trait FromPestPair: Sized {
    /// Parse from pest pair
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, TextParseError>;
}

pub trait ParseFromRawText: FromPestPair {
    /// Parse text document from raw format
    fn parse_from_raw_text(doc: &str) -> Result<Self, TextParseError>;
}

macro_rules! impl_parse_from_raw_text {
    ($Type:ty, $Rule:expr) => {
        impl ParseFromRawText for $Type {
            #[inline]
            fn parse_from_raw_text(doc: &str) -> Result<Self, TextParseError> {
                let mut doc_pairs = RawDocumentsParser::parse($Rule, doc)
                    .map_err(|e| TextParseError::PestError(e.into()))?;
                Self::from_pest_pair(doc_pairs.next().unwrap_or_else(|| unreachable!()))
                // get and unwrap the `$Rule` rule; never fails
            }
        }
    };
}

impl_parse_from_raw_text!(DubpDocument, Rule::document);
impl_parse_from_raw_text!(IdentityDocument, Rule::idty);
impl_parse_from_raw_text!(CertificationDocument, Rule::cert);
impl_parse_from_raw_text!(MembershipDocument, Rule::membership);
impl_parse_from_raw_text!(RevocationDocument, Rule::revoc);
impl_parse_from_raw_text!(TransactionDocument, Rule::tx);
impl_parse_from_raw_text!(TransactionDocumentV10, Rule::tx_v10);
