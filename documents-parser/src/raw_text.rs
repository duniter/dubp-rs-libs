use crate::*;

pub(super) mod certification;
pub(super) mod document;
pub(super) mod identity;
pub(super) mod membership;
pub(super) mod revocation;
pub(super) mod transaction;

#[derive(Debug, Clone, Copy, Parser)]
#[grammar = "documents_grammar.pest"]
/// Parser for Documents
pub(crate) struct RawDocumentsParser;

pub trait FromPestPair: Sized {
    /// Parse from pest pair
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError>;
}

pub trait ParseFromRawText: FromPestPair {
    /// Parse text document from raw format
    fn parse_from_raw_text(doc: &str) -> Result<Self, RawTextParseError>;
}

macro_rules! impl_parse_from_raw_text {
    ($Type:ty, $Rule:expr) => {
        impl ParseFromRawText for $Type {
            #[inline]
            fn parse_from_raw_text(doc: &str) -> Result<Self, RawTextParseError> {
                let mut doc_pairs = RawDocumentsParser::parse($Rule, doc)
                    .map_err(|e| RawTextParseError::PestError(e.into()))?;
                Self::from_pest_pair(unwrap!(doc_pairs.next())) // get and unwrap the `$Rule` rule; never fails
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
