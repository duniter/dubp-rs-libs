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

//! Define DUBP Documents.

#![deny(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces
)]

pub mod certification;
pub mod identity;
pub mod membership;
pub mod revocation;
mod traits;
pub mod transaction;

// Re-export crates
pub use dubp_wallet;
pub use dubp_wallet::dubp_common;
pub use dubp_wallet::smallvec;

// prelude
pub mod prelude {
    pub use crate::traits::{
        text::{CompactTextDocument, TextDocument, TextDocumentBuilder, TextDocumentFormat},
        Document, DocumentBuilder, ToJsonObject, ToStringObject,
    };
    pub use crate::{DubpDocument, DubpDocumentStr};
}

// Crate imports
pub(crate) use crate::prelude::*;
pub(crate) use crate::transaction::{TransactionDocumentTrait, UTXOConditions};
pub(crate) use beef::lean::Cow as BeefCow;
pub(crate) use dubp_common::crypto::bases::b58::ToBase58;
pub(crate) use dubp_common::crypto::hashs::Hash;
pub(crate) use dubp_common::crypto::keys::*;
pub(crate) use dubp_common::prelude::*;
pub(crate) use dubp_wallet::prelude::*;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use smallvec::{smallvec as svec, SmallVec, ToSmallVec};
pub(crate) use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    iter::FromIterator,
};

/// User document of DUBP (DUniter Blockhain Protocol)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum DubpDocument {
    /// Transaction document.
    Transaction(transaction::TransactionDocument),

    /// Identity document.
    Identity(identity::IdentityDocument),

    /// Membership document.
    Membership(membership::MembershipDocument),

    /// Certification document.
    Certification(certification::CertificationDocument),

    /// Revocation document.
    Revocation(revocation::RevocationDocument),
}

/// List of stringified user document types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DubpDocumentStr {
    /// Transaction document.
    Transaction(Box<transaction::TransactionDocumentStringified>),

    /// Identity document.
    Identity(identity::IdentityDocumentStringified),

    /// Membership document.
    Membership(membership::MembershipDocumentStringified),

    /// Certification document.
    Certification(Box<certification::CertificationDocumentStringified>),

    /// Revocation document.
    Revocation(Box<revocation::RevocationDocumentStringified>),
}

impl ToStringObject for DubpDocument {
    type StringObject = DubpDocumentStr;

    fn to_string_object(&self) -> Self::StringObject {
        match *self {
            DubpDocument::Identity(ref doc) => DubpDocumentStr::Identity(doc.to_string_object()),
            DubpDocument::Membership(ref doc) => {
                DubpDocumentStr::Membership(doc.to_string_object())
            }
            DubpDocument::Certification(ref doc) => {
                DubpDocumentStr::Certification(Box::new(doc.to_string_object()))
            }
            DubpDocument::Revocation(ref doc) => {
                DubpDocumentStr::Revocation(Box::new(doc.to_string_object()))
            }
            DubpDocument::Transaction(ref doc) => {
                DubpDocumentStr::Transaction(Box::new(doc.to_string_object()))
            }
        }
    }
}

macro_rules! dubp_document_fn {
    ($fn_name:ident, $return_type:ty) => {
        fn $fn_name(&self) -> $return_type {
            match self {
                Self::Certification(doc) => doc.$fn_name(),
                Self::Identity(doc) => doc.$fn_name(),
                Self::Membership(doc) => doc.$fn_name(),
                Self::Revocation(doc) => doc.$fn_name(),
                Self::Transaction(doc) => doc.$fn_name(),
            }
        }
    };
}

impl Document for DubpDocument {
    type PublicKey = PubKey;

    dubp_document_fn!(as_bytes, BeefCow<[u8]>);
    dubp_document_fn!(blockstamp, Blockstamp);
    dubp_document_fn!(currency, &str);
    dubp_document_fn!(issuers, SmallVec<[Self::PublicKey; 1]>);
    dubp_document_fn!(
        signatures,
        SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]>
    );
    dubp_document_fn!(version, usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    //use pretty_assertions::assert_eq;
    use unwrap::unwrap;

    // simple text document for signature testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PlainTextDocument {
        pub text: &'static str,
        pub issuers: SmallVec<[PubKey; 1]>,
        pub signatures: SmallVec<[Sig; 1]>,
    }

    impl Document for PlainTextDocument {
        type PublicKey = PubKey;

        fn version(&self) -> usize {
            unimplemented!()
        }

        fn currency(&self) -> &str {
            unimplemented!()
        }

        fn blockstamp(&self) -> Blockstamp {
            unimplemented!()
        }

        fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
            self.issuers.iter().copied().collect()
        }

        fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
            self.signatures.iter().copied().collect()
        }

        fn as_bytes(&self) -> BeefCow<[u8]> {
            BeefCow::borrowed(self.text.as_bytes())
        }
    }

    #[test]
    fn verify_signatures() {
        let text = "Version: 10
Type: Identity
Currency: duniter_unit_test_currency
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
UniqueID: tic
Timestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
";

        // good pair
        let issuer1 = PubKey::Ed25519(unwrap!(
            ed25519::PublicKey::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"),
            "Fail to parse PublicKey from base58"
        ));

        let sig1 = Sig::Ed25519(unwrap!(
            ed25519::Signature::from_base64(
                "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMM\
                 mQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==",
            ),
            "Fail to parse Signature from base64"
        ));

        // incorrect pair
        let issuer2 = PubKey::Ed25519(unwrap!(
            ed25519::PublicKey::from_base58("DNann1Lh55eZMEDXeYt32bzHbA3NJR46DeQYCS2qQdLV"),
            "Fail to parse PublicKey from base58"
        ));

        let sig2 = Sig::Ed25519(unwrap!(
            ed25519::Signature::from_base64(
                "1eubHHbuNfilHHH0G2bI30iZzebQ2cQ1PC7uPAw08FGMM\
                 mQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==",
            ),
            "Fail to parse Signature from base64"
        ));

        {
            let doc = PlainTextDocument {
                text,
                issuers: svec![issuer1],
                signatures: svec![sig1],
            };

            if let Err(e) = doc.verify_signatures() {
                panic!("DocumentSigsErr: {:?}", e)
            }
        }

        {
            let doc = PlainTextDocument {
                text,
                issuers: svec![issuer1],
                signatures: svec![sig2],
            };
            assert_eq!(
                doc.verify_signatures(),
                Err(DocumentSigsErr::Invalid(
                    maplit::hashmap![0 => SigError::InvalidSig]
                ))
            );
        }

        {
            let doc = PlainTextDocument {
                text,
                issuers: svec![issuer1, issuer2],
                signatures: svec![sig1],
            };

            assert_eq!(
                doc.verify_signatures(),
                Err(DocumentSigsErr::IncompletePairs(2, 1))
            );
        }

        {
            let doc = PlainTextDocument {
                text,
                issuers: svec![issuer1],
                signatures: svec![sig1, sig2],
            };

            assert_eq!(
                doc.verify_signatures(),
                Err(DocumentSigsErr::IncompletePairs(1, 2))
            );
        }
    }
}
