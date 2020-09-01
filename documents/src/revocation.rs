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

//! Wrappers around Revocation documents.

pub mod v10;

use crate::*;

pub use v10::{
    CompactRevocationDocumentV10, CompactRevocationDocumentV10Stringified, RevocationDocumentV10,
    RevocationDocumentV10Stringified,
};

/// Wrap an Revocation document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RevocationDocument {
    /// Revocation document v10
    V10(RevocationDocumentV10),
}

/// Wrap an Compact Revocation document.
///
/// Must be created by a revocation document.
#[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum CompactRevocationDocument {
    /// Compact revocation document v10
    V10(CompactRevocationDocumentV10),
}

impl Document for RevocationDocument {
    type PublicKey = PubKey;

    #[inline]
    fn version(&self) -> usize {
        match self {
            RevocationDocument::V10(revoc_10) => revoc_10.version(),
        }
    }

    #[inline]
    fn currency(&self) -> &str {
        match self {
            RevocationDocument::V10(revoc_v10) => revoc_v10.currency(),
        }
    }

    #[inline]
    fn blockstamp(&self) -> Blockstamp {
        match self {
            RevocationDocument::V10(revoc_v10) => revoc_v10.blockstamp(),
        }
    }

    #[inline]
    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        match self {
            RevocationDocument::V10(revoc_v10) => svec![PubKey::Ed25519(revoc_v10.issuers()[0])],
        }
    }

    #[inline]
    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        match self {
            RevocationDocument::V10(revoc_v10) => svec![Sig::Ed25519(revoc_v10.signatures()[0])],
        }
    }

    #[inline]
    fn as_bytes(&self) -> BeefCow<[u8]> {
        match self {
            RevocationDocument::V10(revoc_v10) => revoc_v10.as_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RevocationDocumentStringified {
    V10(RevocationDocumentV10Stringified),
}

impl ToStringObject for RevocationDocument {
    type StringObject = RevocationDocumentStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            RevocationDocument::V10(idty) => {
                RevocationDocumentStringified::V10(idty.to_string_object())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CompactRevocationDocumentStringified {
    V10(CompactRevocationDocumentV10Stringified),
}

impl ToStringObject for CompactRevocationDocument {
    type StringObject = CompactRevocationDocumentStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            CompactRevocationDocument::V10(doc) => {
                CompactRevocationDocumentStringified::V10(doc.to_string_object())
            }
        }
    }
}
