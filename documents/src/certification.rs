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

//! Wrappers around Certification documents.

pub mod v10;

pub use v10::{
    CertificationDocumentV10, CertificationDocumentV10Stringified, CompactCertificationDocumentV10,
};

use crate::*;

/// Wrap an Certification document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum CertificationDocument {
    /// Certification document v10
    V10(CertificationDocumentV10),
}

impl Document for CertificationDocument {
    type PublicKey = PubKey;

    #[inline]
    fn version(&self) -> usize {
        match self {
            CertificationDocument::V10(cert_v10) => cert_v10.version(),
        }
    }

    #[inline]
    fn currency(&self) -> &str {
        match self {
            CertificationDocument::V10(cert_v10) => cert_v10.currency(),
        }
    }

    #[inline]
    fn blockstamp(&self) -> Blockstamp {
        match self {
            CertificationDocument::V10(cert_v10) => cert_v10.blockstamp(),
        }
    }

    #[inline]
    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        match self {
            CertificationDocument::V10(cert_v10) => svec![PubKey::Ed25519(cert_v10.issuers()[0])],
        }
    }

    #[inline]
    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        match self {
            CertificationDocument::V10(cert_v10) => svec![Sig::Ed25519(cert_v10.signatures()[0])],
        }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        match self {
            CertificationDocument::V10(cert_v10) => cert_v10.as_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CertificationDocumentStringified {
    V10(CertificationDocumentV10Stringified),
}

impl ToStringObject for CertificationDocument {
    type StringObject = CertificationDocumentStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            CertificationDocument::V10(idty) => {
                CertificationDocumentStringified::V10(idty.to_string_object())
            }
        }
    }
}
