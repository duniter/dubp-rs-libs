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

//! Wrappers around Identity documents.

pub mod v10;

pub use v10::{IdentityDocumentV10, IdentityDocumentV10Builder, IdentityDocumentV10Stringified};

use crate::*;

/// Identity document
#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
pub enum IdentityDocument {
    /// Identity document V10
    V10(IdentityDocumentV10),
}

impl Document for IdentityDocument {
    type PublicKey = PubKey;

    #[inline]
    fn version(&self) -> usize {
        match self {
            IdentityDocument::V10(idty_v10) => idty_v10.version(),
        }
    }

    #[inline]
    fn currency(&self) -> &str {
        match self {
            IdentityDocument::V10(idty_v10) => idty_v10.currency(),
        }
    }

    #[inline]
    fn blockstamp(&self) -> Blockstamp {
        match self {
            IdentityDocument::V10(idty_v10) => idty_v10.blockstamp(),
        }
    }

    #[inline]
    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        match self {
            IdentityDocument::V10(idty_v10) => svec![PubKey::Ed25519(idty_v10.issuers()[0])],
        }
    }

    #[inline]
    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        match self {
            IdentityDocument::V10(idty_v10) => svec![Sig::Ed25519(idty_v10.signatures()[0])],
        }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        match self {
            IdentityDocument::V10(idty_v10) => idty_v10.as_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IdentityDocumentStringified {
    V10(IdentityDocumentV10Stringified),
}

impl ToStringObject for IdentityDocument {
    type StringObject = IdentityDocumentStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            IdentityDocument::V10(idty) => {
                IdentityDocumentStringified::V10(idty.to_string_object())
            }
        }
    }
}
