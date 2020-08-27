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

//! Wrappers around Membership documents.

pub mod v10;

pub use v10::{
    MembershipDocumentV10, MembershipDocumentV10Builder, MembershipDocumentV10Stringified,
    MembershipType,
};

use crate::*;

/// Wrap an Membership document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum MembershipDocument {
    V10(MembershipDocumentV10),
}

impl Document for MembershipDocument {
    type PublicKey = PubKey;

    #[inline]
    fn version(&self) -> usize {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.version(),
        }
    }

    #[inline]
    fn currency(&self) -> &str {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.currency(),
        }
    }

    #[inline]
    fn blockstamp(&self) -> Blockstamp {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.blockstamp(),
        }
    }

    #[inline]
    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        match self {
            MembershipDocument::V10(ms_v10) => svec![PubKey::Ed25519(ms_v10.issuers()[0])],
        }
    }

    #[inline]
    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        match self {
            MembershipDocument::V10(ms_v10) => svec![Sig::Ed25519(ms_v10.signatures()[0])],
        }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.as_bytes(),
        }
    }
}

impl CompactTextDocument for MembershipDocument {
    fn as_compact_text(&self) -> String {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.as_compact_text(),
        }
    }
}

impl TextDocument for MembershipDocument {
    type CompactTextDocument_ = MembershipDocument;

    fn as_text(&self) -> &str {
        match self {
            MembershipDocument::V10(ms_v10) => ms_v10.as_text(),
        }
    }

    fn to_compact_document(&self) -> Self::CompactTextDocument_ {
        match self {
            MembershipDocument::V10(ms_v10) => {
                MembershipDocument::V10(ms_v10.to_compact_document())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MembershipDocumentStringified {
    V10(MembershipDocumentV10Stringified),
}

impl ToStringObject for MembershipDocument {
    type StringObject = MembershipDocumentStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            MembershipDocument::V10(idty) => {
                MembershipDocumentStringified::V10(idty.to_string_object())
            }
        }
    }
}
