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

//! Define DUBP Documents Traits.

pub mod text;

use crate::*;

/// trait providing commun methods for any documents of any protocol version.
pub trait Document: Debug + Clone + PartialEq + Eq {
    /// Type of the `PublicKey` used by the document.
    type PublicKey: PublicKey;

    /// Get document as bytes for signature verification.
    ///
    /// Some documents do not directly store the sequence of bytes that will be signed but generate
    // it on request, so these types of documents cannot provide a reference to the signed bytes.
    /// This is why this method must return a `Cow<[u8]>` (we use the beef implementation instead of the std implementation).
    fn as_bytes(&self) -> BeefCow<[u8]>;

    /// Get document blockstamp
    fn blockstamp(&self) -> Blockstamp;

    /// Get document currency name.
    fn currency(&self) -> &str;

    /// Iterate over document issuers.
    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]>;

    /// Iterate over document signatures.
    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]>;

    /// Verify one signature
    #[inline]
    fn verify_one_signature(
        &self,
        public_key: &Self::PublicKey,
        signature: &<Self::PublicKey as PublicKey>::Signature,
    ) -> Result<(), SigError> {
        public_key.verify(self.as_bytes().as_ref(), signature)
    }

    /// Verify signatures of document content
    fn verify_signatures(&self) -> Result<(), DocumentSigsErr> {
        let issuers_count = self.issuers().len();
        let signatures_count = self.signatures().len();

        if issuers_count != signatures_count {
            Err(DocumentSigsErr::IncompletePairs(
                issuers_count,
                signatures_count,
            ))
        } else {
            let issuers = self.issuers();
            let signatures = self.signatures();
            let mismatches: HashMap<usize, SigError> = issuers
                .iter()
                .zip(signatures)
                .enumerate()
                .filter_map(|(i, (key, signature))| {
                    if let Err(e) = self.verify_one_signature(key, &signature) {
                        Some((i, e))
                    } else {
                        None
                    }
                })
                .collect();

            if mismatches.is_empty() {
                Ok(())
            } else {
                Err(DocumentSigsErr::Invalid(mismatches))
            }
        }
    }

    /// Get document version.
    fn version(&self) -> usize;
}

/// Trait helper for building new documents.
pub trait DocumentBuilder {
    /// Type of the builded document.
    type Document: Document;

    /// Type of the signator signing the documents.
    type Signator: Signator<PublicKey = <Self::Document as Document>::PublicKey>;

    /// Build a document and sign it with the private key.
    fn build_and_sign(self, signators: Vec<Self::Signator>) -> Self::Document;

    /// Build a document with provided signatures.
    fn build_with_signature(
        self,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> Self::Document;
}

/// Stringify a document
pub trait ToStringObject {
    /// Generated string object
    type StringObject: Serialize;

    /// Transforms object fields into string
    fn to_string_object(&self) -> Self::StringObject;
}

/// Jsonify a document
pub trait ToJsonObject: ToStringObject {
    /// Convert to JSON String
    fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_string_object())
    }
    /// Convert to JSON String pretty
    fn to_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_string_object())
    }
}

impl<T: ToStringObject> ToJsonObject for T {}
