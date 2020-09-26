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

//! Wrappers around Identity documents V10.

use crate::*;

/// Wrap an Identity document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
pub struct IdentityDocumentV10 {
    /// Document as text.
    ///
    /// Is used to check signatures, and other values
    /// must be extracted from it.
    text: Option<String>,

    /// Currency.
    currency: String,
    /// Unique ID
    username: String,
    /// Blockstamp
    blockstamp: Blockstamp,
    /// Document issuer (there should be only one).
    issuer: ed25519::PublicKey,
    /// Document signature (there should be only one).
    signature: ed25519::Signature,
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// identity document for jsonification
pub struct IdentityDocumentV10Stringified {
    /// Currency.
    pub currency: String,
    /// Unique ID
    pub username: String,
    /// Blockstamp
    pub blockstamp: String,
    /// Document issuer
    pub issuer: String,
    /// Document signature
    pub signature: String,
}

impl ToStringObject for IdentityDocumentV10 {
    type StringObject = IdentityDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> IdentityDocumentV10Stringified {
        IdentityDocumentV10Stringified {
            currency: self.currency.clone(),
            username: self.username.clone(),
            blockstamp: format!("{}", self.blockstamp),
            issuer: self.issuer.to_base58(),
            signature: self.signature.to_base64(),
        }
    }
}

impl IdentityDocumentV10 {
    /// Unique ID
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Lightens the identity (for example to store it while minimizing the space required)
    pub fn reduce(&mut self) {
        self.text = None;
    }
}

impl Document for IdentityDocumentV10 {
    type PublicKey = ed25519::PublicKey;

    fn version(&self) -> usize {
        10
    }

    fn currency(&self) -> &str {
        &self.currency
    }

    fn blockstamp(&self) -> Blockstamp {
        self.blockstamp
    }

    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        svec![self.issuer]
    }

    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        svec![self.signature]
    }

    fn as_bytes(&self) -> BeefCow<[u8]> {
        BeefCow::borrowed(self.as_text().as_bytes())
    }
}

/// CompactIdentityDocumentV10
#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
pub struct CompactIdentityDocumentV10 {
    /// Unique ID
    username: String,
    /// Blockstamp
    blockstamp: Blockstamp,
    /// Document issuer
    pubkey: ed25519::PublicKey,
    /// Document signature
    signature: ed25519::Signature,
}

impl CompactTextDocument for CompactIdentityDocumentV10 {
    fn as_compact_text(&self) -> String {
        format!(
            "{issuer}:{signature}:{blockstamp}:{username}",
            issuer = self.pubkey,
            signature = self.signature,
            blockstamp = self.blockstamp,
            username = self.username,
        )
    }
}

impl TextDocument for IdentityDocumentV10 {
    type CompactTextDocument_ = CompactIdentityDocumentV10;

    fn as_text(&self) -> &str {
        if let Some(ref text) = self.text {
            text
        } else {
            panic!("Try to get text of reduce identity !")
        }
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Owned(CompactIdentityDocumentV10 {
            username: self.username.clone(),
            blockstamp: self.blockstamp,
            pubkey: self.issuer,
            signature: self.signature,
        })
    }
}

/// Identity document builder.
#[derive(Debug, Copy, Clone)]
pub struct IdentityDocumentV10Builder<'a> {
    /// Document currency.
    pub currency: &'a str,
    /// Identity unique id.
    pub username: &'a str,
    /// Reference blockstamp.
    pub blockstamp: Blockstamp,
    /// Document/identity issuer.
    pub issuer: ed25519::PublicKey,
}

impl<'a> TextDocumentBuilder for IdentityDocumentV10Builder<'a> {
    type Document = IdentityDocumentV10;
    type Signator = ed25519::Signator;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> IdentityDocumentV10 {
        IdentityDocumentV10 {
            text: Some(text),
            currency: self.currency.to_string(),
            username: self.username.to_string(),
            blockstamp: self.blockstamp,
            issuer: self.issuer,
            signature: signatures[0],
        }
    }

    fn generate_text(&self) -> String {
        format!(
            "Version: 10
Type: Identity
Currency: {currency}
Issuer: {issuer}
UniqueID: {username}
Timestamp: {blockstamp}
",
            currency = self.currency,
            issuer = self.issuer,
            username = self.username,
            blockstamp = self.blockstamp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use std::str::FromStr;
    use unwrap::unwrap;

    #[test]
    fn generate_real_document() {
        let keypair = ed25519::KeyPairFromSeed32Generator::generate(unwrap!(
            Seed32::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"),
            "fail to build Seed32"
        ));
        let pubkey = keypair.public_key();
        let signator = keypair.generate_signator();

        let sig = unwrap!(ed25519::Signature::from_base64(
                "mmFepRsiOjILKnCvEvN3IZScLOfg8+e0JPAl5VkiuTLZRGJKgKhPy8nQlCKbeg0jefQm/2HJ78e/Sj+NMqYLCw==",
            ), "fail to build Signature");

        let blockstamp = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "fail to build Blockstamp"
        );

        let builder = IdentityDocumentV10Builder {
            currency: "duniter_unit_test_currency",
            username: "tic",
            blockstamp,
            issuer: pubkey,
        };

        assert!(builder
            .build_with_signature(smallvec![sig])
            .verify_signatures()
            .is_ok());
        assert!(builder
            .build_and_sign(vec![signator])
            .verify_signatures()
            .is_ok());
    }
}
