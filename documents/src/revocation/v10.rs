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

//! Wrappers around Revocation documents V//  Copyright (C) 2020  Éloïs SANCHEZ.
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

//! Wrappers around Revocation documents V10.

use crate::*;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// Wrap an Compact Revocation document (in block content)
pub struct CompactRevocationDocumentV10 {
    /// Issuer
    pub issuer: ed25519::PublicKey,
    /// Signature
    pub signature: ed25519::Signature,
}

impl CompactTextDocument for CompactRevocationDocumentV10 {
    fn as_compact_text(&self) -> String {
        format!(
            "{issuer}:{signature}",
            issuer = self.issuer,
            signature = self.signature,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// Revocation document for jsonification
pub struct CompactRevocationDocumentV10Stringified {
    /// Document issuer
    pub issuer: String,
    /// Document signature
    pub signature: String,
}

impl ToStringObject for CompactRevocationDocumentV10 {
    type StringObject = CompactRevocationDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> CompactRevocationDocumentV10Stringified {
        CompactRevocationDocumentV10Stringified {
            issuer: format!("{}", self.issuer),
            signature: format!("{}", self.signature),
        }
    }
}

/// Wrap an Revocation document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RevocationDocumentV10 {
    /// Document as text.
    ///
    /// Is used to check signatures, and other values mut be extracted from it.
    text: String,

    /// Name of the currency.
    currency: String,
    /// Document issuer.
    issuer: ed25519::PublicKey,
    /// Username of target identity.
    identity_username: String,
    /// Target Identity document blockstamp.
    identity_blockstamp: Blockstamp,
    /// Target Identity document signature.
    identity_sig: ed25519::Signature,
    /// Document signature.
    signature: ed25519::Signature,
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// Revocation document for jsonification
pub struct RevocationDocumentV10Stringified {
    /// Name of the currency.
    currency: String,
    /// Document issuer
    issuer: String,
    /// Username of target identity
    identity_username: String,
    /// Target Identity document blockstamp.
    identity_blockstamp: String,
    /// Target Identity document signature.
    identity_sig: String,
    /// Document signature
    signature: String,
}

impl ToStringObject for RevocationDocumentV10 {
    type StringObject = RevocationDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> RevocationDocumentV10Stringified {
        RevocationDocumentV10Stringified {
            currency: self.currency.clone(),
            issuer: self.issuer.to_base58(),
            identity_username: self.identity_username.clone(),
            identity_blockstamp: format!("{}", self.identity_blockstamp),
            identity_sig: format!("{}", self.identity_sig),
            signature: self.signature.to_base64(),
        }
    }
}

impl RevocationDocumentV10 {
    /// Username of target identity
    pub fn identity_username(&self) -> &str {
        &self.identity_username
    }
}

impl Document for RevocationDocumentV10 {
    type PublicKey = ed25519::PublicKey;

    fn version(&self) -> usize {
        10
    }

    fn currency(&self) -> &str {
        &self.currency
    }

    fn blockstamp(&self) -> Blockstamp {
        unimplemented!()
    }

    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        svec![self.issuer]
    }

    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        svec![self.signature]
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_text_without_signature().as_bytes()
    }
}

impl TextDocument for RevocationDocumentV10 {
    type CompactTextDocument_ = CompactRevocationDocumentV10;

    fn as_text(&self) -> &str {
        &self.text
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Owned(CompactRevocationDocumentV10 {
            issuer: self.issuer,
            signature: self.signature,
        })
    }
}

/// Revocation document builder.
#[derive(Debug, Copy, Clone)]
pub struct RevocationDocumentV10Builder<'a> {
    /// Document currency.
    pub currency: &'a str,
    /// Revocation issuer.
    pub issuer: ed25519::PublicKey,
    /// Username of target Identity.
    pub identity_username: &'a str,
    /// Blockstamp of target Identity.
    pub identity_blockstamp: Blockstamp,
    /// Signature of target Identity.
    pub identity_sig: ed25519::Signature,
}

impl<'a> TextDocumentBuilder for RevocationDocumentV10Builder<'a> {
    type Document = RevocationDocumentV10;
    type Signator = ed25519::Signator;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> RevocationDocumentV10 {
        RevocationDocumentV10 {
            text,
            currency: self.currency.to_string(),
            issuer: self.issuer,
            identity_username: self.identity_username.to_string(),
            identity_blockstamp: self.identity_blockstamp,
            identity_sig: self.identity_sig,
            signature: signatures[0],
        }
    }

    fn generate_text(&self) -> String {
        format!(
            "Version: 10
Type: Revocation
Currency: {currency}
Issuer: {issuer}
IdtyUniqueID: {idty_uid}
IdtyTimestamp: {idty_blockstamp}
IdtySignature: {idty_sig}
",
            currency = self.currency,
            issuer = self.issuer,
            idty_uid = self.identity_username,
            idty_blockstamp = self.identity_blockstamp,
            idty_sig = self.identity_sig,
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
            "gBD2mCr7E/tW8u3wqVK7IWtQB6IKxddg13UMl9ypVsv/VhqhAFTBba9BwoK5t6H9eqF1d+4sCB3WY2eJ/yuUAg==",
        ), "Fail to build Signature");

        let identity_blockstamp = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "Fail to build Blockstamp"
        );

        let identity_sig = unwrap!(ed25519::Signature::from_base64(
            "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==",
        ), "Fail to build Signature");

        let builder = RevocationDocumentV10Builder {
            currency: "g1",
            issuer: pubkey,
            identity_username: "tic",
            identity_blockstamp,
            identity_sig,
        };

        println!(
            "Signatures = {:?}",
            builder
                .build_and_sign(vec![keypair.generate_signator()])
                .signatures()
        );

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
