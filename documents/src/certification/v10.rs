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

//! Wrappers around Certification documents V10.

use crate::*;

#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
/// Wrap an Compact certification document (in block content)
pub struct CompactCertificationDocumentV10 {
    /// Issuer
    pub issuer: ed25519::PublicKey,
    /// Target
    pub target: ed25519::PublicKey,
    /// Blockstamp
    pub block_number: BlockNumber,
    /// Signature
    pub signature: ed25519::Signature,
}

impl CompactTextDocument for CompactCertificationDocumentV10 {
    fn as_compact_text(&self) -> String {
        format!(
            "{issuer}:{target}:{block_number}:{signature}",
            issuer = self.issuer,
            target = self.target,
            block_number = self.block_number.0,
            signature = self.signature,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// identity document for jsonification
pub struct CompactCertificationDocumentV10Stringified {
    /// Document issuer
    pub issuer: String,
    /// issuer of target identity.
    pub target: String,
    /// Block number
    pub block_number: u64,
    /// Document signature
    pub signature: String,
}

impl ToStringObject for CompactCertificationDocumentV10 {
    type StringObject = CompactCertificationDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> CompactCertificationDocumentV10Stringified {
        CompactCertificationDocumentV10Stringified {
            issuer: format!("{}", self.issuer),
            target: format!("{}", self.target),
            block_number: u64::from(self.block_number.0),
            signature: format!("{}", self.signature),
        }
    }
}

/// Wrap an Certification document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CertificationDocumentV10 {
    /// Document as text.
    ///
    /// Is used to check signatures, and other values mut be extracted from it.
    text: String,

    /// Name of the currency.
    currency: String,
    /// Document issuer
    issuer: ed25519::PublicKey,
    /// issuer of target identity.
    target: ed25519::PublicKey,
    /// Username of target identity
    identity_username: String,
    /// Target Identity document blockstamp.
    identity_blockstamp: Blockstamp,
    /// Target Identity document signature.
    identity_sig: ed25519::Signature,
    /// Blockstamp
    blockstamp: Blockstamp,
    /// Document signature
    signature: ed25519::Signature,
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// identity document for jsonification
pub struct CertificationDocumentV10Stringified {
    /// Name of the currency.
    currency: String,
    /// Document issuer
    issuer: String,
    /// issuer of target identity.
    target: String,
    /// Username of target identity
    identity_username: String,
    /// Target Identity document blockstamp.
    identity_blockstamp: String,
    /// Target Identity document signature.
    identity_sig: String,
    /// Blockstamp
    blockstamp: String,
    /// Document signature
    signature: String,
}

impl ToStringObject for CertificationDocumentV10 {
    type StringObject = CertificationDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> CertificationDocumentV10Stringified {
        CertificationDocumentV10Stringified {
            currency: self.currency.clone(),
            issuer: self.issuer.to_base58(),
            target: format!("{}", self.target),
            identity_username: self.identity_username.clone(),
            identity_blockstamp: format!("{}", self.identity_blockstamp),
            blockstamp: format!("{}", self.blockstamp),
            identity_sig: format!("{}", self.identity_sig),
            signature: format!("{}", self.signature),
        }
    }
}

impl CertificationDocumentV10 {
    /// Username of target identity
    pub fn identity_username(&self) -> &str {
        &self.identity_username
    }

    /// PubKey of source identity
    pub fn source(&self) -> &ed25519::PublicKey {
        &self.issuer
    }

    /// PubKey of target identity
    pub fn target(&self) -> &ed25519::PublicKey {
        &self.target
    }
}

impl Document for CertificationDocumentV10 {
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

impl TextDocument for CertificationDocumentV10 {
    type CompactTextDocument_ = CompactCertificationDocumentV10;

    fn as_text(&self) -> &str {
        &self.text
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Owned(CompactCertificationDocumentV10 {
            issuer: self.issuer,
            target: self.target,
            block_number: self.blockstamp().number,
            signature: self.signatures()[0],
        })
    }
}

/// Certification document builder.
#[derive(Debug, Copy, Clone)]
pub struct CertificationDocumentV10Builder<'a> {
    /// Document currency.
    pub currency: &'a str,
    /// Certification issuer (=source).
    pub issuer: ed25519::PublicKey,
    /// Reference blockstamp.
    pub blockstamp: Blockstamp,
    /// PubKey of target identity.
    pub target: ed25519::PublicKey,
    /// Username of target Identity.
    pub identity_username: &'a str,
    /// Blockstamp of target Identity.
    pub identity_blockstamp: Blockstamp,
    /// Signature of target Identity.
    pub identity_sig: ed25519::Signature,
}

impl<'a> TextDocumentBuilder for CertificationDocumentV10Builder<'a> {
    type Document = CertificationDocumentV10;
    type Signator = ed25519::Signator;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> CertificationDocumentV10 {
        CertificationDocumentV10 {
            text,
            currency: self.currency.to_string(),
            issuer: self.issuer,
            blockstamp: self.blockstamp,
            target: self.target,
            identity_username: self.identity_username.to_string(),
            identity_blockstamp: self.identity_blockstamp,
            identity_sig: self.identity_sig,
            signature: signatures[0],
        }
    }

    fn generate_text(&self) -> String {
        format!(
            "Version: 10
Type: Certification
Currency: {currency}
Issuer: {issuer}
IdtyIssuer: {target}
IdtyUniqueID: {idty_uid}
IdtyTimestamp: {idty_blockstamp}
IdtySignature: {idty_sig}
CertTimestamp: {blockstamp}
",
            currency = self.currency,
            issuer = self.issuer,
            target = self.target,
            idty_uid = self.identity_username,
            idty_blockstamp = self.identity_blockstamp,
            idty_sig = self.identity_sig,
            blockstamp = self.blockstamp,
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
    fn generate_real_certification_document() {
        let seed = unwrap!(
            Seed32::from_base58("4tNQ7d9pj2Da5wUVoW9mFn7JjuPoowF977au8DdhEjVR"),
            "fail to build Seed32"
        );
        let keypair = ed25519::KeyPairFromSeed32Generator::generate(seed);
        let pubkey = keypair.public_key();
        let signator = keypair.generate_signator();

        let sig = unwrap!(ed25519::Signature::from_base64(
            "sYbaZp3pP9F/CveT1LPiJXECTBHlNurDXqmBo71N7JX/rvmHw6m/sid9bGdIa8cUq+vDD4DMB/F7r7As1p4rAg==",
        ), "Fail to build Signature");

        let target = unwrap!(
            ed25519::PublicKey::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"),
            "Fail to build PublicKey"
        );

        let identity_blockstamp = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "Fail to build Blockstamp"
        );

        let identity_sig = unwrap!(ed25519::Signature::from_base64(
            "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==",
        ), "Fail to build Signature");

        let blockstamp = unwrap!(
            Blockstamp::from_str(
                "36-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B865",
            ),
            "Fail to build Blockstamp"
        );

        let builder = CertificationDocumentV10Builder {
            currency: "duniter_unit_test_currency",
            issuer: pubkey,
            target,
            identity_username: "tic",
            identity_blockstamp,
            identity_sig,
            blockstamp,
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
