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

//! Wrappers around Membership documents v10.

use crate::*;

/// Type of a Membership.
#[derive(Debug, Deserialize, Clone, Copy, Hash, Serialize, PartialEq, Eq)]
pub enum MembershipType {
    /// The member wishes to opt-in.
    In(),
    /// The member wishes to opt-out.
    Out(),
}

/// Wrap an Membership document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct MembershipDocumentV10 {
    /// Document as text.
    ///
    /// Is used to check signatures, and other values mut be extracted from it.
    text: Option<String>,

    /// Name of the currency.
    currency: String,
    /// Document issuer.
    issuer: ed25519::PublicKey,
    /// Blockstamp
    blockstamp: Blockstamp,
    /// Membership message.
    membership: MembershipType,
    /// Identity to use for this public key.
    identity_username: String,
    /// Identity document blockstamp.
    identity_blockstamp: Blockstamp,
    /// Document signature.
    signature: ed25519::Signature,
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// identity document for jsonification
pub struct MembershipDocumentV10Stringified {
    /// Currency.
    pub currency: String,
    /// Document issuer
    pub issuer: String,
    /// Blockstamp
    pub blockstamp: String,
    /// Membership message.
    pub membership: String,
    /// Unique ID
    pub username: String,
    /// Identity document blockstamp.
    pub identity_blockstamp: String,
    /// Document signature
    pub signature: String,
}

impl ToStringObject for MembershipDocumentV10 {
    type StringObject = MembershipDocumentV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> MembershipDocumentV10Stringified {
        MembershipDocumentV10Stringified {
            currency: self.currency.clone(),
            issuer: self.issuer.to_base58(),
            blockstamp: format!("{}", self.blockstamp),
            membership: match self.membership {
                MembershipType::In() => "IN".to_owned(),
                MembershipType::Out() => "OUT".to_owned(),
            },
            username: self.identity_username.clone(),
            identity_blockstamp: format!("{}", self.identity_blockstamp),
            signature: self.signature.to_base64(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Hash, Deserialize, Serialize)]
/// Membership event type (blockchain event)
pub enum MembershipEventType {
    /// Newcomer
    Join(),
    /// Renewal
    Renewal(),
    /// Renewal after expire or leave
    Rejoin(),
    /// Expire
    Expire(),
}

#[derive(Debug, Clone, PartialEq, Hash, Deserialize, Serialize)]
/// Membership event (blockchain event)
pub struct MembershipEvent {
    /// Blockstamp of block event
    pub blockstamp: Blockstamp,
    /// Membership document
    pub doc: MembershipDocumentV10,
    /// Event type
    pub event_type: MembershipEventType,
    /// Chainable time
    pub chainable_on: u64,
}

impl MembershipDocumentV10 {
    /// Membership message.
    pub fn membership(&self) -> MembershipType {
        self.membership
    }

    /// Identity to use for this public key.
    pub fn identity_username(&self) -> &str {
        &self.identity_username
    }

    /// Lightens the membership (for example to store it while minimizing the space required)
    pub fn reduce(&mut self) {
        self.text = None;
    }
}

impl Document for MembershipDocumentV10 {
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

    fn as_bytes(&self) -> &[u8] {
        self.as_text_without_signature().as_bytes()
    }
}

impl CompactTextDocument for MembershipDocumentV10 {
    fn as_compact_text(&self) -> String {
        format!(
            "{issuer}:{signature}:{blockstamp}:{idty_blockstamp}:{username}",
            issuer = self.issuer,
            signature = self.signature,
            blockstamp = self.blockstamp,
            idty_blockstamp = self.identity_blockstamp,
            username = self.identity_username,
        )
    }
}

/// CompactPoolMembershipDoc
#[derive(Copy, Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
pub struct CompactPoolMembershipDoc {
    /// Document creation blockstamp
    pub blockstamp: Blockstamp,
    /// Signature
    pub signature: Sig,
}

impl TextDocument for MembershipDocumentV10 {
    type CompactTextDocument_ = MembershipDocumentV10;

    fn as_text(&self) -> &str {
        if let Some(ref text) = self.text {
            text
        } else {
            panic!("Try to get text of reduce membership !")
        }
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Borrowed(self)
    }
}

/// Membership document builder.
#[derive(Debug, Copy, Clone)]
pub struct MembershipDocumentV10Builder<'a> {
    /// Document currency.
    pub currency: &'a str,
    /// Document/identity issuer.
    pub issuer: ed25519::PublicKey,
    /// Reference blockstamp.
    pub blockstamp: Blockstamp,
    /// Membership message.
    pub membership: MembershipType,
    /// Identity username.
    pub identity_username: &'a str,
    /// Identity document blockstamp.
    pub identity_blockstamp: Blockstamp,
}

impl<'a> TextDocumentBuilder for MembershipDocumentV10Builder<'a> {
    type Document = MembershipDocumentV10;
    type Signator = ed25519::Signator;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> MembershipDocumentV10 {
        MembershipDocumentV10 {
            text: Some(text),
            currency: self.currency.to_string(),
            issuer: self.issuer,
            blockstamp: self.blockstamp,
            membership: self.membership,
            identity_username: self.identity_username.to_string(),
            identity_blockstamp: self.identity_blockstamp,
            signature: signatures[0],
        }
    }

    fn generate_text(&self) -> String {
        format!(
            "Version: 10
Type: Membership
Currency: {currency}
Issuer: {issuer}
Block: {blockstamp}
Membership: {membership}
UserID: {username}
CertTS: {ity_blockstamp}
",
            currency = self.currency,
            issuer = self.issuer,
            blockstamp = self.blockstamp,
            membership = match self.membership {
                MembershipType::In() => "IN",
                MembershipType::Out() => "OUT",
            },
            username = self.identity_username,
            ity_blockstamp = self.identity_blockstamp,
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
                "cUgoc8AI+Tae/AZmRfTnW+xq3XFtmYoUi2LXlmXr8/7LaXiUccQb8+Ds1nZoBp/8+t031HMwqAUpVIqww2FGCg==",
            ), "fail to build Signature");

        let blockstamp = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "fail to build Blockstamp"
        );

        let builder = MembershipDocumentV10Builder {
            currency: "duniter_unit_test_currency",
            issuer: pubkey,
            blockstamp,
            membership: MembershipType::In(),
            identity_username: "tic",
            identity_blockstamp: blockstamp,
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
