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

//! Wrappers around transaction document v10 unsigned.

use super::*;

/// Wrap an unsigned transaction document v10.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UnsignedTransactionDocumentV10 {
    /// Document as text.
    ///
    /// Is used to generate signatures
    pub(super) text: String,

    /// Currency.
    pub(super) currency: String,
    /// Blockstamp
    pub(super) blockstamp: Blockstamp,
    /// Locktime
    pub(super) locktime: u64,
    /// Document issuers.
    pub(super) issuers: SmallVec<[ed25519::PublicKey; 1]>,
    /// Transaction inputs.
    pub(super) inputs: Vec<TransactionInputV10>,
    /// Inputs unlocks.
    pub(super) unlocks: Vec<TransactionInputUnlocksV10>,
    /// Transaction outputs.
    pub(super) outputs: SmallVec<[TransactionOutputV10; 2]>,
    /// Transaction comment
    pub(super) comment: String,
    /// Document optional signatures.
    pub(super) signatures_opt: SmallVec<[Option<ed25519::Signature>; 1]>,
}

impl<'a> UnsignedTransactionDocumentTrait<'a> for UnsignedTransactionDocumentV10 {
    type PubKey = ed25519::PublicKey;
    type SignedDoc = TransactionDocumentV10;

    fn as_text(&self) -> &str {
        self.text.as_str()
    }

    fn sign<S: Signator<PublicKey = Self::PubKey>>(
        mut self,
        signator: &S,
    ) -> Result<SignedOrUnsignedDocument<Self::SignedDoc, Self>, TransactionSignErr> {
        while self.signatures_opt.len() < self.issuers.len() {
            self.signatures_opt.push(None);
        }

        let tx_bytes = self.text.as_bytes();
        let signator_pubkey = signator.public_key();

        let mut invalid_signatures = HashMap::new();
        let mut signator_in_issuers = false;
        let mut valid_signatures = SmallVec::new();
        for (i, issuer) in self.issuers.iter().enumerate() {
            if issuer == &signator_pubkey {
                let signature = signator.sign(tx_bytes);
                valid_signatures.insert(i, signature);
                self.signatures_opt[i] = Some(signature);
                signator_in_issuers = true;
            } else if let Some(signature) = self.signatures_opt[i] {
                if let Err(e) = issuer.verify(tx_bytes, &signature) {
                    invalid_signatures.insert(i, e);
                } else {
                    valid_signatures.insert(i, signature);
                }
            }
        }
        if !invalid_signatures.is_empty() {
            Err(TransactionSignErr::InvalidSignatures(invalid_signatures))
        } else if signator_in_issuers {
            if valid_signatures.len() == self.issuers.len() {
                let mut signed_doc = TransactionDocumentV10 {
                    text: Some(self.text),
                    currency: self.currency,
                    blockstamp: self.blockstamp,
                    locktime: self.locktime,
                    issuers: self.issuers,
                    inputs: self.inputs,
                    unlocks: self.unlocks,
                    outputs: self.outputs,
                    comment: self.comment,
                    signatures: valid_signatures,
                    hash: None,
                };
                let tx_hash = signed_doc.compute_hash();
                signed_doc.hash = Some(tx_hash);
                Ok(SignedOrUnsignedDocument::Signed(signed_doc))
            } else {
                Ok(SignedOrUnsignedDocument::Unsigned(self))
            }
        } else {
            Err(TransactionSignErr::InvalidSignator)
        }
    }
}
