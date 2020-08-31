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

//! Wrappers around Transaction documents.

pub mod v10;

use crate::*;

pub use v10::{
    TransactionDocumentV10, TransactionDocumentV10Builder, TransactionDocumentV10Stringified,
    TransactionInputV10, TransactionOutputV10,
};

/// Wrap an utxo conditions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct UTXOConditions {
    /// We are obliged to allow the introduction of the original text (instead of the self-generated text),
    /// because the original text may contain errors that are unfortunately allowed by duniter-ts.
    pub origin_str: Option<String>,
    /// Store script conditions
    pub script: WalletScriptV10,
}

impl From<WalletScriptV10> for UTXOConditions {
    fn from(script: WalletScriptV10) -> Self {
        UTXOConditions {
            origin_str: None,
            script,
        }
    }
}

impl UTXOConditions {
    /// Lightens the UTXOConditions (for example to store it while minimizing the space required)
    pub fn reduce(&mut self) {
        if self.check() {
            self.origin_str = None;
        }
    }
    /// Check validity of this UTXOConditions
    pub fn check(&self) -> bool {
        if let Some(ref origin_str) = self.origin_str {
            origin_str == self.script.to_string().as_str()
        } else {
            true
        }
    }
}

impl ToString for UTXOConditions {
    fn to_string(&self) -> String {
        if let Some(ref origin_str) = self.origin_str {
            origin_str.to_string()
        } else {
            self.script.to_string()
        }
    }
}

pub trait TransactionDocumentTrait<'a> {
    type Input: 'a;
    type Inputs: AsRef<[Self::Input]>;
    type Output: 'a;
    type Outputs: AsRef<[Self::Output]>;
    fn get_inputs(&'a self) -> Self::Inputs;
    fn get_outputs(&'a self) -> Self::Outputs;
}

/// Wrap a Transaction document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum TransactionDocument {
    V10(TransactionDocumentV10),
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// Transaction document stringifed
pub enum TransactionDocumentStringified {
    V10(TransactionDocumentV10Stringified),
}

impl ToStringObject for TransactionDocument {
    type StringObject = TransactionDocumentStringified;

    fn to_string_object(&self) -> TransactionDocumentStringified {
        match self {
            TransactionDocument::V10(tx_v10) => {
                TransactionDocumentStringified::V10(tx_v10.to_string_object())
            }
        }
    }
}

impl TransactionDocument {
    /// Compute transaction hash
    pub fn compute_hash(&self) -> Hash {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.compute_hash(),
        }
    }
    /// get transaction hash option
    pub fn get_hash_opt(&self) -> Option<Hash> {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.get_hash_opt(),
        }
    }
    /// Get transaction hash
    pub fn get_hash(&mut self) -> Hash {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.get_hash(),
        }
    }
    /// Lightens the transaction (for example to store it while minimizing the space required)
    /// WARNING: do not remove the hash as it's necessary to reverse the transaction !
    pub fn reduce(&mut self) {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.reduce(),
        };
    }
}

impl Document for TransactionDocument {
    type PublicKey = PubKey;

    fn version(&self) -> usize {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.version(),
        }
    }

    fn currency(&self) -> &str {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.currency(),
        }
    }

    fn blockstamp(&self) -> Blockstamp {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.blockstamp(),
        }
    }

    fn issuers(&self) -> SmallVec<[Self::PublicKey; 1]> {
        match self {
            TransactionDocument::V10(tx_v10) => svec![PubKey::Ed25519(tx_v10.issuers()[0])],
        }
    }

    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        match self {
            TransactionDocument::V10(tx_v10) => svec![Sig::Ed25519(tx_v10.signatures()[0])],
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.as_bytes(),
        }
    }
}

impl CompactTextDocument for TransactionDocument {
    fn as_compact_text(&self) -> String {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.as_compact_text(),
        }
    }
}

impl TextDocument for TransactionDocument {
    type CompactTextDocument_ = TransactionDocument;

    fn as_text(&self) -> &str {
        match self {
            TransactionDocument::V10(tx_v10) => tx_v10.as_text(),
        }
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Borrowed(self)
    }
}

/// Transaction document builder.
#[derive(Debug, Clone)]
pub enum TransactionDocumentBuilder<'a> {
    V10(TransactionDocumentV10Builder<'a>),
}

impl<'a> TextDocumentBuilder for TransactionDocumentBuilder<'a> {
    type Document = TransactionDocument;
    type Signator = SignatorEnum;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> TransactionDocument {
        match self {
            TransactionDocumentBuilder::V10(tx_v10_builder) => TransactionDocument::V10(
                tx_v10_builder.build_with_text_and_sigs(
                    text,
                    signatures
                        .into_iter()
                        .filter_map(|sig| {
                            if let Sig::Ed25519(sig) = sig {
                                Some(sig)
                            } else {
                                None
                            }
                        })
                        .collect(),
                ),
            ),
        }
    }

    fn generate_text(&self) -> String {
        match self {
            TransactionDocumentBuilder::V10(tx_v10_builder) => tx_v10_builder.generate_text(),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use smallvec::smallvec;
    use std::str::FromStr;
    use unwrap::unwrap;
    use v10::{TransactionInputUnlocksV10, TransactionOutputV10};

    pub(super) fn tx_output_v10(amount: isize, recv: &str) -> TransactionOutputV10 {
        TransactionOutputV10 {
            amount: SourceAmount::with_base0(amount),
            conditions: UTXOConditions::from(WalletScriptV10::single(WalletConditionV10::Sig(
                unwrap!(ed25519::PublicKey::from_base58(recv)),
            ))),
        }
    }

    #[test]
    fn generate_real_document() {
        let keypair = ed25519::KeyPairFromSeed32Generator::generate(unwrap!(
            Seed32::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"),
            "Fail to parse Seed32"
        ));
        let pubkey = keypair.public_key();
        let signator = keypair.generate_signator();

        let sig = unwrap!(ed25519::Signature::from_base64(
            "cq86RugQlqAEyS8zFkB9o0PlWPSb+a6D/MEnLe8j+okyFYf/WzI6pFiBkQ9PSOVn5I0dwzVXg7Q4N1apMWeGAg==",
        ), "Fail to parse Signature");

        let blockstamp = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "Fail to parse blockstamp"
        );

        let builder = TransactionDocumentV10Builder {
            currency: "duniter_unit_test_currency",
            blockstamp,
            locktime: 0,
            issuers: &[pubkey],
            inputs: &[TransactionInputV10 {
                amount: SourceAmount::with_base0(10),
                id: SourceIdV10::Ud(UdSourceIdV10 {
                    issuer: unwrap!(
                        ed25519::PublicKey::from_base58(
                            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"
                        ),
                        "Fail to parse PublicKey"
                    ),
                    block_number: BlockNumber(0),
                }),
            }],
            unlocks: &[TransactionInputUnlocksV10 {
                index: 0,
                unlocks: vec![WalletUnlockProofV10::Sig(0)],
            }],
            outputs: smallvec![tx_output_v10(
                10,
                "FD9wujR7KABw88RyKEGBYRLz8PA6jzVCbcBAsrBXBqSa",
            )],
            comment: "test",
            hash: None,
        };
        assert!(builder
            .clone()
            .build_with_signature(svec![sig])
            .verify_signatures()
            .is_ok());
        assert!(builder
            .build_and_sign(vec![signator])
            .verify_signatures()
            .is_ok());
    }

    #[test]
    fn compute_transaction_hash() {
        let pubkey = unwrap!(
            ed25519::PublicKey::from_base58("FEkbc4BfJukSWnCU6Hed6dgwwTuPFTVdgz5LpL4iHr9J"),
            "Fail to parse PublicKey"
        );

        let sig = unwrap!(ed25519::Signature::from_base64(
            "XEwKwKF8AI1gWPT7elR4IN+bW3Qn02Dk15TEgrKtY/S2qfZsNaodsLofqHLI24BBwZ5aadpC88ntmjo/UW9oDQ==",
        ), "Fail to parse Signature");

        let blockstamp = unwrap!(
            Blockstamp::from_str(
                "60-00001FE00410FCD5991EDD18AA7DDF15F4C8393A64FA92A1DB1C1CA2E220128D",
            ),
            "Fail to parse Blockstamp"
        );

        let builder = TransactionDocumentV10Builder {
            currency: "g1",
            blockstamp,
            locktime: 0,
            issuers: &[pubkey],
            inputs: &[TransactionInputV10 {
                amount: SourceAmount::with_base0(950),
                id: SourceIdV10::Utxo(UtxoIdV10 {
                    tx_hash: unwrap!(Hash::from_hex(
                        "2CF1ACD8FE8DC93EE39A1D55881C50D87C55892AE8E4DB71D4EBAB3D412AA8FD"
                    )),
                    output_index: 1,
                }),
            }],
            unlocks: &[TransactionInputUnlocksV10::default()],
            outputs: smallvec![
                tx_output_v10(30, "38MEAZN68Pz1DTvT3tqgxx4yQP6snJCQhPqEFxbDk4aE"),
                tx_output_v10(920, "FEkbc4BfJukSWnCU6Hed6dgwwTuPFTVdgz5LpL4iHr9J"),
            ],
            comment: "Pour cesium merci",
            hash: None,
        };
        let mut tx_doc = TransactionDocument::V10(builder.build_with_signature(svec![sig]));
        assert!(tx_doc.verify_signatures().is_ok());
        assert!(tx_doc.get_hash_opt().is_none());
        assert_eq!(
            tx_doc.get_hash(),
            Hash::from_hex("876D2430E0B66E2CE4467866D8F923D68896CACD6AA49CDD8BDD0096B834DEF1")
                .expect("fail to parse hash")
        );
    }
}
