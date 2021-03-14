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

use crate::*;

/// Wrap a transaction input
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionInputV10 {
    pub amount: SourceAmount,
    pub id: SourceIdV10,
}

impl ToString for TransactionInputV10 {
    fn to_string(&self) -> String {
        match self.id {
            SourceIdV10::Ud(UdSourceIdV10 {
                issuer,
                block_number,
            }) => format!(
                "{}:{}:D:{}:{}",
                self.amount.amount(),
                self.amount.base(),
                issuer,
                block_number.0
            ),
            SourceIdV10::Utxo(UtxoIdV10 {
                tx_hash,
                output_index,
            }) => format!(
                "{}:{}:T:{}:{}",
                self.amount.amount(),
                self.amount.base(),
                tx_hash,
                output_index
            ),
        }
    }
}

const TX_V10_MAX_LINES: usize = 100;

impl<'a> TransactionDocumentTrait<'a> for TransactionDocumentV10 {
    type Address = WalletScriptV10;
    type Input = TransactionInputV10;
    type Inputs = &'a [TransactionInputV10];
    type InputUnlocks = TransactionInputUnlocksV10;
    type InputsUnlocks = &'a [TransactionInputUnlocksV10];
    type Output = TransactionOutputV10;
    type Outputs = &'a [TransactionOutputV10];
    type PubKey = ed25519::PublicKey;

    fn generate_simple_txs(
        blockstamp: Blockstamp,
        currency: String,
        inputs_with_sum: (Vec<Self::Input>, SourceAmount),
        issuer: Self::PubKey,
        recipient: Self::PubKey,
        user_amount_and_comment: (SourceAmount, String),
        cash_back_pubkey: Option<ed25519::PublicKey>,
    ) -> Vec<Self> {
        let (inputs, inputs_sum) = inputs_with_sum;
        let (user_amount, user_comment) = user_amount_and_comment;
        super::v10_gen::TransactionDocV10SimpleGen {
            blockstamp,
            currency,
            inputs,
            inputs_sum,
            issuer,
            recipient,
            user_amount,
            user_comment,
            cash_back_pubkey,
        }
        .gen()
    }
    fn get_inputs(&'a self) -> Self::Inputs {
        &self.inputs
    }
    fn get_inputs_unlocks(&'a self) -> Self::InputsUnlocks {
        &self.unlocks
    }
    fn get_outputs(&'a self) -> Self::Outputs {
        &self.outputs
    }

    fn verify(&self, expected_currency_opt: Option<&str>) -> Result<(), super::TxVerifyErr> {
        if let Some(expected_currency) = expected_currency_opt {
            if self.currency != expected_currency {
                return Err(super::TxVerifyErr::WrongCurrency {
                    expected: expected_currency.to_owned(),
                    found: self.currency.clone(),
                });
            }
        }
        if self.inputs.is_empty() {
            return Err(super::TxVerifyErr::NoInput);
        }
        if self.issuers.is_empty() {
            return Err(super::TxVerifyErr::NoIssuer);
        }
        if self.outputs.is_empty() {
            return Err(super::TxVerifyErr::NoOutput);
        }
        if self.inputs.len() != self.unlocks.len() {
            return Err(super::TxVerifyErr::NotSameAmountOfInputsAndUnlocks(
                self.inputs.len(),
                self.unlocks.len(),
            ));
        }
        self.verify_signatures().map_err(super::TxVerifyErr::Sigs)?;
        let lines_count = self.compact_size_in_lines();
        if lines_count > TX_V10_MAX_LINES {
            return Err(super::TxVerifyErr::TooManyLines {
                found: lines_count,
                max: TX_V10_MAX_LINES,
            });
        }
        let inputs_amount: SourceAmount = self.inputs.iter().map(|input| input.amount).sum();
        let outputs_amount: SourceAmount = self.outputs.iter().map(|output| output.amount).sum();
        if inputs_amount != outputs_amount {
            return Err(
                super::TxVerifyErr::NotSameSumOfInputsAmountAndOutputsAmount(
                    inputs_amount,
                    outputs_amount,
                ),
            );
        }

        Ok(())
    }
}

/// Wrap a transaction unlocks input
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionInputUnlocksV10 {
    /// Input index
    pub index: usize,
    /// List of proof to unlock funds
    pub unlocks: SmallVec<[WalletUnlockProofV10; 1]>,
}

impl Default for TransactionInputUnlocksV10 {
    fn default() -> Self {
        TransactionInputUnlocksV10 {
            index: 0,
            unlocks: svec![WalletUnlockProofV10::Sig(0)],
        }
    }
}

impl TransactionInputUnlocksV10 {
    pub fn single_index(i: usize) -> Self {
        TransactionInputUnlocksV10 {
            index: i,
            unlocks: svec![WalletUnlockProofV10::Sig(0)],
        }
    }
}

impl ToString for TransactionInputUnlocksV10 {
    fn to_string(&self) -> String {
        let mut result: String = format!("{}:", self.index);
        for unlock in &self.unlocks {
            result.push_str(&format!("{} ", unlock.to_string()));
        }
        let new_size = result.len() - 1;
        result.truncate(new_size);
        result
    }
}

/// Wrap a transaction ouput
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionOutputV10 {
    /// Amount
    pub amount: SourceAmount,
    /// List of conditions for consum this output
    pub conditions: UTXOConditions,
}

impl TransactionOutputV10 {
    /// Lightens the TransactionOutputV10 (for example to store it while minimizing the space required)
    fn reduce(&mut self) {
        self.conditions.reduce()
    }
    /// Check validity of this output
    pub fn check(&self) -> bool {
        self.conditions.check()
    }
}

impl ToString for TransactionOutputV10 {
    fn to_string(&self) -> String {
        format!(
            "{}:{}:{}",
            self.amount.amount(),
            self.amount.base(),
            self.conditions.to_string()
        )
    }
}
/// Wrap a Transaction document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionDocumentV10 {
    /// Document as text.
    ///
    /// Is used to check signatures, and other values
    /// must be extracted from it.
    text: Option<String>,

    /// Currency.
    currency: String,
    /// Blockstamp
    blockstamp: Blockstamp,
    /// Locktime
    locktime: u64,
    /// Document issuers.
    issuers: SmallVec<[ed25519::PublicKey; 1]>,
    /// Transaction inputs.
    inputs: Vec<TransactionInputV10>,
    /// Inputs unlocks.
    unlocks: Vec<TransactionInputUnlocksV10>,
    /// Transaction outputs.
    outputs: SmallVec<[TransactionOutputV10; 2]>,
    /// Transaction comment
    comment: String,
    /// Document signatures.
    signatures: SmallVec<[ed25519::Signature; 1]>,
    /// Transaction hash
    hash: Option<Hash>,
}

#[derive(Clone, Debug, Deserialize, Hash, Serialize, PartialEq, Eq)]
/// Transaction document stringifed
pub struct TransactionDocumentV10Stringified {
    /// Currency.
    pub currency: String,
    /// Blockstamp
    pub blockstamp: String,
    /// Locktime
    pub locktime: u64,
    /// Document issuers.
    pub issuers: Vec<String>,
    /// Transaction inputs.
    pub inputs: Vec<String>,
    /// Inputs unlocks.
    pub unlocks: Vec<String>,
    /// Transaction outputs.
    pub outputs: Vec<String>,
    /// Transaction comment
    pub comment: String,
    /// Document signatures
    pub signatures: Vec<String>,
    /// Transaction hash
    pub hash: Option<String>,
}

impl ToStringObject for TransactionDocumentV10 {
    type StringObject = TransactionDocumentV10Stringified;

    fn to_string_object(&self) -> TransactionDocumentV10Stringified {
        TransactionDocumentV10Stringified {
            currency: self.currency.clone(),
            blockstamp: format!("{}", self.blockstamp),
            locktime: self.locktime,
            issuers: self.issuers.iter().map(|p| format!("{}", p)).collect(),
            inputs: self
                .inputs
                .iter()
                .map(TransactionInputV10::to_string)
                .collect(),
            unlocks: self
                .unlocks
                .iter()
                .map(TransactionInputUnlocksV10::to_string)
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(TransactionOutputV10::to_string)
                .collect(),
            comment: self.comment.clone(),
            signatures: self.signatures.iter().map(|s| format!("{}", s)).collect(),
            hash: if let Some(hash) = self.hash {
                Some(hash.to_string())
            } else {
                Some(self.compute_hash().to_hex())
            },
        }
    }
}

impl TransactionDocumentV10 {
    /// Compute  compact size in lines
    pub fn compact_size_in_lines(&self) -> usize {
        let compact_lines = 2  + // Header + blockstamp
        self.issuers.len() +
        self.inputs.len() +
        self.unlocks.len() +
        self.outputs.len() +
        self.signatures.len();
        if !self.comment.is_empty() {
            compact_lines + 1
        } else {
            compact_lines
        }
    }
    /// Compute transaction hash
    pub fn compute_hash(&self) -> Hash {
        let mut hashing_text = if let Some(ref text) = self.text {
            text.clone()
        } else {
            panic!("Try to compute_hash of tx with None text !")
        };
        for sig in &self.signatures {
            hashing_text.push_str(&sig.to_string());
            hashing_text.push('\n');
        }
        Hash::compute(hashing_text.as_bytes())
    }
    /// get transaction hash option
    pub fn get_hash_opt(&self) -> Option<Hash> {
        self.hash
    }
    /// Get transaction hash
    pub fn get_hash(&self) -> Hash {
        if let Some(hash) = self.hash {
            hash
        } else {
            self.compute_hash()
        }
    }
    pub fn recipients_keys(&self) -> Vec<ed25519::PublicKey> {
        let issuers = self.issuers.iter().copied().collect();
        let mut pubkeys = BTreeSet::new();
        for output in &self.outputs {
            pubkeys.append(&mut output.conditions.script.pubkeys());
        }
        pubkeys.difference(&issuers).copied().collect()
    }
    /// Lightens the transaction (for example to store it while minimizing the space required)
    /// WARNING: do not remove the hash as it's necessary to reverse the transaction !
    pub fn reduce(&mut self) {
        self.hash = Some(self.compute_hash());
        self.text = None;
        for output in &mut self.outputs {
            output.reduce()
        }
    }
    /// Verify comment validity
    pub fn verify_comment(comment: &str) -> bool {
        if comment.is_ascii() {
            for char_ in comment.chars() {
                match char_ {
                    c if c.is_ascii_alphanumeric() => continue,
                    '.' | ' ' | '-' | '_' | '\\' | ':' | '/' | ';' | '*' | '[' | ']' | '('
                    | ')' | '?' | '!' | '^' | '+' | '=' | '@' | '&' | '~' | '#' | '{' | '}'
                    | '|' | '<' | '>' | '%' => continue,
                    _ => return false,
                }
            }
            true
        } else {
            false
        }
    }
    /// Indicates from which blockchain timestamp the transaction can be writable.
    pub fn writable_on(
        &self,
        inputs_written_on: &[u64],
        inputs_scripts: &[WalletScriptV10],
    ) -> Result<u64, SourceV10NotUnlockableError> {
        assert_eq!(self.inputs.len(), inputs_written_on.len());
        let mut tx_unlockable_on = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.inputs.len() {
            let source_unlockable_on = SourceV10::unlockable_on(
                self.issuers.as_ref(),
                self.unlocks[i].unlocks.as_ref(),
                inputs_written_on[i],
                &inputs_scripts[i],
            )?;
            if source_unlockable_on > tx_unlockable_on {
                tx_unlockable_on = source_unlockable_on;
            }
        }
        Ok(tx_unlockable_on)
    }
}

impl Document for TransactionDocumentV10 {
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
        self.issuers.iter().copied().collect()
    }

    fn signatures(&self) -> SmallVec<[<Self::PublicKey as PublicKey>::Signature; 1]> {
        self.signatures.iter().copied().collect()
    }

    fn as_bytes(&self) -> BeefCow<[u8]> {
        BeefCow::borrowed(self.as_text().as_bytes())
    }
}

impl CompactTextDocument for TransactionDocumentV10 {
    fn as_compact_text(&self) -> String {
        let mut issuers_str = String::from("");
        for issuer in &self.issuers {
            issuers_str.push('\n');
            issuers_str.push_str(&issuer.to_string());
        }
        let mut inputs_str = String::from("");
        for input in &self.inputs {
            inputs_str.push('\n');
            inputs_str.push_str(&input.to_string());
        }
        let mut unlocks_str = String::from("");
        for unlock in &self.unlocks {
            unlocks_str.push('\n');
            unlocks_str.push_str(&unlock.to_string());
        }
        let mut outputs_str = String::from("");
        for output in &self.outputs {
            outputs_str.push('\n');
            outputs_str.push_str(&output.to_string());
        }
        let comment_str = if self.comment.is_empty() {
            String::with_capacity(0)
        } else {
            format!("{}\n", self.comment)
        };
        let mut signatures_str = String::from("");
        for sig in &self.signatures {
            signatures_str.push_str(&sig.to_string());
            signatures_str.push('\n');
        }
        // Remove end line step
        signatures_str.pop();
        format!(
            "TX:10:{issuers_count}:{inputs_count}:{unlocks_count}:{outputs_count}:{has_comment}:{locktime}
{blockstamp}{issuers}{inputs}{unlocks}{outputs}\n{comment}{signatures}",
            issuers_count = self.issuers.len(),
            inputs_count = self.inputs.len(),
            unlocks_count = self.unlocks.len(),
            outputs_count = self.outputs.len(),
            has_comment = if self.comment.is_empty() { 0 } else { 1 },
            locktime = self.locktime,
            blockstamp = self.blockstamp,
            issuers = issuers_str,
            inputs = inputs_str,
            unlocks = unlocks_str,
            outputs = outputs_str,
            comment = comment_str,
            signatures = signatures_str,
        )
    }
}

impl TextDocument for TransactionDocumentV10 {
    type CompactTextDocument_ = TransactionDocumentV10;

    fn as_text(&self) -> &str {
        if let Some(ref text) = self.text {
            text
        } else {
            panic!("Try to get text of tx with None text !")
        }
    }

    fn to_compact_document(&self) -> Cow<Self::CompactTextDocument_> {
        Cow::Borrowed(self)
    }
}

/// Transaction document builder.
#[derive(Debug, Clone)]
pub struct TransactionDocumentV10Builder<'a> {
    /// Document currency.
    pub currency: &'a str,
    /// Reference blockstamp.
    pub blockstamp: Blockstamp,
    /// Locktime
    pub locktime: u64,
    /// Transaction Document issuers.
    pub issuers: SmallVec<[ed25519::PublicKey; 1]>,
    /// Transaction inputs.
    pub inputs: &'a [TransactionInputV10],
    /// Inputs unlocks.
    pub unlocks: &'a [TransactionInputUnlocksV10],
    /// Transaction ouputs.
    pub outputs: SmallVec<[TransactionOutputV10; 2]>,
    /// Transaction comment
    pub comment: &'a str,
    /// Transaction hash
    pub hash: Option<Hash>,
}

impl<'a> TransactionDocumentV10Builder<'a> {
    pub(crate) fn build_without_sig(self) -> TransactionDocumentV10 {
        TransactionDocumentV10 {
            text: Some(self.generate_text()),
            currency: self.currency.to_string(),
            blockstamp: self.blockstamp,
            locktime: self.locktime,
            issuers: self.issuers.to_smallvec(),
            inputs: self.inputs.to_vec(),
            unlocks: self.unlocks.to_vec(),
            outputs: self.outputs,
            comment: self.comment.to_owned(),
            signatures: SmallVec::new(),
            hash: None,
        }
    }
}

impl<'a> TextDocumentBuilder for TransactionDocumentV10Builder<'a> {
    type Document = TransactionDocumentV10;
    type Signator = ed25519::Signator;

    fn build_with_text_and_sigs(
        self,
        text: String,
        signatures: SmallVec<
            [<<Self::Document as Document>::PublicKey as PublicKey>::Signature; 1],
        >,
    ) -> TransactionDocumentV10 {
        TransactionDocumentV10 {
            text: Some(text),
            currency: self.currency.to_string(),
            blockstamp: self.blockstamp,
            locktime: self.locktime,
            issuers: self.issuers.to_smallvec(),
            inputs: self.inputs.to_vec(),
            unlocks: self.unlocks.to_vec(),
            outputs: self.outputs,
            comment: self.comment.to_owned(),
            signatures,
            hash: self.hash,
        }
    }

    fn generate_text(&self) -> String {
        let mut issuers_string: String = "".to_owned();
        let mut inputs_string: String = "".to_owned();
        let mut unlocks_string: String = "".to_owned();
        let mut outputs_string: String = "".to_owned();
        for issuer in &self.issuers {
            issuers_string.push_str(&format!("{}\n", issuer.to_string()))
        }
        for input in self.inputs {
            inputs_string.push_str(&format!("{}\n", input.to_string()))
        }
        for unlock in self.unlocks {
            unlocks_string.push_str(&format!("{}\n", unlock.to_string()))
        }
        for output in &self.outputs {
            outputs_string.push_str(&format!("{}\n", output.to_string()))
        }
        format!(
            "Version: 10
Type: Transaction
Currency: {currency}
Blockstamp: {blockstamp}
Locktime: {locktime}
Issuers:
{issuers}Inputs:
{inputs}Unlocks:
{unlocks}Outputs:
{outputs}Comment: {comment}
",
            currency = self.currency,
            blockstamp = self.blockstamp,
            locktime = self.locktime,
            issuers = issuers_string,
            inputs = inputs_string,
            unlocks = unlocks_string,
            outputs = outputs_string,
            comment = self.comment,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::tx_output_v10;
    use super::*;
    use smallvec::smallvec;
    use std::str::FromStr;
    use unwrap::unwrap;

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

        let block = unwrap!(
            Blockstamp::from_str(
                "0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            ),
            "Fail to parse blockstamp"
        );

        let builder = TransactionDocumentV10Builder {
            currency: "duniter_unit_test_currency",
            blockstamp: block,
            locktime: 0,
            issuers: svec![pubkey],
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
                unlocks: smallvec![WalletUnlockProofV10::Sig(0)],
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

        let block = unwrap!(
            Blockstamp::from_str(
                "60-00001FE00410FCD5991EDD18AA7DDF15F4C8393A64FA92A1DB1C1CA2E220128D",
            ),
            "Fail to parse Blockstamp"
        );

        let builder = TransactionDocumentV10Builder {
            currency: "g1",
            blockstamp: block,
            locktime: 0,
            issuers: svec![pubkey],
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
        let tx_doc = builder.build_with_signature(svec![sig]);
        assert!(tx_doc.verify_signatures().is_ok());
        assert!(tx_doc.get_hash_opt().is_none());
        assert_eq!(
            tx_doc.get_hash(),
            unwrap!(Hash::from_hex(
                "876D2430E0B66E2CE4467866D8F923D68896CACD6AA49CDD8BDD0096B834DEF1"
            ))
        );
    }
    #[test]
    fn verify_comment() {
        assert!(TransactionDocumentV10::verify_comment(""));
        assert!(TransactionDocumentV10::verify_comment("sntsrttfsrt"));
        assert!(!TransactionDocumentV10::verify_comment("sntsrt,tfsrt"));
        assert!(TransactionDocumentV10::verify_comment("sntsrt|tfsrt"));
    }
}
