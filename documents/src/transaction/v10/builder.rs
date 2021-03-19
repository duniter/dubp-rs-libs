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

//! Transaction document v10 builder.

use super::*;

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
    pub(crate) fn build_unsigned(self) -> UnsignedTransactionDocumentV10 {
        UnsignedTransactionDocumentV10 {
            text: self.generate_text(),
            currency: self.currency.to_string(),
            blockstamp: self.blockstamp,
            locktime: self.locktime,
            issuers: self.issuers.to_smallvec(),
            inputs: self.inputs.to_vec(),
            unlocks: self.unlocks.to_vec(),
            outputs: self.outputs,
            comment: self.comment.to_owned(),
            signatures_opt: SmallVec::new(),
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
