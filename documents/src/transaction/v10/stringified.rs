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

//! Wrappers around transaction document v10 stringified.

use super::*;

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
