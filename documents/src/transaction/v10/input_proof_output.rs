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

//! Wrappers around transaction document v10 inputs, proofs and outputs.

use super::*;

/// Wrap a transaction input v10
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
    pub(crate) fn reduce(&mut self) {
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
