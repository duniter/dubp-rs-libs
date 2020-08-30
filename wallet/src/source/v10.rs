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

//! Define DUBP currency source v10

use crate::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SourceV10 {
    pub id: SourceIdV10,
    pub amount: SourceAmount,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum SourceIdV10 {
    Ud(UdSourceIdV10),
    Utxo(UtxoIdV10),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UdSourceIdV10 {
    pub issuer: PublicKey,
    pub block_number: BlockNumber,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UtxoIdV10 {
    pub tx_hash: Hash,
    pub output_index: usize,
}

#[derive(Debug, Error)]
pub enum SourceV10NotUnlockableError {
    #[error("Too long signer index: {0}")]
    TooLongSignerIndex(usize),
    #[error("{0}")]
    ScriptNotVerified(ScriptNeverUnlockableError),
}

impl SourceV10 {
    /// Indicates from which blockchain timestamp the currency source can be unlocked.
    pub fn unlockable_on(
        tx_signers: &[PublicKey],
        proofs: &[WalletUnlockProofV10],
        source_written_on: u64,
        utxo_script: &WalletScriptV10,
    ) -> Result<u64, SourceV10NotUnlockableError> {
        let mut signers = HashSet::with_capacity(proofs.len());
        let mut codes_hash = HashSet::with_capacity(proofs.len());

        for proof in proofs {
            match proof {
                WalletUnlockProofV10::Sig(tx_signers_index) => {
                    if *tx_signers_index >= tx_signers.len() {
                        return Err(SourceV10NotUnlockableError::TooLongSignerIndex(
                            *tx_signers_index,
                        ));
                    } else {
                        signers.insert(tx_signers[*tx_signers_index]);
                    }
                }
                WalletUnlockProofV10::Xhx(code) => {
                    codes_hash.insert(Hash::compute_str(code));
                }
            }
        }

        utxo_script
            .unlockable_on(&signers, &codes_hash, source_written_on)
            .map_err(SourceV10NotUnlockableError::ScriptNotVerified)
    }
}
