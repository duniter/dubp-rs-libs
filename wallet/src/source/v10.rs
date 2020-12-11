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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct UtxoIdV10 {
    pub tx_hash: Hash,
    pub output_index: usize,
}

impl std::fmt::Display for UtxoIdV10 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.tx_hash, self.output_index)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum SourceV10NotUnlockableError {
    #[error("{0}")]
    ScriptNeverUnlockable(ScriptNeverUnlockableError),
    #[error("Too long signer index: {0}")]
    TooLongSignerIndex(usize),
    #[error("Too many proofs: found {found}, used {used}")]
    TooManyProofs { found: usize, used: usize },
}

impl SourceV10 {
    /// Indicates from which blockchain timestamp the currency source can be unlocked.
    pub fn unlockable_on(
        tx_signers: &[PublicKey],
        proofs: &[WalletUnlockProofV10],
        source_written_on: u64,
        utxo_script: &WalletScriptV10,
    ) -> Result<u64, SourceV10NotUnlockableError> {
        let mut input_signers = HashSet::with_capacity(proofs.len());
        let mut codes_hash = HashSet::with_capacity(proofs.len());

        for proof in proofs {
            match proof {
                WalletUnlockProofV10::Sig(tx_signers_index) => {
                    if *tx_signers_index >= tx_signers.len() {
                        return Err(SourceV10NotUnlockableError::TooLongSignerIndex(
                            *tx_signers_index,
                        ));
                    } else {
                        input_signers.insert(&tx_signers[*tx_signers_index].as_ref()[..32]);
                    }
                }
                WalletUnlockProofV10::Xhx(code) => {
                    codes_hash.insert(Hash::compute_str(code));
                }
            }
        }

        let (script_unlockable_on, used_proofs) = utxo_script
            .unlockable_on(&input_signers, &codes_hash, source_written_on)
            .map_err(SourceV10NotUnlockableError::ScriptNeverUnlockable)?;

        if used_proofs.len() < proofs.len() {
            Err(SourceV10NotUnlockableError::TooManyProofs {
                found: proofs.len(),
                used: used_proofs.len(),
            })
        } else {
            Ok(script_unlockable_on)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dubp_common::crypto::keys::PublicKey as _;
    use unwrap::unwrap;

    #[inline(always)]
    fn pk(pk_b58: &str) -> PublicKey {
        unwrap!(PublicKey::from_base58(pk_b58))
    }

    #[test]
    fn test_source_unlockable_on_invariant_with_leading_1() {
        let p43 = pk("XoFs76G4yidvVY3FZBwYyLXTMjabryhFD8mNQPkQKHk");
        let p43_with_leading_1 = pk("1XoFs76G4yidvVY3FZBwYyLXTMjabryhFD8mNQPkQKHk");
        let script = WalletScriptV10::single(WalletConditionV10::Sig(p43));
        let script_with_leading_1 =
            WalletScriptV10::single(WalletConditionV10::Sig(p43_with_leading_1));
        let proofs = vec![WalletUnlockProofV10::Sig(0)];

        assert_eq!(
            Ok(0),
            SourceV10::unlockable_on(&[p43_with_leading_1], &proofs, 0, &script)
        );

        assert_eq!(
            Ok(0),
            SourceV10::unlockable_on(&[p43], &proofs, 0, &script_with_leading_1)
        );
    }

    #[test]
    fn test_source_unlockable_on() {
        let p1 = pk("D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C");
        let p2 = pk("42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp");
        let script = WalletScriptV10::or(WalletConditionV10::Sig(p1), WalletConditionV10::Sig(p2));
        let signers = vec![p1, p2];
        let proofs = vec![WalletUnlockProofV10::Sig(0), WalletUnlockProofV10::Sig(1)];

        assert_eq!(
            Err(SourceV10NotUnlockableError::TooManyProofs { found: 2, used: 1 }),
            SourceV10::unlockable_on(&signers, &proofs, 0, &script)
        );
        assert_eq!(
            Err(SourceV10NotUnlockableError::TooLongSignerIndex(2)),
            SourceV10::unlockable_on(&signers, &[WalletUnlockProofV10::Sig(2)], 0, &script)
        );
        assert_eq!(
            Err(SourceV10NotUnlockableError::ScriptNeverUnlockable(
                ScriptNeverUnlockableError
            )),
            SourceV10::unlockable_on(&signers, &[], 0, &script)
        );
        assert_eq!(
            Ok(0),
            SourceV10::unlockable_on(&signers, &[WalletUnlockProofV10::Sig(1)], 0, &script)
        );
    }
}
