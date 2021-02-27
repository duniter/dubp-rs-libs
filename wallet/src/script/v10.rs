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

//! Define DUBP Wallet script V10.

use crate::*;

/// Wrap a transaction unlock proof
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum WalletUnlockProofV10 {
    /// Indicates that the signature of the corresponding key is at the bottom of the document
    Sig(usize),
    /// Provides the code to unlock the corresponding funds
    Xhx(String),
}

impl Default for WalletUnlockProofV10 {
    fn default() -> Self {
        WalletUnlockProofV10::Sig(0)
    }
}

impl ToString for WalletUnlockProofV10 {
    fn to_string(&self) -> String {
        match *self {
            Self::Sig(ref index) => format!("SIG({})", index),
            Self::Xhx(ref hash) => format!("XHX({})", hash),
        }
    }
}

/// Wrap a wallet sub script (= conditions for unlocking the sources of this wallet)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum WalletSubScriptV10 {
    /// Single
    Single(WalletConditionV10),
    /// Brackets
    Brackets(usize),
    /// And operator
    And(usize, usize),
    /// Or operator
    Or(usize, usize),
}

impl WalletSubScriptV10 {
    fn to_raw_text(self, nodes: &[WalletSubScriptV10]) -> String {
        match self {
            Self::Single(cond) => cond.to_string(),
            Self::Brackets(sub_script) => format!("({})", nodes[sub_script].to_raw_text(nodes)),
            Self::And(sub_script_1, sub_script_2) => format!(
                "{} && {}",
                nodes[sub_script_1].to_raw_text(nodes),
                nodes[sub_script_2].to_raw_text(nodes),
            ),
            Self::Or(sub_script_1, sub_script_2) => format!(
                "{} || {}",
                nodes[sub_script_1].to_raw_text(nodes),
                nodes[sub_script_2].to_raw_text(nodes),
            ),
        }
    }
}

impl WalletSubScriptV10 {
    pub fn is_single_sig(&self) -> bool {
        matches!(self, Self::Single(WalletConditionV10::Sig(_)))
    }
    fn unlockable_on(
        self,
        nodes: &[WalletSubScriptV10],
        signers: &HashSet<&[u8]>,
        codes_hash: &HashSet<Hash>,
        source_written_on: u64,
    ) -> Result<(u64, HashSet<UsedProofV10>), ScriptNeverUnlockableError> {
        match self {
            Self::Single(cond) => cond
                .unlockable_on(signers, codes_hash, source_written_on)
                .map(|(cond_unlockable_on, used_proof_opt)| {
                    if let Some(used_proof) = used_proof_opt {
                        let mut used_proofs_set = HashSet::with_capacity(1);
                        used_proofs_set.insert(used_proof);
                        (cond_unlockable_on, used_proofs_set)
                    } else {
                        (cond_unlockable_on, HashSet::with_capacity(0))
                    }
                }),
            Self::Brackets(sub_script_index) => {
                nodes[sub_script_index].unlockable_on(nodes, signers, codes_hash, source_written_on)
            }
            Self::And(sub_script1_index, sub_script2_index) => {
                let (script1_unlockable_on, script1_used_proofs) = nodes[sub_script1_index]
                    .unlockable_on(nodes, signers, codes_hash, source_written_on)?;
                let (script2_unlockable_on, script2_used_proofs) = nodes[sub_script2_index]
                    .unlockable_on(nodes, signers, codes_hash, source_written_on)?;
                Ok((
                    std::cmp::max(script1_unlockable_on, script2_unlockable_on),
                    script1_used_proofs
                        .union(&script2_used_proofs)
                        .copied()
                        .collect(),
                ))
            }
            Self::Or(sub_script1_index, sub_script2_index) => {
                let script1_unlockable_on_res = nodes[sub_script1_index].unlockable_on(
                    nodes,
                    signers,
                    codes_hash,
                    source_written_on,
                );
                let script2_unlockable_on_res = nodes[sub_script2_index].unlockable_on(
                    nodes,
                    signers,
                    codes_hash,
                    source_written_on,
                );
                match script1_unlockable_on_res {
                    Ok((script1_unlockable_on, script1_used_proofs)) => {
                        match script2_unlockable_on_res {
                            Ok((script2_unlockable_on, script2_used_proofs)) => Ok((
                                std::cmp::min(script1_unlockable_on, script2_unlockable_on),
                                if script2_used_proofs.len() < script1_used_proofs.len() {
                                    script2_used_proofs
                                } else {
                                    script1_used_proofs
                                },
                            )),
                            Err(_) => Ok((script1_unlockable_on, script1_used_proofs)),
                        }
                    }
                    Err(_) => script2_unlockable_on_res,
                }
            }
        }
    }
}

pub type WalletScriptNodesV10 = SmallVec<[WalletSubScriptV10; 8]>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct WalletScriptV10 {
    pub root: WalletSubScriptV10,
    pub nodes: WalletScriptNodesV10,
}

impl ToString for WalletScriptV10 {
    fn to_string(&self) -> String {
        self.root.to_raw_text(&self.nodes)
    }
}

impl WalletScriptV10 {
    pub fn single(condition: WalletConditionV10) -> Self {
        WalletScriptV10 {
            root: WalletSubScriptV10::Single(condition),
            nodes: SmallVec::new(),
        }
    }
    pub fn single_sig(pubkey: PublicKey) -> Self {
        WalletScriptV10 {
            root: WalletSubScriptV10::Single(WalletConditionV10::Sig(pubkey)),
            nodes: SmallVec::new(),
        }
    }
    pub fn is_single_sig(&self) -> bool {
        self.nodes.is_empty() && self.root.is_single_sig()
    }
    pub fn and(cond1: WalletConditionV10, cond2: WalletConditionV10) -> Self {
        let mut nodes = SmallVec::new();
        nodes.push(WalletSubScriptV10::Single(cond1));
        nodes.push(WalletSubScriptV10::Single(cond2));

        WalletScriptV10 {
            root: WalletSubScriptV10::And(0, 1),
            nodes,
        }
    }
    pub fn and_and(
        cond1: WalletConditionV10,
        cond2: WalletConditionV10,
        cond3: WalletConditionV10,
    ) -> Self {
        let mut nodes = SmallVec::new();
        nodes.push(WalletSubScriptV10::Single(cond1));
        nodes.push(WalletSubScriptV10::And(2, 3));
        nodes.push(WalletSubScriptV10::Single(cond2));
        nodes.push(WalletSubScriptV10::Single(cond3));

        WalletScriptV10 {
            root: WalletSubScriptV10::And(0, 1),
            nodes,
        }
    }
    pub fn or(cond1: WalletConditionV10, cond2: WalletConditionV10) -> Self {
        let mut nodes = SmallVec::new();
        nodes.push(WalletSubScriptV10::Single(cond1));
        nodes.push(WalletSubScriptV10::Single(cond2));

        WalletScriptV10 {
            root: WalletSubScriptV10::Or(0, 1),
            nodes,
        }
    }
    pub fn pubkeys(&self) -> BTreeSet<PublicKey> {
        let mut pubkeys = BTreeSet::new();
        if let WalletSubScriptV10::Single(WalletConditionV10::Sig(pubkey)) = self.root {
            pubkeys.insert(pubkey);
        }
        for node in &self.nodes {
            if let WalletSubScriptV10::Single(WalletConditionV10::Sig(pubkey)) = node {
                pubkeys.insert(*pubkey);
            }
        }
        pubkeys
    }
    pub(crate) fn unlockable_on(
        &self,
        signers: &HashSet<&[u8]>,
        codes_hash: &HashSet<Hash>,
        source_written_on: u64,
    ) -> Result<(u64, HashSet<UsedProofV10>), ScriptNeverUnlockableError> {
        self.root
            .unlockable_on(&self.nodes, signers, codes_hash, source_written_on)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq)]
#[error("Script never unlockable")]
pub struct ScriptNeverUnlockableError;

/// Wrap wallet condition (= one condition in wallet script)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum WalletConditionV10 {
    /// The consumption of funds will require a valid signature of the specified key
    Sig(PublicKey),
    /// The consumption of funds will require to provide a code with the hash indicated
    Xhx(Hash),
    /// Funds may not be consumed until the blockchain reaches the timestamp indicated.
    Cltv(u64),
    /// Funds may not be consumed before the duration indicated, starting from the timestamp of the block where the transaction is written.
    Csv(u64),
}

impl ToString for WalletConditionV10 {
    fn to_string(&self) -> String {
        match *self {
            Self::Sig(ref pubkey) => format!("SIG({})", pubkey),
            Self::Xhx(ref hash) => format!("XHX({})", hash),
            Self::Cltv(timestamp) => format!("CLTV({})", timestamp),
            Self::Csv(duration) => format!("CSV({})", duration),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UsedProofV10 {
    Sig(PublicKey),
    CodeHash(Hash),
}

impl WalletConditionV10 {
    pub(crate) fn unlockable_on(
        &self,
        signers: &HashSet<&[u8]>,
        codes_hash: &HashSet<Hash>,
        source_written_on: u64,
    ) -> Result<(u64, Option<UsedProofV10>), ScriptNeverUnlockableError> {
        match self {
            Self::Sig(pubkey) => {
                if signers.contains(&pubkey.as_ref()[..32]) {
                    Ok((0, Some(UsedProofV10::Sig(*pubkey))))
                } else {
                    Err(ScriptNeverUnlockableError)
                }
            }
            Self::Xhx(code_hash) => {
                if codes_hash.contains(code_hash) {
                    Ok((0, Some(UsedProofV10::CodeHash(*code_hash))))
                } else {
                    Err(ScriptNeverUnlockableError)
                }
            }
            Self::Cltv(timestamp) => Ok((*timestamp, None)),
            Self::Csv(duration_secs) => Ok((source_written_on + *duration_secs, None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dubp_common::crypto::keys::PublicKey as _;
    use maplit::hashset;
    use smallvec::smallvec as svec;
    use unwrap::unwrap;

    #[test]
    fn test_script_or_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond1 = WalletConditionV10::Sig(p1);
        let cond2 = WalletConditionV10::Cltv(123);
        let script = WalletScriptV10::or(cond1, cond2);

        assert_eq!(
            Ok((0, hashset![])),
            script.unlockable_on(&hashset![&p1.as_ref()[..32]], &hashset![], 0),
        );
        assert_eq!(
            Ok((123, hashset![])),
            script.unlockable_on(&hashset![&[0u8; 32][..]], &hashset![], 0),
        );
    }

    #[test]
    fn test_script_and_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond1 = WalletConditionV10::Sig(p1);
        let cond2 = WalletConditionV10::Cltv(123);
        let script = WalletScriptV10::and(cond1, cond2);

        assert_eq!(
            Ok((123, hashset![UsedProofV10::Sig(p1)])),
            script.unlockable_on(&hashset![&p1.as_ref()[..32]], &hashset![], 0)
        );
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            script.unlockable_on(&hashset![&[0u8; 32][..]], &hashset![], 0),
        );
    }

    #[test]
    fn test_script_complex() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let h1 = unwrap!(Hash::from_hex(
            "3D8BF2B661155EA073D80A1E1171212261AD4D21F2E41737BDE192871C469ABE"
        ));
        let cond1 = WalletConditionV10::Sig(p1);
        let cond2 = WalletConditionV10::Cltv(123);
        let cond3 = WalletConditionV10::Xhx(h1);

        let script = WalletScriptV10 {
            root: WalletSubScriptV10::Or(0, 4),
            nodes: svec![
                WalletSubScriptV10::Single(cond3),
                WalletSubScriptV10::Single(cond1),
                WalletSubScriptV10::Single(cond2),
                WalletSubScriptV10::And(1, 2),
                WalletSubScriptV10::Brackets(3),
            ],
        };

        assert_eq!(
            "XHX(3D8BF2B661155EA073D80A1E1171212261AD4D21F2E41737BDE192871C469ABE) || (SIG(D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C) && CLTV(123))",
            script.to_string()
        );
        assert_eq!(
            Ok((123, hashset![UsedProofV10::Sig(p1)])),
            script.unlockable_on(&hashset![&p1.as_ref()[..32]], &hashset![], 0),
        );
    }

    #[test]
    fn test_sig_cond_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond = WalletConditionV10::Sig(p1);

        assert_eq!(
            Ok((0, Some(UsedProofV10::Sig(p1)))),
            cond.unlockable_on(&hashset![&p1.as_ref()[..32]], &hashset![], 0),
        );
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            cond.unlockable_on(&hashset![&[0u8; 32][..]], &hashset![], 0),
        );
    }

    #[test]
    fn test_xhx_cond_unlockable_on() {
        let h1 = Hash::compute(b"1");
        let cond = WalletConditionV10::Xhx(h1);

        assert_eq!(
            Ok((0, Some(UsedProofV10::CodeHash(h1)))),
            cond.unlockable_on(&hashset![], &hashset![h1], 0),
        );
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            cond.unlockable_on(&hashset![&[0u8; 32][..]], &hashset![], 0),
        );
    }

    #[test]
    fn test_cltv_cond_unlockable_on() {
        let cond = WalletConditionV10::Cltv(123);

        assert_eq!(
            Ok((123, None)),
            cond.unlockable_on(&hashset![], &hashset![], 0),
        );
    }

    #[test]
    fn test_csv_cond_unlockable_on() {
        let cond = WalletConditionV10::Csv(123);

        assert_eq!(
            Ok((369, None)),
            cond.unlockable_on(&hashset![], &hashset![], 246),
        );
    }

    #[test]
    fn test_and_and() {
        let cond1 = WalletConditionV10::Csv(123);
        let cond2 = WalletConditionV10::Csv(456);
        let cond3 = WalletConditionV10::Csv(789);

        let script = WalletScriptV10::and_and(cond1, cond2, cond3);
        assert_eq!(&script.to_string(), "CSV(123) && CSV(456) && CSV(789)");
    }

    #[test]
    fn test_is_single_sig() {
        assert!(WalletScriptV10::single_sig(PublicKey::default()).is_single_sig());
        assert!(!WalletScriptV10::single(WalletConditionV10::Csv(100)).is_single_sig());

        let cond1 = WalletConditionV10::Csv(123);
        let cond2 = WalletConditionV10::Csv(456);
        assert!(!WalletScriptV10::and(cond1, cond2).is_single_sig());
    }
}
