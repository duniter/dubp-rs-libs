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

/// Wrap a wallet script (= conditions for unlocking the sources of this wallet)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum WalletScriptV10 {
    /// Single
    Single(WalletConditionV10),
    /// Brackets
    Brackets(Box<WalletScriptV10>),
    /// And operator
    And(Box<WalletScriptV10>, Box<WalletScriptV10>),
    /// Or operator
    Or(Box<WalletScriptV10>, Box<WalletScriptV10>),
}

impl ToString for WalletScriptV10 {
    fn to_string(&self) -> String {
        match *self {
            Self::Single(ref condition) => condition.to_string(),
            Self::Brackets(ref sub_script) => format!("({})", sub_script.to_string()),
            Self::And(ref sub_script_1, ref sub_script_2) => format!(
                "{} && {}",
                sub_script_1.to_string(),
                sub_script_2.to_string()
            ),
            Self::Or(ref sub_script_1, ref sub_script_2) => format!(
                "{} || {}",
                sub_script_1.to_string(),
                sub_script_2.to_string()
            ),
        }
    }
}

#[derive(Debug, Error, PartialEq)]
#[error("Script never  unlockable")]
pub struct ScriptNeverUnlockableError;

impl WalletScriptV10 {
    pub(crate) fn unlockable_on(
        &self,
        signers: &HashSet<PublicKey>,
        codes_hash: &HashSet<Hash>,
        source_written_on: u64,
    ) -> Result<u64, ScriptNeverUnlockableError> {
        match self {
            Self::Single(cond) => cond.unlockable_on(signers, codes_hash, source_written_on),
            Self::Brackets(script) => script.unlockable_on(signers, codes_hash, source_written_on),
            Self::And(script1, script2) => Ok(std::cmp::max(
                script1.unlockable_on(signers, codes_hash, source_written_on)?,
                script2.unlockable_on(signers, codes_hash, source_written_on)?,
            )),
            Self::Or(script1, script2) => {
                let script1_unlockable_on_res =
                    script1.unlockable_on(signers, codes_hash, source_written_on);
                let script2_unlockable_on_res =
                    script2.unlockable_on(signers, codes_hash, source_written_on);
                match script1_unlockable_on_res {
                    Ok(script1_unlockable_on) => match script2_unlockable_on_res {
                        Ok(script2_unlockable_on) => {
                            Ok(std::cmp::min(script1_unlockable_on, script2_unlockable_on))
                        }
                        Err(_) => Ok(script1_unlockable_on),
                    },
                    Err(e) => match script2_unlockable_on_res {
                        Ok(script2_unlockable_on) => Ok(script2_unlockable_on),
                        Err(_) => Err(e),
                    },
                }
            }
        }
    }
}

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

impl WalletConditionV10 {
    pub(crate) fn unlockable_on(
        &self,
        signers: &HashSet<PublicKey>,
        codes_hash: &HashSet<Hash>,
        source_written_on: u64,
    ) -> Result<u64, ScriptNeverUnlockableError> {
        match self {
            Self::Sig(pubkey) => {
                if signers.contains(pubkey) {
                    Ok(0)
                } else {
                    Err(ScriptNeverUnlockableError)
                }
            }
            Self::Xhx(code_hash) => {
                if codes_hash.contains(code_hash) {
                    Ok(0)
                } else {
                    Err(ScriptNeverUnlockableError)
                }
            }
            Self::Cltv(timestamp) => Ok(*timestamp),
            Self::Csv(duration_secs) => Ok(source_written_on + *duration_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dubp_common::crypto::keys::PublicKey as _;
    use maplit::hashset;
    use unwrap::unwrap;

    #[test]
    fn test_script_or_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond1 = WalletConditionV10::Sig(p1);
        let cond2 = WalletConditionV10::Cltv(123);
        let script = WalletScriptV10::Or(
            Box::new(WalletScriptV10::Single(cond1)),
            Box::new(WalletScriptV10::Single(cond2)),
        );

        assert_eq!(Ok(0), script.unlockable_on(&hashset![p1], &hashset![], 0),);
        assert_eq!(
            Ok(123),
            script.unlockable_on(&hashset![PublicKey::default()], &hashset![], 0),
        );
    }

    #[test]
    fn test_script_and_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond1 = WalletConditionV10::Sig(p1);
        let cond2 = WalletConditionV10::Cltv(123);
        let script = WalletScriptV10::And(
            Box::new(WalletScriptV10::Single(cond1)),
            Box::new(WalletScriptV10::Single(cond2)),
        );

        assert_eq!(Ok(123), script.unlockable_on(&hashset![p1], &hashset![], 0),);
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            script.unlockable_on(&hashset![PublicKey::default()], &hashset![], 0),
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

        let script = WalletScriptV10::Or(
            Box::new(WalletScriptV10::Single(cond3)),
            Box::new(WalletScriptV10::Brackets(Box::new(WalletScriptV10::And(
                Box::new(WalletScriptV10::Single(cond1)),
                Box::new(WalletScriptV10::Single(cond2)),
            )))),
        );

        assert_eq!(
            "XHX(3D8BF2B661155EA073D80A1E1171212261AD4D21F2E41737BDE192871C469ABE) || (SIG(D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C) && CLTV(123))",
            script.to_string()
        );
        assert_eq!(Ok(123), script.unlockable_on(&hashset![p1], &hashset![], 0),);
    }

    #[test]
    fn test_sig_cond_unlockable_on() {
        let p1 = unwrap!(PublicKey::from_base58(
            "D7CYHJXjaH4j7zRdWngUbsURPnSnjsCYtvo6f8dvW3C"
        ));
        let cond = WalletConditionV10::Sig(p1);

        assert_eq!(Ok(0), cond.unlockable_on(&hashset![p1], &hashset![], 0),);
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            cond.unlockable_on(&hashset![PublicKey::default()], &hashset![], 0),
        );
    }

    #[test]
    fn test_xhx_cond_unlockable_on() {
        let h1 = Hash::compute_str("1");
        let cond = WalletConditionV10::Xhx(h1);

        assert_eq!(Ok(0), cond.unlockable_on(&hashset![], &hashset![h1], 0),);
        assert_eq!(
            Err(ScriptNeverUnlockableError),
            cond.unlockable_on(&hashset![PublicKey::default()], &hashset![], 0),
        );
    }

    #[test]
    fn test_cltv_cond_unlockable_on() {
        let cond = WalletConditionV10::Cltv(123);

        assert_eq!(Ok(123), cond.unlockable_on(&hashset![], &hashset![], 0),);
    }

    #[test]
    fn test_csv_cond_unlockable_on() {
        let cond = WalletConditionV10::Csv(123);

        assert_eq!(Ok(369), cond.unlockable_on(&hashset![], &hashset![], 246),);
    }
}
