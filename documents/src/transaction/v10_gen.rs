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

//! Transaction documents V10 generator.

use super::*;
use crate::*;

type RawTx = String;

#[cfg(not(test))]
const TX_V10_MAX_SIZE_IN_COMPACT_LINES: usize = 100;
#[cfg(test)]
const TX_V10_MAX_SIZE_IN_COMPACT_LINES: usize = 14;
const MAX_INPUTS_PER_SIMPLE_TX: usize = (TX_V10_MAX_SIZE_IN_COMPACT_LINES - 7) / 2;
const TX_V10_MAX_INPUTS_PLUS_SIGNERS: usize = TX_V10_MAX_SIZE_IN_COMPACT_LINES - 4;

pub(crate) struct TransactionDocV10SimpleGen {
    pub(crate) blockstamp: Blockstamp,
    pub(crate) currency: String,
    pub(crate) inputs: Vec<TransactionInputV10>,
    pub(crate) inputs_sum: SourceAmount,
    pub(crate) issuer: ed25519::PublicKey,
    pub(crate) recipient: ed25519::PublicKey,
    pub(crate) user_amount: SourceAmount,
    pub(crate) user_comment: String,
    pub(crate) cash_back_pubkey: Option<ed25519::PublicKey>,
}

impl TransactionDocV10SimpleGen {
    pub(crate) fn gen(self) -> Vec<RawTx> {
        let inputs_count = self.inputs.len();
        if inputs_count > MAX_INPUTS_PER_SIMPLE_TX {
            /*let (mut txs, final_changes_sources) = */
            gen_change_txs(
                self.blockstamp,
                self.currency.clone(),
                self.inputs,
                svec![self.issuer],
                WalletScriptV10::single(WalletConditionV10::Sig(self.issuer)),
                svec![WalletUnlockProofV10::default()],
            ) /*;
              txs.push(gen_simple_tx_with_inputs(
                  amount,
                  current_blockstamp,
                  comment,
                  currency,
                  (
                      final_changes_sources.as_ref(),
                      final_changes_sources.iter().map(|i| i.amount).sum(),
                  ),
                  issuer,
                  recipient,
              ));
              txs*/
        } else {
            vec![gen_final_simple_tx(
                self.user_amount,
                self.blockstamp,
                self.user_comment,
                self.currency,
                (self.inputs.as_ref(), self.inputs_sum),
                self.issuer,
                self.recipient,
                self.cash_back_pubkey,
            )]
        }
    }
}

#[derive(Debug)]
pub struct TxV10ComplexIssuer {
    pub amount: SourceAmount,
    pub codes: SmallVec<[String; 1]>,
    pub inputs: Vec<TransactionInputV10>,
    pub inputs_sum: SourceAmount,
    pub script: WalletScriptV10,
    pub signers: SmallVec<[ed25519::PublicKey; 1]>,
}
pub type TxV10Recipient = (SourceAmount, WalletScriptV10);

#[derive(Debug)]
pub struct TransactionDocV10ComplexGen {
    pub blockstamp: Blockstamp,
    pub currency: String,
    pub issuers: Vec<TxV10ComplexIssuer>,
    pub recipients: Vec<TxV10Recipient>,
    pub user_comment: String,
}

impl TransactionDocV10ComplexGen {
    pub fn gen(self) -> Result<(Option<RawTx>, Vec<RawTx>), GenTxError> {
        let mut signers = BTreeSet::new();
        for issuer in &self.issuers {
            signers.extend(issuer.signers.iter().copied())
        }

        let max_inputs =
            (TX_V10_MAX_INPUTS_PLUS_SIGNERS - ((signers.len() + self.recipients.len()) * 2)) / 2;

        if max_inputs < self.issuers.len() {
            return Err(GenTxError::TooManySignersOrRecipients);
        }

        let inputs_count: usize = self.issuers.iter().map(|issuer| issuer.inputs.len()).sum();

        if inputs_count > max_inputs {
            let TransactionDocV10ComplexGen {
                blockstamp,
                currency,
                issuers,
                ..
            } = self;
            let issuers_count = issuers.len();

            let change_txs = issuers.into_iter().fold(
                Vec::with_capacity(issuers_count),
                |mut raw_txs, issuer| {
                    let TxV10ComplexIssuer {
                        codes,
                        inputs,
                        script,
                        signers,
                        ..
                    } = issuer;
                    let signers_index: BTreeMap<ed25519::PublicKey, usize> =
                        signers.iter().enumerate().map(|(i, pk)| (*pk, i)).collect();
                    let unlocks = signers
                        .iter()
                        .map(|pk| {
                            WalletUnlockProofV10::Sig(
                                *signers_index.get(pk).unwrap_or_else(|| unreachable!()),
                            )
                        })
                        .chain(codes.into_iter().map(WalletUnlockProofV10::Xhx))
                        .collect();
                    raw_txs.append(&mut gen_change_txs(
                        blockstamp,
                        currency.clone(),
                        inputs,
                        signers,
                        script,
                        unlocks,
                    ));
                    raw_txs
                },
            );
            Ok((None, change_txs))
        } else {
            Ok((
                Some(gen_final_complex_tx(
                    self.blockstamp,
                    self.user_comment,
                    self.currency,
                    self.issuers,
                    signers.into_iter().collect(),
                    self.recipients,
                )),
                vec![],
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn gen_final_simple_tx(
    amount: SourceAmount,
    blockstamp: Blockstamp,
    comment: String,
    currency: String,
    inputs_with_sum: (&[TransactionInputV10], SourceAmount),
    issuer: ed25519::PublicKey,
    recipient: ed25519::PublicKey,
    cash_back_pubkey: Option<ed25519::PublicKey>,
) -> RawTx {
    let (inputs, inputs_sum) = inputs_with_sum;
    let inputs_len = inputs.len();
    let unlocks = (0..inputs_len)
        .into_iter()
        .map(TransactionInputUnlocksV10::single_index)
        .collect::<Vec<_>>();

    let rest = inputs_sum - amount;
    let main_output = TransactionOutputV10 {
        amount,
        conditions: UTXOConditions::from(WalletScriptV10::single(WalletConditionV10::Sig(
            recipient,
        ))),
    };
    let outputs = if rest.amount() > 0 {
        svec![
            main_output,
            TransactionOutputV10 {
                amount: rest,
                conditions: UTXOConditions::from(WalletScriptV10::single(WalletConditionV10::Sig(
                    cash_back_pubkey.unwrap_or(issuer),
                ))),
            },
        ]
    } else {
        svec![main_output]
    };

    TransactionDocumentV10Builder {
        currency: &currency,
        blockstamp,
        locktime: 0,
        issuers: svec![issuer],
        inputs,
        unlocks: &unlocks,
        outputs,
        comment: &comment,
        hash: None,
    }
    .generate_text()
}

fn gen_final_complex_tx(
    blockstamp: Blockstamp,
    comment: String,
    currency: String,
    issuers: Vec<TxV10ComplexIssuer>,
    signers: SmallVec<[ed25519::PublicKey; 1]>,
    recipients: Vec<TxV10Recipient>,
) -> RawTx {
    let signers_index: BTreeMap<ed25519::PublicKey, usize> =
        signers.iter().enumerate().map(|(i, pk)| (*pk, i)).collect();
    let (inputs, unlocks, mut outputs): (
        Vec<TransactionInputV10>,
        Vec<TransactionInputUnlocksV10>,
        SmallVec<[TransactionOutputV10; 2]>,
    ) = issuers
        .into_iter()
        .map(|issuer| {
            let TxV10ComplexIssuer {
                amount,
                codes,
                inputs,
                inputs_sum,
                script,
                signers,
            } = issuer;
            let inputs_count = inputs.len();
            let rest = inputs_sum - amount;
            let unlocks_per_input: SmallVec<[_; 1]> = signers
                .iter()
                .map(|pk| {
                    WalletUnlockProofV10::Sig(
                        *signers_index.get(pk).unwrap_or_else(|| unreachable!()),
                    )
                })
                .chain(codes.into_iter().map(WalletUnlockProofV10::Xhx))
                .collect();
            (
                inputs,
                (0..inputs_count).map(move |i| TransactionInputUnlocksV10 {
                    index: i,
                    unlocks: unlocks_per_input.clone(),
                }),
                if rest > SourceAmount::ZERO {
                    Some(TransactionOutputV10 {
                        amount: rest,
                        conditions: UTXOConditions::from(script),
                    })
                } else {
                    None
                },
            )
        })
        .fold(
            (vec![], vec![], SmallVec::new()),
            |(mut inputs, mut unlocks, mut outputs),
             (mut issuer_inputs, issuer_unlocks, issuer_rest_output_opt)| {
                inputs.append(&mut issuer_inputs);
                unlocks.extend(issuer_unlocks);
                if let Some(issuer_rest_output) = issuer_rest_output_opt {
                    outputs.push(issuer_rest_output);
                }
                (inputs, unlocks, outputs)
            },
        );

    outputs.extend(
        recipients
            .into_iter()
            .map(|(amount, script)| TransactionOutputV10 {
                amount,
                conditions: UTXOConditions::from(script),
            }),
    );

    TransactionDocumentV10Builder {
        currency: &currency,
        blockstamp,
        locktime: 0,
        issuers: signers,
        inputs: &inputs,
        unlocks: &unlocks,
        outputs,
        comment: &comment,
        hash: None,
    }
    .generate_text()
}

fn gen_change_txs(
    blockstamp: Blockstamp,
    currency: String,
    inputs: Vec<TransactionInputV10>,
    signers: SmallVec<[ed25519::PublicKey; 1]>,
    script: WalletScriptV10,
    unlocks: SmallVec<[WalletUnlockProofV10; 1]>,
) -> Vec<RawTx> {
    let max_inputs = (TX_V10_MAX_INPUTS_PLUS_SIGNERS - (2 * signers.len())) / 2;
    let inputs_len = inputs.len();
    let div = inputs_len / max_inputs;
    let rest = inputs_len % max_inputs;
    let txs_count = div + std::cmp::min(rest, 1);
    let mut txs = Vec::with_capacity(txs_count);

    let mut cursor = 0;
    for _ in 0..div {
        let next_cursor = cursor + max_inputs;
        let tx_inputs = &inputs[cursor..next_cursor];
        let tx_inputs_sum = tx_inputs.iter().map(|i| i.amount).sum();
        txs.push(gen_one_change_tx(
            blockstamp,
            currency.clone(),
            (tx_inputs, tx_inputs_sum),
            signers.iter().copied().collect(),
            script.clone(),
            unlocks.clone(),
        ));
        cursor = next_cursor;
    }
    if rest > 1 {
        let tx_inputs = &inputs[cursor..];
        let tx_inputs_sum = tx_inputs.iter().map(|i| i.amount).sum();
        txs.push(gen_one_change_tx(
            blockstamp,
            currency,
            (tx_inputs, tx_inputs_sum),
            signers,
            script,
            unlocks,
        ));
    }
    txs
}

fn gen_one_change_tx(
    blockstamp: Blockstamp,
    currency: String,
    inputs_with_sum: (&[TransactionInputV10], SourceAmount),
    signers: SmallVec<[ed25519::PublicKey; 1]>,
    script: WalletScriptV10,
    unlocks: SmallVec<[WalletUnlockProofV10; 1]>,
) -> String {
    let (inputs, inputs_sum) = inputs_with_sum;
    let inputs_len = inputs.len();
    let unlocks = (0..inputs_len)
        .into_iter()
        .map(|i| TransactionInputUnlocksV10 {
            index: i,
            unlocks: unlocks.clone(),
        })
        .collect::<Vec<_>>();

    let main_output = TransactionOutputV10 {
        amount: inputs_sum,
        conditions: UTXOConditions::from(script),
    };

    TransactionDocumentV10Builder {
        currency: &currency,
        blockstamp,
        locktime: 0,
        issuers: signers,
        inputs,
        unlocks: &unlocks,
        outputs: svec![main_output],
        comment: "change",
        hash: None,
    }
    .generate_text()
}

#[cfg(test)]
mod tests {

    use super::*;
    use unwrap::unwrap;

    #[test]
    fn gen_complex_tx() -> Result<(), GenTxError> {
        let issuer1 = unwrap!(ed25519::PublicKey::from_base58(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        let issuer2 = unwrap!(ed25519::PublicKey::from_base58(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        ));
        let recipient1 = unwrap!(ed25519::PublicKey::from_base58(
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        ));
        let tx_hash = Hash::default();
        let issuer1 = TxV10ComplexIssuer {
            amount: SourceAmount::with_base0(8),
            codes: svec![],
            inputs: vec![TransactionInputV10 {
                amount: SourceAmount::with_base0(10),
                id: SourceIdV10::Ud(UdSourceIdV10 {
                    issuer: issuer1,
                    block_number: BlockNumber(0),
                }),
            }],
            inputs_sum: SourceAmount::with_base0(10),
            script: WalletScriptV10::single(WalletConditionV10::Sig(issuer1)),
            signers: svec![issuer1],
        };
        let issuer2 = TxV10ComplexIssuer {
            amount: SourceAmount::with_base0(27),
            codes: svec![],
            inputs: vec![TransactionInputV10 {
                amount: SourceAmount::with_base0(30),
                id: SourceIdV10::Utxo(UtxoIdV10 {
                    tx_hash,
                    output_index: 1,
                }),
            }],
            inputs_sum: SourceAmount::with_base0(30),
            script: WalletScriptV10::single(WalletConditionV10::Sig(issuer2)),
            signers: svec![issuer2],
        };

        let txs = TransactionDocV10ComplexGen {
            blockstamp: Blockstamp::default(),
            currency: "test".to_owned(),
            issuers: vec![issuer1, issuer2],
            recipients: vec![(
                SourceAmount::with_base0(35),
                WalletScriptV10::single(WalletConditionV10::Sig(recipient1)),
            )],
            user_comment: "toto".to_owned(),
        }
        .gen()?;

        assert!(txs.1.is_empty());
        assert!(txs.0.is_some());
        let complex_tx = txs.0.unwrap_or_else(|| unreachable!());
        //print!("complex_tx={}", complex_tx);
        assert_eq!(
            complex_tx,
            "Version: 10
Type: Transaction
Currency: test
Blockstamp: 0-0000000000000000000000000000000000000000000000000000000000000000
Locktime: 0
Issuers:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Inputs:
10:0:D:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0
30:0:T:0000000000000000000000000000000000000000000000000000000000000000:1
Unlocks:
0:SIG(0)
0:SIG(1)
Outputs:
2:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
3:0:SIG(BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)
35:0:SIG(CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC)
Comment: toto
"
        );

        Ok(())
    }

    #[test]
    fn gen_simple_tx() {
        let tx_hash = Hash::default();
        let mut inputs = vec![
            TransactionInputV10 {
                amount: SourceAmount::with_base0(20),
                id: SourceIdV10::Utxo(UtxoIdV10 {
                    tx_hash,
                    output_index: 0,
                }),
            },
            TransactionInputV10 {
                amount: SourceAmount::with_base0(20),
                id: SourceIdV10::Utxo(UtxoIdV10 {
                    tx_hash,
                    output_index: 1,
                }),
            },
        ];
        let issuer = unwrap!(ed25519::PublicKey::from_base58(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        let recipient = unwrap!(ed25519::PublicKey::from_base58(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        ));
        let cash_back_pubkey = unwrap!(ed25519::PublicKey::from_base58(
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        ));

        let txs = TransactionDocV10SimpleGen {
            blockstamp: Blockstamp::default(),
            currency: "test".to_owned(),
            inputs: inputs.clone(),
            inputs_sum: SourceAmount::with_base0(40),
            issuer,
            recipient,
            user_amount: SourceAmount::with_base0(32),
            user_comment: "toto".to_owned(),
            cash_back_pubkey: Some(cash_back_pubkey),
        }
        .gen();

        assert_eq!(txs.len(), 1);
        //println!("txs[0]={}", txs[0]);
        assert_eq!(
            &txs[0],
            "Version: 10
Type: Transaction
Currency: test
Blockstamp: 0-0000000000000000000000000000000000000000000000000000000000000000
Locktime: 0
Issuers:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Inputs:
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:0
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:1
Unlocks:
0:SIG(0)
1:SIG(0)
Outputs:
32:0:SIG(BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)
8:0:SIG(CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC)
Comment: toto
"
        );

        inputs.push(TransactionInputV10 {
            amount: SourceAmount::with_base0(20),
            id: SourceIdV10::Utxo(UtxoIdV10 {
                tx_hash,
                output_index: 2,
            }),
        });
        inputs.push(TransactionInputV10 {
            amount: SourceAmount::with_base0(20),
            id: SourceIdV10::Utxo(UtxoIdV10 {
                tx_hash,
                output_index: 3,
            }),
        });

        let txs = TransactionDocV10SimpleGen {
            blockstamp: Blockstamp::default(),
            currency: "test".to_owned(),
            inputs,
            inputs_sum: SourceAmount::with_base0(80),
            issuer,
            recipient,
            user_amount: SourceAmount::with_base0(62),
            user_comment: "toto".to_owned(),
            cash_back_pubkey: None,
        }
        .gen();

        assert_eq!(txs.len(), 1);
        //println!("txs[0]={}", txs[0]);
        assert_eq!(
            &txs[0],
            "Version: 10
Type: Transaction
Currency: test
Blockstamp: 0-0000000000000000000000000000000000000000000000000000000000000000
Locktime: 0
Issuers:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Inputs:
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:0
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:1
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:2
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:3
Unlocks:
0:SIG(0)
1:SIG(0)
2:SIG(0)
3:SIG(0)
Outputs:
80:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
Comment: change
"
        );
    }
}
