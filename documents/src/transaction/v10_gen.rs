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

pub(crate) struct TransactionDocV10SimpleGen {
    pub(crate) blockstamp: Blockstamp,
    pub(crate) currency: String,
    pub(crate) inputs: Vec<TransactionInputV10>,
    pub(crate) inputs_sum: SourceAmount,
    pub(crate) inputs_per_tx: usize,
    pub(crate) issuer: ed25519::PublicKey,
    pub(crate) recipient: ed25519::PublicKey,
    pub(crate) user_amount: SourceAmount,
    pub(crate) user_comment: String,
}

impl TransactionDocV10SimpleGen {
    pub(crate) fn gen(self) -> Vec<RawTx> {
        let inputs_count = self.inputs.len();
        if inputs_count > self.inputs_per_tx {
            /*let (mut txs, final_changes_sources) = */
            gen_change_txs(
                self.blockstamp,
                self.currency.clone(),
                self.inputs,
                self.inputs_per_tx,
                self.issuer,
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
            vec![gen_simple_tx_with_inputs(
                self.user_amount,
                self.blockstamp,
                self.user_comment,
                self.currency,
                (self.inputs.as_ref(), self.inputs_sum),
                self.issuer,
                self.recipient,
            )]
        }
    }
}

fn gen_simple_tx_with_inputs(
    amount: SourceAmount,
    blockstamp: Blockstamp,
    comment: String,
    currency: String,
    inputs_with_sum: (&[TransactionInputV10], SourceAmount),
    issuer: ed25519::PublicKey,
    recipient: ed25519::PublicKey,
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
                    issuer,
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

fn gen_change_txs(
    blockstamp: Blockstamp,
    currency: String,
    inputs: Vec<TransactionInputV10>,
    inputs_per_tx: usize,
    issuer: ed25519::PublicKey,
) -> Vec<RawTx> {
    let inputs_len = inputs.len();
    let div = inputs_len / inputs_per_tx;
    let rest = inputs_len % inputs_per_tx;
    let txs_count = div + std::cmp::min(rest, 1);
    let mut txs = Vec::with_capacity(txs_count);

    let mut cursor = 0;
    for _ in 0..div {
        let next_cursor = cursor + inputs_per_tx;
        let tx_inputs = &inputs[cursor..next_cursor];
        let tx_inputs_sum = tx_inputs.iter().map(|i| i.amount).sum();
        txs.push(gef_one_change_tx(
            blockstamp,
            currency.clone(),
            (tx_inputs, tx_inputs_sum),
            issuer,
        ));
        cursor = next_cursor;
    }
    if rest > 1 {
        let tx_inputs = &inputs[cursor..];
        let tx_inputs_sum = tx_inputs.iter().map(|i| i.amount).sum();
        txs.push(gef_one_change_tx(
            blockstamp,
            currency,
            (tx_inputs, tx_inputs_sum),
            issuer,
        ));
    }
    txs
}

fn gef_one_change_tx(
    blockstamp: Blockstamp,
    currency: String,
    inputs_with_sum: (&[TransactionInputV10], SourceAmount),
    issuer: ed25519::PublicKey,
) -> String {
    let (inputs, inputs_sum) = inputs_with_sum;
    let inputs_len = inputs.len();
    let unlocks = (0..inputs_len)
        .into_iter()
        .map(TransactionInputUnlocksV10::single_index)
        .collect::<Vec<_>>();

    let main_output = TransactionOutputV10 {
        amount: inputs_sum,
        conditions: UTXOConditions::from(WalletScriptV10::single(WalletConditionV10::Sig(issuer))),
    };

    TransactionDocumentV10Builder {
        currency: &currency,
        blockstamp,
        locktime: 0,
        issuers: svec![issuer],
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
            TransactionInputV10 {
                amount: SourceAmount::with_base0(20),
                id: SourceIdV10::Utxo(UtxoIdV10 {
                    tx_hash,
                    output_index: 2,
                }),
            },
        ];
        let issuer = unwrap!(ed25519::PublicKey::from_base58(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        let recipient = unwrap!(ed25519::PublicKey::from_base58(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        ));

        let txs = TransactionDocV10SimpleGen {
            blockstamp: Blockstamp::default(),
            currency: "test".to_owned(),
            inputs: inputs.clone(),
            inputs_sum: SourceAmount::with_base0(60),
            inputs_per_tx: 3,
            issuer,
            recipient,
            user_amount: SourceAmount::with_base0(42),
            user_comment: "toto".to_owned(),
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
Unlocks:
0:SIG(0)
1:SIG(0)
2:SIG(0)
Outputs:
42:0:SIG(BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)
18:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
Comment: toto
"
        );

        let txs = TransactionDocV10SimpleGen {
            blockstamp: Blockstamp::default(),
            currency: "test".to_owned(),
            inputs: inputs.clone(),
            inputs_sum: SourceAmount::with_base0(60),
            inputs_per_tx: 2,
            issuer,
            recipient,
            user_amount: SourceAmount::with_base0(42),
            user_comment: "toto".to_owned(),
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
40:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
Comment: change
"
        );

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
            inputs_per_tx: 2,
            issuer,
            recipient,
            user_amount: SourceAmount::with_base0(65),
            user_comment: "toto".to_owned(),
        }
        .gen();

        assert_eq!(txs.len(), 2);
        //println!("txs[0]={}", txs[0]);
        //println!("txs[1]={}", txs[1]);
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
40:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
Comment: change
"
        );
        assert_eq!(
            &txs[1],
            "Version: 10
Type: Transaction
Currency: test
Blockstamp: 0-0000000000000000000000000000000000000000000000000000000000000000
Locktime: 0
Issuers:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Inputs:
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:2
20:0:T:0000000000000000000000000000000000000000000000000000000000000000:3
Unlocks:
0:SIG(0)
1:SIG(0)
Outputs:
40:0:SIG(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
Comment: change
"
        );
    }
}
