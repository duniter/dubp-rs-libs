use crate::*;

impl FromPestPair for TransactionDocumentV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<TransactionDocumentV10, TextParseError> {
        let mut currency = "";
        let mut blockstamp = Blockstamp::default();
        let mut locktime = 0;
        let mut issuers = SmallVec::new();
        let mut inputs = Vec::new();
        let mut unlocks = Vec::new();
        let mut outputs = SmallVec::new();
        let mut comment = "";
        let mut sigs = SmallVec::new();

        for field in pair.into_inner() {
            match field.as_rule() {
                Rule::currency => currency = field.as_str(),
                Rule::blockstamp => {
                    let mut inner_rules = field.into_inner(); // ${ block_id ~ "-" ~ hash }

                    let block_number: &str = inner_rules
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str();
                    let block_hash: &str = inner_rules
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str();
                    blockstamp = Blockstamp {
                        number: BlockNumber(
                            block_number.parse().unwrap_or_else(|_| unreachable!()),
                        ), // Grammar ensures that we have a digits string.
                        hash: BlockHash(
                            Hash::from_hex(block_hash).unwrap_or_else(|_| unreachable!()),
                        ), // Grammar ensures that we have an hexadecimal string.
                    };
                }
                Rule::tx_locktime => {
                    locktime = field.as_str().parse().unwrap_or_else(|_| unreachable!())
                } // Grammar ensures that we have digits characters.
                Rule::pubkey => issuers.push(
                    ed25519::PublicKey::from_base58(field.as_str())
                        .unwrap_or_else(|_| unreachable!()), // Grammar ensures that we have a base58 string.
                ),
                Rule::tx_input => inputs.push(TransactionInputV10::from_pest_pair(field)?),
                Rule::tx_unlock => unlocks.push(TransactionInputUnlocksV10::from_pest_pair(field)?),
                Rule::tx_output => outputs.push(TransactionOutputV10::from_pest_pair(field)?),
                Rule::tx_comment => comment = field.as_str(),
                Rule::ed25519_sig => {
                    sigs.push(
                        ed25519::Signature::from_base64(field.as_str()).unwrap_or_else(
                            |_| unreachable!(), // Grammar ensures that we have a base64 string.
                        ),
                    );
                }
                Rule::EOI => (),
                _ => panic!("unexpected rule: {:?}", field.as_rule()), // Grammar ensures that we never reach this line
            }
        }

        Ok(TransactionDocumentV10Builder {
            currency,
            blockstamp,
            locktime,
            issuers,
            inputs: &inputs[..],
            unlocks: &unlocks[..],
            outputs,
            comment,
            hash: None,
        }
        .build_with_signature(sigs))
    }
}

impl FromPestPair for TransactionInputV10 {
    fn from_pest_pair(pairs: Pair<Rule>) -> Result<TransactionInputV10, TextParseError> {
        let tx_input_type_pair = pairs.into_inner().next().unwrap_or_else(|| unreachable!());
        Ok(match tx_input_type_pair.as_rule() {
            Rule::tx_input_du => {
                let mut inner_rules = tx_input_type_pair.into_inner(); // ${ tx_amount ~ ":" ~ tx_amount_base ~ ":D:" ~ pubkey ~ ":" ~ du_block_id }

                TransactionInputV10 {
                    amount: SourceAmount::new(
                        inner_rules
                            .next()
                            .unwrap_or_else(|| unreachable!())
                            .as_str()
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                        inner_rules
                            .next()
                            .unwrap_or_else(|| unreachable!())
                            .as_str()
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                    id: SourceIdV10::Ud(UdSourceIdV10 {
                        issuer: ed25519::PublicKey::from_base58(
                            inner_rules
                                .next()
                                .unwrap_or_else(|| unreachable!())
                                .as_str(),
                        )
                        .unwrap_or_else(|_| unreachable!()),
                        block_number: BlockNumber(
                            inner_rules
                                .next()
                                .unwrap_or_else(|| unreachable!())
                                .as_str()
                                .parse()
                                .unwrap_or_else(|_| unreachable!()),
                        ),
                    }),
                }
            }
            Rule::tx_input_tx => {
                let mut inner_rules = tx_input_type_pair.into_inner(); // ${ tx_amount ~ ":" ~ tx_amount_base ~ ":D:" ~ pubkey ~ ":" ~ du_block_id }

                TransactionInputV10 {
                    amount: SourceAmount::new(
                        inner_rules
                            .next()
                            .unwrap_or_else(|| unreachable!())
                            .as_str()
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                        inner_rules
                            .next()
                            .unwrap_or_else(|| unreachable!())
                            .as_str()
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                    id: SourceIdV10::Utxo(UtxoIdV10 {
                        tx_hash: Hash::from_hex(
                            inner_rules
                                .next()
                                .unwrap_or_else(|| unreachable!())
                                .as_str(),
                        )
                        .unwrap_or_else(|_| unreachable!()),
                        output_index: inner_rules
                            .next()
                            .unwrap_or_else(|| unreachable!())
                            .as_str()
                            .parse()
                            .unwrap_or_else(|_| unreachable!()),
                    }),
                }
            }
            _ => panic!("unexpected rule: {:?}", tx_input_type_pair.as_rule()), // Grammar ensures that we never reach this line
        })
    }
}

impl FromPestPair for TransactionInputUnlocksV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<TransactionInputUnlocksV10, TextParseError> {
        let mut input_index = 0;
        let mut unlock_conds = Vec::new();
        for unlock_field in pair.into_inner() {
            // ${ input_index ~ ":" ~ unlock_cond ~ (" " ~ unlock_cond)* }
            match unlock_field.as_rule() {
                Rule::input_index => {
                    input_index = unlock_field
                        .as_str()
                        .parse()
                        .unwrap_or_else(|_| unreachable!())
                }
                Rule::unlock_sig => unlock_conds.push(WalletUnlockProofV10::Sig(
                    unlock_field
                        .into_inner()
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str()
                        .parse()
                        .unwrap_or_else(|_| unreachable!()),
                )),
                Rule::unlock_xhx => unlock_conds.push(WalletUnlockProofV10::Xhx(String::from(
                    unlock_field
                        .into_inner()
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str(),
                ))),
                _ => panic!("unexpected rule: {:?}", unlock_field.as_rule()), // Grammar ensures that we never reach this line
            }
        }
        Ok(TransactionInputUnlocksV10 {
            index: input_index,
            unlocks: unlock_conds,
        })
    }
}

impl FromPestPair for TransactionOutputV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<TransactionOutputV10, TextParseError> {
        let mut utxo_pairs = pair.into_inner();
        let amount = SourceAmount::new(
            utxo_pairs
                .next()
                .unwrap_or_else(|| unreachable!())
                .as_str()
                .parse()
                .unwrap_or_else(|_| unreachable!()),
            utxo_pairs
                .next()
                .unwrap_or_else(|| unreachable!())
                .as_str()
                .parse()
                .unwrap_or_else(|_| unreachable!()),
        );
        let script_pairs = utxo_pairs.next().unwrap_or_else(|| unreachable!());
        let script_origin_str = script_pairs.as_str();
        let script = WalletScriptV10::from_pest_pair(script_pairs)?;

        Ok(TransactionOutputV10 {
            amount,
            conditions: UTXOConditions {
                origin_str: if script_origin_str != script.to_string() {
                    //println!("TMP DEBUG script_origin_str={}", script_origin_str);
                    //println!("TMP DEBUG conditions={:#?}", script);
                    //println!("TMP DEBUG conditions.to_string()={}", script.to_string());
                    Some(script_origin_str.to_owned())
                } else {
                    None
                },
                script,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn parse_simple_transaction_document() {
        let doc = "Version: 10
Type: Transaction
Currency: BETA_BROUZOUF2
Blockstamp: 3-94C1E4508A314E31B28ECCE4E21C65EBCD7F3267D2A468D65D9278B73AE0A0DA
Locktime: 0
Issuers:
DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
Inputs:
120:0:T:71A1E79DD17762A9869D7FBD2FEBAC2738CBB7506CB758C7B3C2DD548BAA42D2:0
Unlocks:
0:XHX(1872767826647264) SIG(0)
Outputs:
120:0:SIG(DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV)
Comment: tic takes money on BETA_BROUZOUF
hfncr3i2TMfyu+SFgUQOkE9Hfw23Sxgk/WF2SR3jXfaaEhM8wFYEVyJsgSWPAKrBqQl+jhVkXMQc6lnzjD/EDA==
";
        let doc = unwrap!(TransactionDocumentV10::parse_from_raw_text(doc));
        println!("doc={:?}", doc);
        assert!(doc.verify_signatures().is_ok());
    }

    #[test]
    fn parse_complex_transaction_document() {
        let doc = "Version: 10
Type: Transaction
Currency: duniter_unit_test_currency
Blockstamp: 204-00003E2B8A35370BA5A7064598F628A62D4E9EC1936BE8651CE9A85F2E06981B
Locktime: 0
Issuers:
DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
4tNQ7d9pj2Da5wUVoW9mFn7JjuPoowF977au8DdhEjVR
FD9wujR7KABw88RyKEGBYRLz8PA6jzVCbcBAsrBXBqSa
Inputs:
40:2:T:6991C993631BED4733972ED7538E41CCC33660F554E3C51963E2A0AC4D6453D3:2
70:2:T:3A09A20E9014110FD224889F13357BAB4EC78A72F95CA03394D8CCA2936A7435:8
20:2:D:DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV:46
70:2:T:A0D9B4CDC113ECE1145C5525873821398890AE842F4B318BD076095A23E70956:3
20:2:T:67F2045B5318777CC52CD38B424F3E40DDA823FA0364625F124BABE0030E7B5B:5
15:2:D:FD9wujR7KABw88RyKEGBYRLz8PA6jzVCbcBAsrBXBqSa:46
Unlocks:
0:SIG(0)
1:XHX(7665798292)
2:SIG(0)
3:SIG(0) SIG(2)
4:SIG(0) SIG(1) SIG(2)
5:SIG(2)
Outputs:
120:2:SIG(BYfWYFrsyjpvpFysgu19rGK3VHBkz4MqmQbNyEuVU64g)
146:2:SIG(DSz4rgncXCytsUMW2JU2yhLquZECD2XpEkpP9gG5HyAx)
49:2:(SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA))
Comment: -----@@@----- (why not this comment?)
kL59C1izKjcRN429AlKdshwhWbasvyL7sthI757zm1DfZTdTIctDWlKbYeG/tS7QyAgI3gcfrTHPhu1E1lKCBw==
e3LpgB2RZ/E/BCxPJsn+TDDyxGYzrIsMyDt//KhJCjIQD6pNUxr5M5jrq2OwQZgwmz91YcmoQ2XRQAUDpe4BAw==
w69bYgiQxDmCReB0Dugt9BstXlAKnwJkKCdWvCeZ9KnUCv0FJys6klzYk/O/b9t74tYhWZSX0bhETWHiwfpWBw==";

        let doc = unwrap!(TransactionDocumentV10::parse_from_raw_text(doc));
        assert!(doc.verify_signatures().is_ok());
        assert_eq!(
            doc.generate_compact_text(),
            "TX:10:3:6:6:3:1:0
204-00003E2B8A35370BA5A7064598F628A62D4E9EC1936BE8651CE9A85F2E06981B
DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
4tNQ7d9pj2Da5wUVoW9mFn7JjuPoowF977au8DdhEjVR
FD9wujR7KABw88RyKEGBYRLz8PA6jzVCbcBAsrBXBqSa
40:2:T:6991C993631BED4733972ED7538E41CCC33660F554E3C51963E2A0AC4D6453D3:2
70:2:T:3A09A20E9014110FD224889F13357BAB4EC78A72F95CA03394D8CCA2936A7435:8
20:2:D:DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV:46
70:2:T:A0D9B4CDC113ECE1145C5525873821398890AE842F4B318BD076095A23E70956:3
20:2:T:67F2045B5318777CC52CD38B424F3E40DDA823FA0364625F124BABE0030E7B5B:5
15:2:D:FD9wujR7KABw88RyKEGBYRLz8PA6jzVCbcBAsrBXBqSa:46
0:SIG(0)
1:XHX(7665798292)
2:SIG(0)
3:SIG(0) SIG(2)
4:SIG(0) SIG(1) SIG(2)
5:SIG(2)
120:2:SIG(BYfWYFrsyjpvpFysgu19rGK3VHBkz4MqmQbNyEuVU64g)
146:2:SIG(DSz4rgncXCytsUMW2JU2yhLquZECD2XpEkpP9gG5HyAx)
49:2:(SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA))
-----@@@----- (why not this comment?)
kL59C1izKjcRN429AlKdshwhWbasvyL7sthI757zm1DfZTdTIctDWlKbYeG/tS7QyAgI3gcfrTHPhu1E1lKCBw==
e3LpgB2RZ/E/BCxPJsn+TDDyxGYzrIsMyDt//KhJCjIQD6pNUxr5M5jrq2OwQZgwmz91YcmoQ2XRQAUDpe4BAw==
w69bYgiQxDmCReB0Dugt9BstXlAKnwJkKCdWvCeZ9KnUCv0FJys6klzYk/O/b9t74tYhWZSX0bhETWHiwfpWBw=="
        );
    }
}
