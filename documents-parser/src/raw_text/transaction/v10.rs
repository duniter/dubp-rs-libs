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
        let mut unlock_conds = SmallVec::new();
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
        let script = WalletScriptV10::from_pest_pair(script_pairs)?;

        Ok(TransactionOutputV10 {
            amount,
            conditions: UTXOConditions {
                origin_str: None,
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
    fn parse_tx_with_invalid_output_cond() -> Result<(), TextParseError> {
        let tx_stringified = TransactionDocumentV10Stringified {
            currency: "g1".to_owned(),
            blockstamp: "71327-0000883B04D983D9C6461D2AD2E67E3DF050B9065ADB6A5514A8BE16EF343E67".to_owned(),
            locktime: 0,
            issuers: vec!["7t38cKwaBN9e6KymPnPS7SDc4bSJEMML1mTyKg4sDtiY".to_owned()],
            inputs: vec!["45249:0:T:E774E2C45B4C93C5008CA466ED9BDC3F698AD5CED4FB2899083DBF28C633A1C4:0".to_owned()],
            unlocks: vec!["0:SIG(0)".to_owned()],
            outputs: vec![
                "45229:0:SIG(7t38cKwaBN9e6KymPnPS7SDc4bSJEMML1mTyKg4sDtiY)".to_owned(),
                "20:0:XHX(6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B))".to_owned()
            ],
            comment: "".to_owned(),
            signatures: vec!["KoO0768jC+M+8MKa02awEbd/CIR1dq1Ee5OGeMlnmIlaoYubwONfkqi5LNVJ2apncQRNhjBYDnFpTbE8OmRLDg==".to_owned()],
            hash: None,
        };

        let tx = TransactionDocumentV10::from_string_object(&tx_stringified)?;

        println!("tx={}", tx.as_text());

        assert_eq!(
            tx.as_text(),
            "Version: 10
Type: Transaction
Currency: g1
Blockstamp: 71327-0000883B04D983D9C6461D2AD2E67E3DF050B9065ADB6A5514A8BE16EF343E67
Locktime: 0
Issuers:
7t38cKwaBN9e6KymPnPS7SDc4bSJEMML1mTyKg4sDtiY
Inputs:
45249:0:T:E774E2C45B4C93C5008CA466ED9BDC3F698AD5CED4FB2899083DBF28C633A1C4:0
Unlocks:
0:SIG(0)
Outputs:
45229:0:SIG(7t38cKwaBN9e6KymPnPS7SDc4bSJEMML1mTyKg4sDtiY)
20:0:XHX(6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B))
Comment: 
"
        );

        Ok(())
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
