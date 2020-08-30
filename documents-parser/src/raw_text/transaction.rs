use crate::*;

pub(crate) mod v10;

impl FromPestPair for TransactionDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let tx_vx_pair = unwrap!(pair.into_inner().next()); // get and unwrap the `tx_vX` rule; never fails

        match tx_vx_pair.as_rule() {
            Rule::tx_v10 => {
                TransactionDocumentV10::from_pest_pair(tx_vx_pair).map(TransactionDocument::V10)
            }
            _ => Err(RawTextParseError::UnexpectedRule(format!(
                "{:#?}",
                tx_vx_pair.as_rule()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_transaction_document() {
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

        let doc = TransactionDocument::parse_from_raw_text(doc)
            .expect("fail to parse test transaction document !");
        //println!("Doc : {:?}", doc);
        println!("{}", doc.generate_compact_text());
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
