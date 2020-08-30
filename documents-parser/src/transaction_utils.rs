use crate::*;

pub(crate) fn tx_input_v10_from_str(
    source: &str,
) -> Result<TransactionInputV10, RawTextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_input, source)
        .map_err(|e| RawTextParseError::PestError(e.into()))?;
    TransactionInputV10::from_pest_pair(unwrap!(doc_pairs.next())) // get and unwrap the `tx_input` rule; never fails
}

pub(crate) fn tx_unlock_v10_from_str(
    source: &str,
) -> Result<TransactionInputUnlocksV10, RawTextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_unlock, source)
        .map_err(|e| RawTextParseError::PestError(e.into()))?;
    TransactionInputUnlocksV10::from_pest_pair(unwrap!(doc_pairs.next())) // get and unwrap the `tx_unlock` rule; never fails
}

pub(crate) fn tx_output_v10_from_str(
    source: &str,
) -> Result<TransactionOutputV10, RawTextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_output, source)
        .map_err(|e| RawTextParseError::PestError(e.into()))?;
    TransactionOutputV10::from_pest_pair(unwrap!(doc_pairs.next())) // get and unwrap the `tx_output` rule; never fails
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tx_output_v10_single() -> Result<(), RawTextParseError> {
        let output_v10_str = "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i)";

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount {
                    amount: 49,
                    base: 2,
                },
                conditions: UTXOConditions::from(WalletScriptV10::Single(WalletConditionV10::Sig(
                    unwrap!(PublicKey::from_base58(
                        "6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i"
                    ))
                )))
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }

    #[test]
    fn parse_tx_output_v10_or() -> Result<(), RawTextParseError> {
        let output_v10_str = "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA)";

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount {
                    amount: 49,
                    base: 2,
                },
                conditions: UTXOConditions::from(WalletScriptV10::Or(
                    Box::new(WalletScriptV10::Single(WalletConditionV10::Sig(unwrap!(
                        PublicKey::from_base58("6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i")
                    )))),
                    Box::new(WalletScriptV10::Single(WalletConditionV10::Xhx(unwrap!(
                        Hash::from_hex(
                            "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                        )
                    ))))
                ))
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }

    #[test]
    fn parse_tx_output_v10_or_in_brakets() -> Result<(), RawTextParseError> {
        let output_v10_str = "49:2:(SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA))";

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount {
                    amount: 49,
                    base: 2,
                },
                conditions: UTXOConditions::from(WalletScriptV10::Brackets(Box::new(
                    WalletScriptV10::Or(
                        Box::new(WalletScriptV10::Single(WalletConditionV10::Sig(unwrap!(
                            PublicKey::from_base58("6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i")
                        )))),
                        Box::new(WalletScriptV10::Single(WalletConditionV10::Xhx(unwrap!(
                            Hash::from_hex(
                                "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                            )
                        ))))
                    )
                )))
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }

    #[test]
    fn parse_tx_output_v10_or_and() -> Result<(), RawTextParseError> {
        let output_v10_str =
            "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA) && SIG(42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp)";

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount {
                    amount: 49,
                    base: 2,
                },
                conditions: UTXOConditions::from(WalletScriptV10::Or(
                    Box::new(WalletScriptV10::Single(WalletConditionV10::Sig(unwrap!(
                        PublicKey::from_base58("6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i")
                    )))),
                    Box::new(WalletScriptV10::And(
                        Box::new(WalletScriptV10::Single(WalletConditionV10::Xhx(unwrap!(
                            Hash::from_hex(
                                "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                            )
                        )))),
                        Box::new(WalletScriptV10::Single(WalletConditionV10::Sig(unwrap!(
                            PublicKey::from_base58("42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp")
                        )))),
                    )),
                ))
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }
}
