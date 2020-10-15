use crate::*;

pub(crate) fn tx_input_v10_from_str(source: &str) -> Result<TransactionInputV10, TextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_input, source)
        .map_err(|e| TextParseError::PestError(e.into()))?;
    TransactionInputV10::from_pest_pair(doc_pairs.next().unwrap_or_else(|| unreachable!()))
    // get and unwrap the `tx_input` rule; never fails
}

pub fn tx_unlock_v10_from_str(source: &str) -> Result<TransactionInputUnlocksV10, TextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_unlock, source)
        .map_err(|e| TextParseError::PestError(e.into()))?;
    TransactionInputUnlocksV10::from_pest_pair(doc_pairs.next().unwrap_or_else(|| unreachable!()))
    // get and unwrap the `tx_unlock` rule; never fails
}

pub(crate) fn tx_output_v10_from_str(source: &str) -> Result<TransactionOutputV10, TextParseError> {
    let mut doc_pairs = RawDocumentsParser::parse(Rule::tx_output, source)
        .map_err(|e| TextParseError::PestError(e.into()))?;
    TransactionOutputV10::from_pest_pair(doc_pairs.next().unwrap_or_else(|| unreachable!()))
    // get and unwrap the `tx_output` rule; never fails
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use dubp_documents::smallvec::smallvec as svec;
    use unwrap::unwrap;

    #[test]
    fn parse_tx_output_v10_single() -> Result<(), TextParseError> {
        let output_v10_str = "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i)";

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount::new(49, 2),
                conditions: UTXOConditions::from(WalletScriptV10::single(WalletConditionV10::Sig(
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
    fn parse_tx_output_v10_or() -> Result<(), TextParseError> {
        let output_v10_str = "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA)";
        let expected_script = WalletScriptV10 {
            root: WalletSubScriptV10::Or(0, 1),
            nodes: svec![
                WalletSubScriptV10::Single(WalletConditionV10::Sig(pk(
                    "6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i"
                ))),
                WalletSubScriptV10::Single(WalletConditionV10::Xhx(h(
                    "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                )))
            ],
        };

        assert_eq!(output_v10_str[5..], expected_script.to_string(),);

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount::new(49, 2),
                conditions: UTXOConditions::from(expected_script)
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }

    #[test]
    fn parse_tx_output_v10_or_in_brakets() -> Result<(), TextParseError> {
        let output_v10_str = "49:2:(SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA))";
        let expected_script = WalletScriptV10 {
            root: WalletSubScriptV10::Brackets(2),
            nodes: svec![
                WalletSubScriptV10::Single(WalletConditionV10::Sig(pk(
                    "6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i"
                ))),
                WalletSubScriptV10::Single(WalletConditionV10::Xhx(h(
                    "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                ))),
                WalletSubScriptV10::Or(0, 1),
            ],
        };

        assert_eq!(output_v10_str[5..], expected_script.to_string(),);

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount::new(49, 2),
                conditions: UTXOConditions::from(expected_script)
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }

    #[test]
    fn parse_tx_output_v10_or_and() -> Result<(), TextParseError> {
        let output_v10_str =
            "49:2:SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA) && SIG(42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp)";
        let expected_script = WalletScriptV10 {
            root: WalletSubScriptV10::Or(0, 3),
            nodes: svec![
                WalletSubScriptV10::Single(WalletConditionV10::Sig(pk(
                    "6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i"
                ))),
                WalletSubScriptV10::Single(WalletConditionV10::Xhx(h(
                    "3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA"
                ))),
                WalletSubScriptV10::Single(WalletConditionV10::Sig(pk(
                    "42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp"
                ))),
                WalletSubScriptV10::And(1, 2),
            ],
        };

        assert_eq!(output_v10_str[5..], expected_script.to_string(),);

        assert_eq!(
            TransactionOutputV10 {
                amount: SourceAmount::new(49, 2),
                conditions: UTXOConditions::from(expected_script)
            },
            tx_output_v10_from_str(output_v10_str)?
        );

        Ok(())
    }
}
