use crate::*;

pub fn wallet_script_from_str(source: &str) -> Result<WalletScriptV10, RawTextParseError> {
    let mut pairs = RawDocumentsParser::parse(Rule::output_conds, source)
        .map_err(|e| RawTextParseError::PestError(e.into()))?;
    WalletScriptV10::from_pest_pair(pairs.next().unwrap_or_else(|| unreachable!()))
    // get and unwrap the `output_conds` rule; never fails
}

impl FromPestPair for WalletScriptV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let mut pairs = pair.into_inner();
        let term_left_pair = pairs.next().unwrap_or_else(|| unreachable!());

        let mut nodes = SmallVec::new();

        let term_left = parse_term(term_left_pair, &mut nodes);
        let root = parse_op(term_left, pairs, &mut nodes);

        Ok(WalletScriptV10 { root, nodes })
    }
}

impl FromPestPair for WalletConditionV10 {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        Ok(match pair.as_rule() {
            Rule::output_cond_sig => WalletConditionV10::Sig(
                ed25519::PublicKey::from_base58(
                    pair.into_inner()
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str(),
                )
                .unwrap_or_else(|_| unreachable!()),
            ),
            Rule::output_cond_xhx => WalletConditionV10::Xhx(
                Hash::from_hex(
                    pair.into_inner()
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str(),
                )
                .unwrap_or_else(|_| unreachable!()),
            ),
            Rule::output_cond_csv => WalletConditionV10::Csv(
                pair.into_inner()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .as_str()
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            Rule::output_cond_cltv => WalletConditionV10::Cltv(
                pair.into_inner()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .as_str()
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        })
    }
}

#[inline]
fn parse_term(pair: Pair<Rule>, nodes: &mut WalletScriptNodesV10) -> WalletSubScriptV10 {
    match pair.as_rule() {
        Rule::output_conds_brackets_expr => {
            let mut pairs = pair.into_inner();
            let term_left_pair = pairs.next().unwrap_or_else(|| unreachable!());
            let term_left = parse_term(term_left_pair, nodes);
            let sub_root = parse_op(term_left, pairs, nodes);
            let sub_script = WalletSubScriptV10::Brackets(nodes.len());
            nodes.push(sub_root);
            sub_script
        }
        Rule::output_single_cond => WalletSubScriptV10::Single(
            WalletConditionV10::from_pest_pair(
                pair.into_inner().next().unwrap_or_else(|| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!()),
        ),
        r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
    }
}

fn parse_op(
    left: WalletSubScriptV10,
    mut pairs: Pairs<Rule>,
    nodes: &mut WalletScriptNodesV10,
) -> WalletSubScriptV10 {
    if let Some(pair) = pairs.next() {
        let left_index = nodes.len();
        nodes.push(left);
        let next_left_term = parse_term(pairs.next().unwrap_or_else(|| unreachable!()), nodes);
        let right = parse_op(next_left_term, pairs, nodes);
        let right_index = nodes.len();
        nodes.push(right);
        match pair.as_rule() {
            Rule::output_cond_op_and => WalletSubScriptV10::And(left_index, right_index),
            Rule::output_cond_op_or => WalletSubScriptV10::Or(left_index, right_index),
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        }
    } else {
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn parse_complex_wallet_script_v10() -> Result<(), RawTextParseError> {
        let script_v10_str =
            "SIG(6DyGr5LFtFmbaJYRvcs9WmBsr4cbJbJ1EV9zBbqG7A6i) || (XHX(3EB4702F2AC2FD3FA4FDC46A4FC05AE8CDEE1A85F2AC2FD3FA4FDC46A4FC01CA) && SIG(42jMJtb8chXrpHMAMcreVdyPJK7LtWjEeRqkPw4eSEVp))";
        let expected_script = WalletScriptV10 {
            root: WalletSubScriptV10::Or(0, 4),
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
                WalletSubScriptV10::Brackets(3),
            ],
        };

        assert_eq!(script_v10_str, expected_script.to_string(),);

        assert_eq!(expected_script, wallet_script_from_str(script_v10_str)?);

        Ok(())
    }
}
