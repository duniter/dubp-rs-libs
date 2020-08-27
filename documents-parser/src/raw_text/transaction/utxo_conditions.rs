use crate::*;

impl FromPestPair for TransactionOutputCondition {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        Ok(match pair.as_rule() {
            Rule::output_cond_sig => TransactionOutputCondition::Sig(PubKey::Ed25519(unwrap!(
                ed25519::PublicKey::from_base58(unwrap!(pair.into_inner().next()).as_str())
            ))),
            Rule::output_cond_xhx => TransactionOutputCondition::Xhx(unwrap!(Hash::from_hex(
                unwrap!(pair.into_inner().next()).as_str()
            ))),
            Rule::output_cond_csv => {
                TransactionOutputCondition::Csv(unwrap!(unwrap!(pair.into_inner().next())
                    .as_str()
                    .parse()))
            }
            Rule::output_cond_cltv => {
                TransactionOutputCondition::Cltv(unwrap!(unwrap!(pair.into_inner().next())
                    .as_str()
                    .parse()))
            }
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        })
    }
}

#[inline]
fn parse_term(pair: Pair<Rule>) -> UTXOConditionsGroup {
    match pair.as_rule() {
        Rule::output_conds_brackets_expr => UTXOConditionsGroup::Brackets(Box::new(unwrap!(
            UTXOConditionsGroup::from_pest_pair(pair)
        ))),
        Rule::output_single_cond => UTXOConditionsGroup::Single(unwrap!(
            TransactionOutputCondition::from_pest_pair(unwrap!(pair.into_inner().next()))
        )),
        r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
    }
}

fn parse_op(left: UTXOConditionsGroup, mut pairs: Pairs<Rule>) -> UTXOConditionsGroup {
    if let Some(pair) = pairs.next() {
        match pair.as_rule() {
            Rule::output_cond_op_and => UTXOConditionsGroup::And(
                Box::new(left),
                Box::new(parse_op(parse_term(unwrap!(pairs.next())), pairs)),
            ),
            Rule::output_cond_op_or => UTXOConditionsGroup::Or(
                Box::new(left),
                Box::new(parse_op(parse_term(unwrap!(pairs.next())), pairs)),
            ),
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        }
    } else {
        left
    }
}

impl FromPestPair for UTXOConditionsGroup {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let mut pairs = pair.into_inner();
        let term_left_pair = unwrap!(pairs.next());

        Ok(parse_op(parse_term(term_left_pair), pairs))
    }
}
