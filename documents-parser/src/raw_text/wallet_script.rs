use crate::*;

pub fn wallet_script_from_str(source: &str) -> Result<WalletConditionV10, RawTextParseError> {
    let mut pairs = RawDocumentsParser::parse(Rule::output_conds, source)
        .map_err(|e| RawTextParseError::PestError(e.into()))?;
    WalletConditionV10::from_pest_pair(unwrap!(pairs.next())) // get and unwrap the `output_conds` rule; never fails
}

impl FromPestPair for WalletScriptV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let mut pairs = pair.into_inner();
        let term_left_pair = unwrap!(pairs.next());

        Ok(parse_op(parse_term(term_left_pair), pairs))
    }
}

impl FromPestPair for WalletConditionV10 {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        Ok(match pair.as_rule() {
            Rule::output_cond_sig => WalletConditionV10::Sig(unwrap!(
                ed25519::PublicKey::from_base58(unwrap!(pair.into_inner().next()).as_str())
            )),
            Rule::output_cond_xhx => WalletConditionV10::Xhx(unwrap!(Hash::from_hex(
                unwrap!(pair.into_inner().next()).as_str()
            ))),
            Rule::output_cond_csv => {
                WalletConditionV10::Csv(unwrap!(unwrap!(pair.into_inner().next()).as_str().parse()))
            }
            Rule::output_cond_cltv => {
                WalletConditionV10::Cltv(unwrap!(unwrap!(pair.into_inner().next())
                    .as_str()
                    .parse()))
            }
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        })
    }
}

#[inline]
fn parse_term(pair: Pair<Rule>) -> WalletScriptV10 {
    match pair.as_rule() {
        Rule::output_conds_brackets_expr => {
            WalletScriptV10::Brackets(Box::new(unwrap!(WalletScriptV10::from_pest_pair(pair))))
        }
        Rule::output_single_cond => {
            WalletScriptV10::Single(unwrap!(WalletConditionV10::from_pest_pair(unwrap!(pair
                .into_inner()
                .next()))))
        }
        r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
    }
}

fn parse_op(left: WalletScriptV10, mut pairs: Pairs<Rule>) -> WalletScriptV10 {
    if let Some(pair) = pairs.next() {
        match pair.as_rule() {
            Rule::output_cond_op_and => WalletScriptV10::And(
                Box::new(left),
                Box::new(parse_op(parse_term(unwrap!(pairs.next())), pairs)),
            ),
            Rule::output_cond_op_or => WalletScriptV10::Or(
                Box::new(left),
                Box::new(parse_op(parse_term(unwrap!(pairs.next())), pairs)),
            ),
            r => panic!("unexpected rule: {:?}", r), // Grammar ensures that we never reach this line
        }
    } else {
        left
    }
}
