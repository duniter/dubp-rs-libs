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
fn parse_term(pair: Pair<Rule>, nodes: &mut WalletScriptNodesV10) -> WalletSubScriptV10 {
    match pair.as_rule() {
        Rule::output_conds_brackets_expr => {
            let mut pairs = pair.into_inner();
            let term_left_pair = unwrap!(pairs.next());
            let term_left = parse_term(term_left_pair, nodes);
            let sub_root = parse_op(term_left, pairs, nodes);
            let sub_script = WalletSubScriptV10::Brackets(nodes.len());
            nodes.push(sub_root);
            sub_script
        }
        Rule::output_single_cond => {
            WalletSubScriptV10::Single(unwrap!(WalletConditionV10::from_pest_pair(unwrap!(pair
                .into_inner()
                .next()))))
        }
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
        let next_left_term = parse_term(unwrap!(pairs.next()), nodes);
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
