use crate::*;

impl FromPestPair for MembershipDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let ms_vx_pair = unwrap!(
            pair.into_inner().next(),
            "Fail to parse Rule::membership_vX"
        ); // get and unwrap the `membership_vX` rule; never fails

        match ms_vx_pair.as_rule() {
            Rule::membership_v10 => Ok(MembershipDocument::V10(
                MembershipDocumentV10::from_pest_pair(ms_vx_pair)?,
            )),
            _ => Err(RawTextParseError::UnexpectedVersion(format!(
                "{:#?}",
                ms_vx_pair.as_rule()
            ))),
        }
    }
}

impl FromPestPair for MembershipDocumentV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<MembershipDocumentV10, RawTextParseError> {
        let doc = pair.as_str();
        let mut currency = "";
        let mut pubkey_str = "";
        let mut uid = "";
        let mut blockstamps = Vec::with_capacity(2);
        let mut membership = MembershipType::In();
        let mut sig_str = "";
        for field in pair.into_inner() {
            match field.as_rule() {
                Rule::currency => currency = field.as_str(),
                Rule::uid => uid = field.as_str(),
                Rule::pubkey => pubkey_str = field.as_str(),
                Rule::membership_in => membership = MembershipType::In(),
                Rule::membership_out => membership = MembershipType::Out(),
                Rule::blockstamp => {
                    let mut inner_rules = field.into_inner(); // { integer ~ "-" ~ hash }

                    let block_number: &str = unwrap!(inner_rules.next()).as_str();
                    let block_hash: &str = unwrap!(inner_rules.next()).as_str();
                    blockstamps.push(Blockstamp {
                        number: BlockNumber(unwrap!(block_number.parse())), // Grammar ensures that we have a digits string.
                        hash: BlockHash(unwrap!(Hash::from_hex(block_hash))), // Grammar ensures that we have an hexadecimal string.
                    });
                }
                Rule::ed25519_sig => sig_str = field.as_str(),
                Rule::EOI => (),
                _ => panic!("unexpected rule"), // Grammar ensures that we never reach this line
            }
        }

        Ok(MembershipDocumentV10Builder {
            issuer: unwrap!(ed25519::PublicKey::from_base58(pubkey_str)), // Grammar ensures that we have a base58 string.
            currency,
            blockstamp: blockstamps[0],
            membership,
            identity_username: uid,
            identity_blockstamp: blockstamps[1],
        }
        .build_with_text_and_sigs(
            doc.to_owned(),
            svec![unwrap!(ed25519::Signature::from_base64(sig_str))],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_membership_document() {
        let doc = "Version: 10
Type: Membership
Currency: duniter_unit_test_currency
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
Block: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
Membership: IN
UserID: tic
CertTS: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
s2hUbokkibTAWGEwErw6hyXSWlWFQ2UWs2PWx8d/kkElAyuuWaQq4Tsonuweh1xn4AC1TVWt4yMR3WrDdkhnAw==";

        let doc = MembershipDocument::parse_from_raw_text(doc)
            .expect("fail to parse test membership document !");
        println!("Doc : {:?}", doc);
        assert!(doc.verify_signatures().is_ok());
        assert_eq!(
            doc.generate_compact_text(),
                "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV:\
                s2hUbokkibTAWGEwErw6hyXSWlWFQ2UWs2PWx8d/kkElAyuuWaQq4Tsonuweh1xn4AC1TVWt4yMR3WrDdkhnAw==:\
                0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855:\
                0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855:\
                tic"
            );
    }
}
