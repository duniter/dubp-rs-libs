use crate::*;

impl FromPestPair for IdentityDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let idty_vx_pair = unwrap!(pair.into_inner().next()); // get and unwrap the `idty_vx` rule; never fails

        match idty_vx_pair.as_rule() {
            Rule::idty_v10 => Ok(IdentityDocument::V10(IdentityDocumentV10::from_pest_pair(
                idty_vx_pair,
            )?)),
            _ => Err(RawTextParseError::UnexpectedVersion(format!(
                "{:#?}",
                idty_vx_pair.as_rule()
            ))),
        }
    }
}

impl FromPestPair for IdentityDocumentV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<IdentityDocumentV10, RawTextParseError> {
        let doc = pair.as_str();
        let mut currency = "";
        let mut pubkey_str = "";
        let mut uid = "";
        let mut blockstamp = Blockstamp::default();
        let mut sig_str = "";
        for field in pair.into_inner() {
            match field.as_rule() {
                Rule::currency => currency = field.as_str(),
                Rule::pubkey => pubkey_str = field.as_str(),
                Rule::uid => uid = field.as_str(),
                Rule::blockstamp => {
                    let mut inner_rules = field.into_inner(); // { integer ~ "-" ~ hash }

                    let block_number: &str = unwrap!(inner_rules.next()).as_str();
                    let block_hash: &str = unwrap!(inner_rules.next()).as_str();
                    blockstamp = Blockstamp {
                        number: BlockNumber(unwrap!(block_number.parse())), // Grammar ensures that we have a digits string.
                        hash: BlockHash(unwrap!(Hash::from_hex(block_hash))), // Grammar ensures that we have an hexadecimal string.
                    };
                }
                Rule::ed25519_sig => sig_str = field.as_str(),
                Rule::EOI => (),
                _ => panic!("unexpected rule"), // Grammar ensures that we never reach this line
            }
        }

        Ok(IdentityDocumentV10Builder {
            currency,
            username: uid,
            blockstamp,
            issuer: unwrap!(ed25519::PublicKey::from_base58(pubkey_str)), // Grammar ensures that we have a base58 string.
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
    fn parse_identity_document() {
        let doc = "Version: 10
Type: Identity
Currency: duniter_unit_test_currency
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
UniqueID: tic
Timestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==";

        let doc = IdentityDocument::parse_from_raw_text(doc).expect("Fail to parse idty doc !");
        println!("Doc : {:?}", doc);
        assert!(doc.verify_signatures().is_ok())
    }
}
