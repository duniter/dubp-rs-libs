use crate::*;

impl FromPestPair for RevocationDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, TextParseError> {
        let revoc_vx_pair = pair.into_inner().next().unwrap_or_else(|| unreachable!()); // get and unwrap the `revoc_vX` rule; never fails

        match revoc_vx_pair.as_rule() {
            Rule::revoc_v10 => {
                RevocationDocumentV10::from_pest_pair(revoc_vx_pair).map(RevocationDocument::V10)
            }
            _ => Err(TextParseError::UnexpectedVersion(format!(
                "{:#?}",
                revoc_vx_pair.as_rule()
            ))),
        }
    }
}

impl FromPestPair for RevocationDocumentV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<RevocationDocumentV10, TextParseError> {
        let mut currency = "";
        let mut pubkeys = Vec::with_capacity(1);
        let mut uid = "";
        let mut sigs = Vec::with_capacity(2);
        let mut blockstamps = Vec::with_capacity(1);
        for field in pair.into_inner() {
            match field.as_rule() {
                Rule::currency => currency = field.as_str(),
                Rule::pubkey => pubkeys.push(
                    ed25519::PublicKey::from_base58(field.as_str())
                        .unwrap_or_else(|_| unreachable!()), // Grammar ensures that we have a base58 string.
                ),
                Rule::uid => {
                    uid = field.as_str();
                }
                Rule::blockstamp => {
                    let mut inner_rules = field.into_inner(); // { integer ~ "-" ~ hash }

                    let block_number: &str = inner_rules
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str();
                    let block_hash: &str = inner_rules
                        .next()
                        .unwrap_or_else(|| unreachable!())
                        .as_str();
                    blockstamps.push(Blockstamp {
                        number: BlockNumber(
                            block_number.parse().unwrap_or_else(|_| unreachable!()),
                        ), // Grammar ensures that we have a digits string.
                        hash: BlockHash(
                            Hash::from_hex(block_hash).unwrap_or_else(|_| unreachable!()),
                        ), // Grammar ensures that we have an hexadecimal string.
                    });
                }
                Rule::ed25519_sig => {
                    sigs.push(
                        ed25519::Signature::from_base64(field.as_str())
                            .unwrap_or_else(|_| unreachable!()), // Grammar ensures that we have a base64 string.
                    );
                }
                Rule::EOI => (),
                _ => panic!("unexpected rule"), // Grammar ensures that we never reach this line
            }
        }
        Ok(RevocationDocumentV10Builder {
            issuer: pubkeys[0],
            currency,
            identity_username: uid,
            identity_blockstamp: blockstamps[0],
            identity_sig: sigs[0],
        }
        .build_with_signature(svec![sigs[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn parse_revocation_document() {
        let doc = "Version: 10
Type: Revocation
Currency: g1
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
IdtyUniqueID: tic
IdtyTimestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
IdtySignature: 1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==
XXOgI++6qpY9O31ml/FcfbXCE6aixIrgkT5jL7kBle3YOMr+8wrp7Rt+z9hDVjrNfYX2gpeJsuMNfG4T/fzVDQ==";

        let doc = unwrap!(RevocationDocument::parse_from_raw_text(doc));
        println!("Doc : {:?}", doc);
        assert!(doc.verify_signatures().is_ok())
    }
}
