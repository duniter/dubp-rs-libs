use crate::*;

impl FromPestPair for CertificationDocument {
    fn from_pest_pair(cert_pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let cert_vx_pair = cert_pair
            .into_inner()
            .next()
            .unwrap_or_else(|| unreachable!()); // get and unwrap the `cert_vX` rule; never fails

        match cert_vx_pair.as_rule() {
            Rule::cert_v10 => CertificationDocumentV10::from_pest_pair(cert_vx_pair)
                .map(CertificationDocument::V10),
            _ => Err(RawTextParseError::UnexpectedVersion(format!(
                "{:#?}",
                cert_vx_pair.as_rule()
            ))),
        }
    }
}

impl FromPestPair for CertificationDocumentV10 {
    fn from_pest_pair(pair: Pair<Rule>) -> Result<CertificationDocumentV10, RawTextParseError> {
        let doc = pair.as_str();
        let mut currency = "";
        let mut pubkeys = Vec::with_capacity(2);
        let mut uid = "";
        let mut sigs = Vec::with_capacity(2);
        let mut blockstamps = Vec::with_capacity(2);
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

        Ok(CertificationDocumentV10Builder {
            issuer: pubkeys[0],
            currency,
            target: pubkeys[1],
            identity_username: uid,
            identity_blockstamp: blockstamps[0],
            identity_sig: sigs[0],
            blockstamp: blockstamps[1],
        }
        .build_with_signature(svec![sigs[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn parse_certification_document() {
        let doc = "Version: 10
Type: Certification
Currency: g1-test
Issuer: 5B8iMAzq1dNmFe3ZxFTBQkqhq4fsztg1gZvxHXCk1XYH
IdtyIssuer: mMPioknj2MQCX9KyKykdw8qMRxYR2w1u3UpdiEJHgXg
IdtyUniqueID: mmpio
IdtyTimestamp: 7543-000044410C5370DE8DBA911A358F318096B7A269CFC2BB93272E397CC513EA0A
IdtySignature: SmSweUD4lEMwiZfY8ux9maBjrQQDkC85oMNsin6oSQCPdXG8sFCZ4FisUaWqKsfOlZVb/HNa+TKzD2t0Yte+DA==
CertTimestamp: 167884-0001DFCA28002A8C96575E53B8CEF8317453A7B0BA255542CCF0EC8AB5E99038
wqZxPEGxLrHGv8VdEIfUGvUcf+tDdNTMXjLzVRCQ4UhlhDRahOMjfcbP7byNYr5OfIl83S1MBxF7VJgu8YasCA==";

        let doc = unwrap!(CertificationDocument::parse_from_raw_text(doc));
        println!("Doc : {:?}", doc);
        assert!(doc.verify_signatures().is_ok());
        assert_eq!(
            doc.to_compact_document().as_compact_text(),
            "5B8iMAzq1dNmFe3ZxFTBQkqhq4fsztg1gZvxHXCk1XYH:\
            mMPioknj2MQCX9KyKykdw8qMRxYR2w1u3UpdiEJHgXg:167884:\
            wqZxPEGxLrHGv8VdEIfUGvUcf+tDdNTMXjLzVRCQ4UhlhDRahOMjfcbP7byNYr5OfIl83S1MBxF7VJgu8YasCA=="
        );
    }
}
