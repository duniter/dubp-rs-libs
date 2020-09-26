use crate::*;

impl FromPestPair for DubpDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, TextParseError> {
        let doc_vx_pair = pair.into_inner().next().unwrap_or_else(|| unreachable!()); // get and unwrap the `document_vX` rule; never fails

        match doc_vx_pair.as_rule() {
            Rule::document_v10 => dubp_doc_from_pest_pair_v10(doc_vx_pair),
            _ => panic!("unexpected rule: {:?}", doc_vx_pair.as_rule()), // Grammar ensures that we never reach this line
        }
    }
}

pub fn dubp_doc_from_pest_pair_v10(pair: Pair<Rule>) -> Result<DubpDocument, TextParseError> {
    let doc_type_v10_pair = pair.into_inner().next().unwrap_or_else(|| unreachable!()); // get and unwrap the `{DOC_TYPE}_v10` rule; never fails

    match doc_type_v10_pair.as_rule() {
        Rule::idty_v10 => Ok(DubpDocument::Identity(IdentityDocument::V10(
            IdentityDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::membership_v10 => Ok(DubpDocument::Membership(MembershipDocument::V10(
            MembershipDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::cert_v10 => Ok(DubpDocument::Certification(CertificationDocument::V10(
            CertificationDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::revoc_v10 => Ok(DubpDocument::Revocation(RevocationDocument::V10(
            RevocationDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::tx_v10 => Ok(DubpDocument::Transaction(TransactionDocument::V10(
            TransactionDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        _ => panic!("unexpected rule: {:?}", doc_type_v10_pair.as_rule()), // Grammar ensures that we never reach this line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_any_document() {
        let doc = "Version: 10
Type: Revocation
Currency: g1
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
IdtyUniqueID: tic
IdtyTimestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
IdtySignature: 1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==
XXOgI++6qpY9O31ml/FcfbXCE6aixIrgkT5jL7kBle3YOMr+8wrp7Rt+z9hDVjrNfYX2gpeJsuMNfG4T/fzVDQ==";

        let doc = DubpDocument::parse_from_raw_text(doc).unwrap_or_else(|_| unreachable!());
        println!("Doc : {:?}", doc);
        assert!(doc.verify_signatures().is_ok())
    }
}
