use crate::*;

impl FromPestPair for DubpDocument {
    #[inline]
    fn from_pest_pair(pair: Pair<Rule>) -> Result<Self, RawTextParseError> {
        let doc_vx_pair = unwrap!(pair.into_inner().next()); // get and unwrap the `document_vX` rule; never fails

        match doc_vx_pair.as_rule() {
            Rule::document_v10 => dubp_doc_from_pest_pair_v10(doc_vx_pair),
            _ => panic!("unexpected rule: {:?}", doc_vx_pair.as_rule()), // Grammar ensures that we never reach this line
        }
    }
}

pub fn dubp_doc_from_pest_pair_v10(pair: Pair<Rule>) -> Result<DubpDocument, RawTextParseError> {
    let doc_type_v10_pair = unwrap!(pair.into_inner().next()); // get and unwrap the `{DOC_TYPE}_v10` rule; never fails

    match doc_type_v10_pair.as_rule() {
        Rule::idty_v10 => Ok(DubpDocument::Identity(IdentityDocument::V10(
            IdentityDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::membership_v10 => Ok(DubpDocument::Membership(MembershipDocument::V10(
            MembershipDocumentV10::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::cert_v10 => Ok(DubpDocument::Certification(Box::new(
            CertificationDocument::V10(CertificationDocumentV10::from_pest_pair(
                doc_type_v10_pair,
            )?),
        ))),
        Rule::revoc_v10 => Ok(DubpDocument::Revocation(Box::new(
            RevocationDocument::from_pest_pair(doc_type_v10_pair)?,
        ))),
        Rule::tx_v10 => Ok(DubpDocument::Transaction(Box::new(
            TransactionDocument::from_pest_pair(doc_type_v10_pair)?,
        ))),
        _ => panic!("unexpected rule: {:?}", doc_type_v10_pair.as_rule()), // Grammar ensures that we never reach this line
    }
}
