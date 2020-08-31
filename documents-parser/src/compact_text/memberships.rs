//  Copyright (C) 2020  Éloïs SANCHEZ.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::*;

/// Parse array of compact memberships
pub fn parse_compact_memberships(
    currency: &str,
    membership_type: MembershipType,
    array_memberships: &[&str],
) -> Result<Vec<MembershipDocumentV10>, ParseCompactDocError> {
    array_memberships
        .iter()
        .map(|membership| {
            let membership_datas: Vec<&str> = membership.split(':').collect();
            if membership_datas.len() == 5 {
                let membership_doc_builder = MembershipDocumentV10Builder {
                    currency,
                    issuer: ed25519::PublicKey::from_base58(membership_datas[0])
                        .map_err(ParseCompactDocError::Issuer)?,
                    blockstamp: Blockstamp::from_str(membership_datas[2])
                        .map_err(ParseCompactDocError::Blockstamp)?,
                    membership: membership_type,
                    identity_username: membership_datas[4],
                    identity_blockstamp: Blockstamp::from_str(membership_datas[3])
                        .map_err(ParseCompactDocError::Blockstamp)?,
                };
                let membership_sig = ed25519::Signature::from_base64(membership_datas[1])
                    .map_err(ParseCompactDocError::Sig)?;
                Ok(membership_doc_builder.build_with_signature(svec![membership_sig]))
            } else {
                Err(ParseCompactDocError::WrongFormat)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_parse_compact_memberships() -> Result<(), ParseCompactDocError> {
        let compact_memberships_strs = &[
            "5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ:462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==:123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E:123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E:toto",
            "GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31:PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==:246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F:246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F:titi",
        ];

        let memberships =
            parse_compact_memberships("test", MembershipType::In(), compact_memberships_strs)?;

        assert_eq!(
            vec![
                MembershipDocumentV10Builder {
                    currency: "test",
                    issuer: unwrap!(ed25519::PublicKey::from_base58("5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ")),
                    blockstamp: unwrap!(Blockstamp::from_str("123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E")),
                    membership: MembershipType::In(),
                    identity_username: "toto",
                    identity_blockstamp: unwrap!(Blockstamp::from_str("123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E")),
                }.build_with_signature(svec![unwrap!(ed25519::Signature::from_base64("462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg=="))]),
                MembershipDocumentV10Builder {
                    currency: "test",
                    issuer: unwrap!(ed25519::PublicKey::from_base58("GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31")),
                    blockstamp: unwrap!(Blockstamp::from_str("246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F")),
                    membership: MembershipType::In(),
                    identity_username: "titi",
                    identity_blockstamp: unwrap!(Blockstamp::from_str("246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F")),
                }.build_with_signature(svec![unwrap!(ed25519::Signature::from_base64("PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ=="))]),
            ],
            memberships,
        );

        Ok(())
    }
}
