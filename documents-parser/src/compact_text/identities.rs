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

/// Parse array of compact identities
pub fn parse_compact_identities(
    currency: &str,
    str_identities: &[&str],
) -> Result<Vec<IdentityDocumentV10>, ParseCompactDocError> {
    let mut identities = Vec::with_capacity(str_identities.len());

    for str_identity in str_identities {
        let idty_elements: Vec<&str> = (*str_identity).split(':').collect();
        let issuer = ed25519::PublicKey::from_base58(idty_elements[0])
            .map_err(ParseCompactDocError::Issuer)?;
        let signature =
            ed25519::Signature::from_base64(idty_elements[1]).map_err(ParseCompactDocError::Sig)?;
        let blockstamp =
            Blockstamp::from_str(idty_elements[2]).map_err(ParseCompactDocError::Blockstamp)?;
        let username = idty_elements[3];
        let idty_doc_builder = IdentityDocumentV10Builder {
            currency,
            username,
            blockstamp,
            issuer,
        };
        identities.push(idty_doc_builder.build_with_signature(svec![signature]))
    }

    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_parse_compact_identities() -> Result<(), ParseCompactDocError> {
        let compact_identities_strs = &[
            "5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ:462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==:123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E:toto",
            "GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31:PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==:246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F:titi",
        ];

        let identities = parse_compact_identities("test", compact_identities_strs)?;

        assert_eq!(
            vec![
                IdentityDocumentV10Builder {
                    currency: "test",
                    username: "toto",
                    blockstamp: unwrap!(Blockstamp::from_str("123123-000004E70532AEC7EFC90C63C3FF996D2C070915DFAEB37E24E149E94A48730E")),
                    issuer: unwrap!(ed25519::PublicKey::from_base58("5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ")),
                }.build_with_signature(svec![unwrap!(ed25519::Signature::from_base64("462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg=="))]),
                IdentityDocumentV10Builder {
                    currency: "test",
                    username: "titi",
                    blockstamp: unwrap!(Blockstamp::from_str("246246-0000060288862F19C36CD79AD8BAE142B0667EDECCD9E10826E345C358002F6F")),
                    issuer: unwrap!(ed25519::PublicKey::from_base58("GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31")),
                }.build_with_signature(svec![unwrap!(ed25519::Signature::from_base64("PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ=="))]),
            ],
            identities,
        );

        Ok(())
    }
}
