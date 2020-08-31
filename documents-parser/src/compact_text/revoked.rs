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

/// Parse array of compact revocations into vector of `CompactRevocationDocumentV10`
pub fn parse_compact_revocations(
    str_revocations: &[&str],
) -> Result<Vec<TextDocumentFormat<RevocationDocumentV10>>, ParseCompactDocError> {
    let mut revocations: Vec<TextDocumentFormat<RevocationDocumentV10>> = Vec::new();
    for revocation in str_revocations {
        let revocations_datas: Vec<&str> = revocation.split(':').collect();
        if revocations_datas.len() == 2 {
            revocations.push(TextDocumentFormat::Compact(CompactRevocationDocumentV10 {
                issuer: ed25519::PublicKey::from_base58(revocations_datas[0])
                    .map_err(ParseCompactDocError::Issuer)?,
                signature: ed25519::Signature::from_base64(revocations_datas[1])
                    .map_err(ParseCompactDocError::Sig)?,
            }));
        }
    }
    Ok(revocations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_parse_compact_revocations() -> Result<(), ParseCompactDocError> {
        let compact_revocations_strs = &[
            "5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ:462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==",
            "GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31:PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==",
        ];

        let compact_revocations = parse_compact_revocations(compact_revocations_strs)?;

        assert_eq!(
            vec![
                TextDocumentFormat::Compact(CompactRevocationDocumentV10 {
                    issuer: unwrap!(ed25519::PublicKey::from_base58("5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ")),
                    signature: unwrap!(ed25519::Signature::from_base64("462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==")),
                }),
                TextDocumentFormat::Compact(CompactRevocationDocumentV10 {
                    issuer: unwrap!(ed25519::PublicKey::from_base58("GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31")),
                    signature: unwrap!(ed25519::Signature::from_base64("PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==")),
                }),
            ],
            compact_revocations,
        );

        Ok(())
    }
}
