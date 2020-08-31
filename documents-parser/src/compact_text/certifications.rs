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

/// Parse array of compact certification into vector of `CompactCertificationDocument`
pub fn parse_compact_certifications(
    str_certs: &[&str],
) -> Result<Vec<TextDocumentFormat<CertificationDocumentV10>>, ParseCompactDocError> {
    let mut certifications: Vec<TextDocumentFormat<CertificationDocumentV10>> = Vec::new();
    for certification in str_certs {
        let certifications_datas: Vec<&str> = certification.split(':').collect();
        if certifications_datas.len() == 4 {
            certifications.push(TextDocumentFormat::Compact(
                CompactCertificationDocumentV10 {
                    issuer: ed25519::PublicKey::from_base58(certifications_datas[0])
                        .map_err(ParseCompactDocError::Issuer)?,
                    target: ed25519::PublicKey::from_base58(certifications_datas[1])
                        .map_err(ParseCompactDocError::Target)?,
                    block_number: BlockNumber(
                        certifications_datas[2]
                            .parse()
                            .map_err(ParseCompactDocError::BlockNumber)?,
                    ),
                    signature: ed25519::Signature::from_base64(certifications_datas[3])
                        .map_err(ParseCompactDocError::Sig)?,
                },
            ));
        }
    }
    Ok(certifications)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_parse_compact_certifications() -> Result<(), ParseCompactDocError> {
        let compact_certs_strs = &[
            "5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ:3Rt4qTmHoLPn5z2FWGAXwQp9AqVokgo85f5N47D2Fosu:352364:462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==",
            "GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31:Aav6dYSbWiGZVSeunqYswZRcFkrobpk1NWw3PCjpD8Mz:346647:PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==",
        ];

        let compact_certs = parse_compact_certifications(compact_certs_strs)?;

        assert_eq!(
            vec![
                TextDocumentFormat::Compact(CompactCertificationDocumentV10 {
                    issuer: unwrap!(ed25519::PublicKey::from_base58("5bG4wxsFDpG3n7vtgDyv8jCC9h5pWjJdDxDDSE21RgZJ")),
                    target: unwrap!(ed25519::PublicKey::from_base58("3Rt4qTmHoLPn5z2FWGAXwQp9AqVokgo85f5N47D2Fosu")),
                    block_number: BlockNumber(352_364),
                    signature: unwrap!(ed25519::Signature::from_base64("462+UqY616pj2WU1M9/xLQIppfuT2CLruoPSGT8Frm1iKepp1fQ3iNk3b/Z6EaFJ3cFD4Eu2jMmgwsbcnVQXBg==")),
                }),
                TextDocumentFormat::Compact(CompactCertificationDocumentV10 {
                    issuer: unwrap!(ed25519::PublicKey::from_base58("GFShJBGAnXXNvWuWv2sBTc2jxPfuJLgB6sxunEj69i31")),
                    target: unwrap!(ed25519::PublicKey::from_base58("Aav6dYSbWiGZVSeunqYswZRcFkrobpk1NWw3PCjpD8Mz")),
                    block_number: BlockNumber(346_647),
                    signature: unwrap!(ed25519::Signature::from_base64("PPuXwwmL/Voc4Q+6NNKV31cfwlK07SC10m+u91RovPLj4Dn7F+452BucruiFZ190L8aB66RbiHByebE5kVD/DQ==")),
                }),
            ],
            compact_certs,
        );

        Ok(())
    }
}
