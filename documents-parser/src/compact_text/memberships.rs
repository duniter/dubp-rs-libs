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

/// Parse memberships documents from array of str
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
