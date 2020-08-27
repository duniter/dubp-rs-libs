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

/// Parse a compact identity
pub fn parse_compact_identities(
    currency: &str,
    str_identities: Vec<&str>,
) -> Result<Vec<IdentityDocumentV10>, ParseCompactDocError> {
    let mut identities = Vec::with_capacity(str_identities.len());

    for str_identity in str_identities {
        let idty_elements: Vec<&str> = str_identity.split(':').collect();
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
