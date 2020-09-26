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

impl FromStringObject for TransactionDocumentV10 {
    fn from_string_object(
        stringified: &TransactionDocumentV10Stringified,
    ) -> Result<Self, TextParseError> {
        let issuers = stringified
            .issuers
            .iter()
            .map(|s| ed25519::PublicKey::from_base58(s))
            .collect::<Result<SmallVec<[ed25519::PublicKey; 1]>, BaseConversionError>>()
            .map_err(|e| TextParseError::BaseConversionError {
                field: "issuers",
                error: e,
            })?;

        let inputs = stringified
            .inputs
            .iter()
            .map(|s| tx_input_v10_from_str(s))
            .collect::<Result<Vec<TransactionInputV10>, TextParseError>>()?;

        let unlocks = stringified
            .unlocks
            .iter()
            .map(|s| tx_unlock_v10_from_str(s))
            .collect::<Result<Vec<TransactionInputUnlocksV10>, TextParseError>>()?;

        let outputs = stringified
            .outputs
            .iter()
            .map(|s| tx_output_v10_from_str(s))
            .collect::<Result<SmallVec<[TransactionOutputV10; 2]>, TextParseError>>()?;

        let signatures = stringified
            .signatures
            .iter()
            .map(|s| ed25519::Signature::from_base64(s))
            .collect::<Result<SmallVec<[ed25519::Signature; 1]>, BaseConversionError>>()
            .map_err(|e| TextParseError::BaseConversionError {
                field: "signatures",
                error: e,
            })?;

        Ok(TransactionDocumentV10Builder {
            currency: &stringified.currency,
            blockstamp: Blockstamp::from_str(&stringified.blockstamp)
                .map_err(TextParseError::BlockstampParseError)?,
            locktime: stringified.locktime,
            issuers,
            inputs: &inputs[..],
            unlocks: &unlocks[..],
            outputs,
            comment: &stringified.comment,
            hash: if let Some(ref hash) = stringified.hash {
                Some(
                    Hash::from_hex(hash).map_err(|e| TextParseError::BaseConversionError {
                        field: "hash",
                        error: e,
                    })?,
                )
            } else {
                None
            },
        }
        .build_with_signature(signatures))
    }
}
