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
use json_pest_parser::*;

#[derive(Debug, Error)]
pub enum ParseJsonTxError {
    #[error("wrong blockstamp : {0}")]
    Blockstamp(BlockstampParseError),
    #[error("wrong hash : {0}")]
    Hash(BaseConversionError),
    #[error("wrong issuer : {0}")]
    Issuer(BaseConversionError),
    #[error("wrong input : {0}")]
    Input(TextParseError),
    #[error("wrong unlock : {0}")]
    Unlock(TextParseError),
    #[error("wrong output : {0}")]
    Output(TextParseError),
    #[error("wrong sig : {0}")]
    Sig(BaseConversionError),
    #[error("json error: {0}")]
    JsonErr(ParseJsonError),
    #[error("wrong format")]
    WrongFormat,
}

impl From<ParseJsonError> for ParseJsonTxError {
    fn from(e: ParseJsonError) -> Self {
        ParseJsonTxError::JsonErr(e)
    }
}

/// Parse transactions documents from array of str
pub fn parse_json_transactions(
    array_transactions: &[&JSONValue<DefaultHasher>],
) -> Result<Vec<TransactionDocumentV10>, ParseJsonTxError> {
    array_transactions
        .iter()
        .map(|tx| {
            parse_json_transaction(tx).map(|tx_doc| match tx_doc {
                TransactionDocument::V10(tx_doc_v10) => tx_doc_v10,
            })
        })
        .collect::<Result<Vec<TransactionDocumentV10>, ParseJsonTxError>>()
}

/// Parse transaction from json value
fn parse_json_transaction(
    json_tx: &JSONValue<DefaultHasher>,
) -> Result<TransactionDocument, ParseJsonTxError> {
    let json_tx = if let JSONValue::Object(json_tx) = json_tx {
        json_tx
    } else {
        return Err(ParseJsonError {
            cause: "Json transaction must be an object !".to_owned(),
        }
        .into());
    };

    match get_u64(json_tx, "version")? {
        10 => Ok(
            TransactionDocumentBuilder::V10(TransactionDocumentV10Builder {
                currency: get_str(json_tx, "currency")?,
                blockstamp: Blockstamp::from_str(get_str(json_tx, "blockstamp")?)
                    .map_err(ParseJsonTxError::Blockstamp)?,
                locktime: (get_number(json_tx, "locktime")?.trunc() as u64),
                issuers: get_str_array(json_tx, "issuers")?
                    .iter()
                    .map(|p| ed25519::PublicKey::from_base58(p))
                    .collect::<Result<SmallVec<_>, BaseConversionError>>()
                    .map_err(ParseJsonTxError::Issuer)?,
                inputs: &get_str_array(json_tx, "inputs")?
                    .iter()
                    .map(|i| tx_input_v10_from_str(i))
                    .collect::<Result<Vec<TransactionInputV10>, TextParseError>>()
                    .map_err(ParseJsonTxError::Input)?[..],
                unlocks: &get_str_array(json_tx, "unlocks")?
                    .iter()
                    .map(|i| tx_unlock_v10_from_str(i))
                    .collect::<Result<Vec<TransactionInputUnlocksV10>, TextParseError>>()
                    .map_err(ParseJsonTxError::Unlock)?[..],
                outputs: get_str_array(json_tx, "outputs")?
                    .iter()
                    .map(|i| tx_output_v10_from_str(i))
                    .collect::<Result<SmallVec<_>, TextParseError>>()
                    .map_err(ParseJsonTxError::Output)?,
                comment: &unescape_str(get_str(json_tx, "comment")?),
                hash: get_optional_str(json_tx, "hash")?
                    .map(Hash::from_hex)
                    .transpose()
                    .map_err(ParseJsonTxError::Hash)?,
            })
            .build_with_signature(
                get_str_array(json_tx, "signatures")?
                    .iter()
                    .map(|p| ed25519::Signature::from_base64(p))
                    .map(|p| p.map(Sig::Ed25519))
                    .collect::<Result<SmallVec<[Sig; 1]>, BaseConversionError>>()
                    .map_err(ParseJsonTxError::Sig)?,
            ),
        ),
        version => Err(ParseJsonError {
            cause: format!("Unhandled json transaction version: {} !", version),
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dubp_documents::smallvec::smallvec;
    use unwrap::unwrap;

    pub fn first_g1_tx_doc() -> TransactionDocument {
        let expected_tx_builder = TransactionDocumentV10Builder {
            currency: &"g1",
            blockstamp: unwrap!(Blockstamp::from_str(
                "50-00001DAA4559FEDB8320D1040B0F22B631459F36F237A0D9BC1EB923C12A12E7",
            )),
            locktime: 0,
            issuers: svec![unwrap!(ed25519::PublicKey::from_base58(
                "2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ",
            ))],
            inputs: &[unwrap!(tx_input_v10_from_str(
                "1000:0:D:2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ:1",
            ))],
            unlocks: &[unwrap!(tx_unlock_v10_from_str("0:SIG(0)"))],
            outputs: smallvec![
                unwrap!(tx_output_v10_from_str(
                    "1:0:SIG(Com8rJukCozHZyFao6AheSsfDQdPApxQRnz7QYFf64mm)",
                )),
                unwrap!(tx_output_v10_from_str(
                    "999:0:SIG(2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ)"
                )),
            ],
            comment: "TEST",
            hash: None,
        };

        TransactionDocumentBuilder::V10(expected_tx_builder).build_with_signature(svec![Sig::Ed25519(
            unwrap!(ed25519::Signature::from_base64("fAH5Gor+8MtFzQZ++JaJO6U8JJ6+rkqKtPrRr/iufh3MYkoDGxmjzj6jCADQL+hkWBt8y8QzlgRkz0ixBcKHBw=="))
        )])
    }

    #[test]
    fn test_parse_json_tx() {
        let tx_json_str = r#"{
     "version": 10,
     "currency": "g1",
     "locktime": 0,
     "blockstamp": "50-00001DAA4559FEDB8320D1040B0F22B631459F36F237A0D9BC1EB923C12A12E7",
     "blockstampTime": 1488990016,
     "issuers": [
      "2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ"
     ],
     "inputs": [
      "1000:0:D:2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ:1"
     ],
     "outputs": [
      "1:0:SIG(Com8rJukCozHZyFao6AheSsfDQdPApxQRnz7QYFf64mm)",
      "999:0:SIG(2ny7YAdmzReQxAayyJZsyVYwYhVyax2thKcGknmQy5nQ)"
     ],
     "unlocks": [
      "0:SIG(0)"
     ],
     "signatures": [
      "fAH5Gor+8MtFzQZ++JaJO6U8JJ6+rkqKtPrRr/iufh3MYkoDGxmjzj6jCADQL+hkWBt8y8QzlgRkz0ixBcKHBw=="
     ],
     "comment": "TEST",
     "block_number": 0,
     "time": 0
    }"#;

        let tx_json_value = unwrap!(json_pest_parser::parse_json_string(tx_json_str));

        assert_eq!(
            first_g1_tx_doc(),
            unwrap!(parse_json_transaction(&tx_json_value))
        );
    }
}
