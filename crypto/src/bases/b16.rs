//  Copyright (C) 2020 Éloïs SANCHEZ.
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

//! Provide base16 convertion tools

use crate::bases::BaseConversionError;

/// Convert a hexadecimal string in an array of 32 bytes.
///
/// The hex string must only contains hex characters
/// and produce a 32 bytes value.
pub fn str_hex_to_32bytes(text: &str) -> Result<[u8; 32], BaseConversionError> {
    if text.len() != 64 {
        Err(BaseConversionError::InvalidLength {
            expected: 64,
            found: text.len(),
        })
    } else {
        let mut bytes = [0u8; 32];

        let chars = text.as_bytes();

        for i in 0..64 {
            if i % 2 != 0 {
                continue;
            }

            let byte1 = hex_char_byte_to_byte(chars[i], i)?;
            let byte2 = hex_char_byte_to_byte(chars[i + 1], i + 1)?;

            bytes[i / 2] = (byte1 << 4) | byte2;
        }

        Ok(bytes)
    }
}

fn hex_char_byte_to_byte(hex_char: u8, pos: usize) -> Result<u8, BaseConversionError> {
    match hex_char {
        b'0' => Ok(0),
        b'1' => Ok(1),
        b'2' => Ok(2),
        b'3' => Ok(3),
        b'4' => Ok(4),
        b'5' => Ok(5),
        b'6' => Ok(6),
        b'7' => Ok(7),
        b'8' => Ok(8),
        b'9' => Ok(9),
        b'A' => Ok(10),
        b'B' => Ok(11),
        b'C' => Ok(12),
        b'D' => Ok(13),
        b'E' => Ok(14),
        b'F' => Ok(15),
        c => Err(BaseConversionError::InvalidCharacter {
            character: c as char,
            offset: pos,
        }),
    }
}
