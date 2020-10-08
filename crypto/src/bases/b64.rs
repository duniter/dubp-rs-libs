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

//! Provide base64 convertion tools

use crate::bases::BaseConversionError;

/// Create an array of 64 bytes from a Base64 string.
pub fn str_base64_to64bytes(base64_data: &str) -> Result<[u8; 64], BaseConversionError> {
    if base64_data.len() > 88 {
        return Err(BaseConversionError::InvalidBaseConverterLength);
    }

    let mut u8_array = [0; 64];
    let written_len = base64::decode_config_slice(base64_data, base64::STANDARD, &mut u8_array)?;

    if written_len == 64 {
        Ok(u8_array)
    } else {
        Err(BaseConversionError::InvalidLength {
            expected: 64,
            found: written_len,
        })
    }
}
