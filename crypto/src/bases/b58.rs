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

//! Provide base58 convertion tools

use crate::bases::BaseConvertionError;

/// Convert to base58 string
pub trait ToBase58 {
    /// Convert to base58 string
    fn to_base58(&self) -> String;
}

/// Create an array of 32 bytes from a Base58 string.
pub fn str_base58_to_32bytes(base58_data: &str) -> Result<([u8; 32], u8), BaseConvertionError> {
    let mut source = base58_data;
    let mut count_leading_1 = 0;
    while !source.is_empty() && &source[0..1] == "1" {
        source = &source[1..];
        count_leading_1 += 1;
    }

    match bs58::decode(source).into_vec() {
        Ok(result) => {
            let mut len = result.len();
            if len > 32 {
                len = 32;
            }
            let mut u8_array = [0; 32];

            u8_array[(32 - len)..].clone_from_slice(&result[..len]);

            Ok((u8_array, count_leading_1))
        }
        Err(bs58::decode::Error::InvalidCharacter { character, index }) => {
            Err(BaseConvertionError::InvalidCharacter {
                character,
                offset: index,
            })
        }
        Err(bs58::decode::Error::BufferTooSmall) => {
            Err(BaseConvertionError::InvalidBaseConverterLength)
        }
        _ => Err(BaseConvertionError::UnknownError),
    }
}

/// Create a Base58 string from a slice of bytes.
pub fn bytes_to_str_base58(bytes: &[u8], count_leading_1: u8) -> String {
    let mut str_base58 = String::new();
    let mut remaining_leading_1 = count_leading_1;
    while remaining_leading_1 > 0 {
        remaining_leading_1 -= 1;
        str_base58.push('1');
    }
    if count_leading_1 >= 32 {
        return str_base58;
    }

    let bytes = if count_leading_1 == 0 && !bytes.is_empty() && bytes[0] == 0 {
        &bytes[1..]
    } else {
        &bytes[count_leading_1 as usize..]
    };

    str_base58.push_str(&bs58::encode(bytes).into_string());

    str_base58
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_base_58_str_with_only_1() -> Result<(), BaseConvertionError> {
        let base58str = "11111111111111111111111111111111111111111111";

        let (bytes, count_leading_1) = str_base58_to_32bytes(base58str)?;

        println!("{:?}", bytes);

        assert_eq!(base58str, &bytes_to_str_base58(&bytes[..], count_leading_1),);

        Ok(())
    }

    #[test]
    fn test_base_58_str_with_leading_1() -> Result<(), BaseConvertionError> {
        let base58str = "13fn6X3XWVgshHTgS8beZMo9XiyScx6MB6yPsBB5ZBia";

        let (bytes, count_leading_1) = str_base58_to_32bytes(base58str)?;

        println!("{:?}", bytes);

        assert_eq!(base58str, &bytes_to_str_base58(&bytes[..], count_leading_1),);

        Ok(())
    }

    #[test]
    fn test_other_base_58_str_with_leading_1() -> Result<(), BaseConvertionError> {
        let base58str = "1V27SH9TiVEDs8TWFPydpRKxhvZari7wjGwQnPxMnkr";

        let (bytes, count_leading_1) = str_base58_to_32bytes(base58str)?;

        println!("{:?}", bytes);

        assert_eq!(base58str, &bytes_to_str_base58(&bytes[..], count_leading_1),);

        Ok(())
    }

    #[test]
    fn test_base_58_str_with_43_char() -> Result<(), BaseConvertionError> {
        let base58str = "2nV7Dv4nhTJ9dZUvRJpL34vFP9b2BkDjKWv9iBW2JaR";

        let (bytes, count_leading_1) = str_base58_to_32bytes(base58str)?;

        println!("{}", count_leading_1);
        println!("{:?}", bytes);

        assert_eq!(base58str, &bytes_to_str_base58(&bytes[..], count_leading_1),);

        Ok(())
    }
}

/*/// Create an array of 64bytes from a Base58 string.
pub fn str_base58_to_64bytes(base58_data: &str) -> Result<[u8; 64], BaseConvertionError> {
    match base58_data.from_base58() {
        Ok(result) => {
            if result.len() == 64 {
                let mut u8_array = [0; 64];

                u8_array[..64].clone_from_slice(&result[..64]);

                Ok(u8_array)
            } else {
                Err(BaseConvertionError::InvalidLength {
                    expected: 64,
                    found: result.len(),
                })
            }
        }
        Err(FromBase58Error::InvalidBase58Character(character, offset)) => {
            Err(BaseConvertionError::InvalidCharacter { character, offset })
        }
        Err(FromBase58Error::InvalidBase58Length) => {
            Err(BaseConvertionError::InvalidBaseConverterLength)
        }
    }
}*/
