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

//! Read [DEWIF](https://git.duniter.org/nodes/common/doc/blob/dewif/rfc/0013_Duniter_Encrypted_Wallet_Import_Format.md) file content

use super::{Currency, ExpectedCurrency};
use crate::keys::ed25519::{KeyPairFromSeed32Generator, PublicKey, PUBKEY_DATAS_SIZE_IN_BYTES};
use crate::keys::{KeyPair, KeyPairEnum};
use crate::seeds::{Seed32, SEED_32_SIZE_IN_BYTES};
use arrayvec::ArrayVec;
use byteorder::ByteOrder;
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

const MAX_KEYPAIRS_COUNT: usize = 2;

type KeyPairsArray = ArrayVec<[KeyPairEnum; MAX_KEYPAIRS_COUNT]>;
type KeyPairsIter = arrayvec::IntoIter<[KeyPairEnum; MAX_KEYPAIRS_COUNT]>;

/// Error when try to read DEWIF file content
#[derive(Clone, Debug, Error)]
pub enum DewifReadError {
    /// DEWIF file content is corrupted
    #[error("DEWIF file content is corrupted.")]
    CorruptedContent,
    /// Invalid base 64 string
    #[error("Invalid base 64 string: {0}.")]
    InvalidBase64Str(base64::DecodeError),
    /// Invalid format
    #[error("Invalid format.")]
    InvalidFormat,
    /// Too short content
    #[error("Too short content.")]
    TooShortContent,
    /// Too long content
    #[error("Too long content.")]
    TooLongContent,
    /// Unexpected currency
    #[error("Unexpected currency '{actual}', expected: '{expected}'.")]
    UnexpectedCurrency {
        /// Expected currency
        expected: ExpectedCurrency,
        /// Actual currency
        actual: Currency,
    },
    /// Unsupported version
    #[error("Version {actual} is not supported. Supported versions: [1, 2].")]
    UnsupportedVersion {
        /// Actual version
        actual: u32,
    },
}

/// read dewif file content with user passphrase
pub fn read_dewif_file_content(
    expected_currency: ExpectedCurrency,
    file_content: &str,
    passphrase: &str,
) -> Result<impl Iterator<Item = KeyPairEnum>, DewifReadError> {
    let mut bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;

    if bytes.len() < 8 {
        return Err(DewifReadError::TooShortContent);
    }

    let version = byteorder::BigEndian::read_u32(&bytes[0..4]);
    let currency = Currency::from(byteorder::BigEndian::read_u32(&bytes[4..8]));

    if !expected_currency.is_valid(currency) {
        return Err(DewifReadError::UnexpectedCurrency {
            expected: expected_currency,
            actual: currency,
        });
    }

    match version {
        1 => Ok({
            let mut array_keypairs = KeyPairsArray::new();
            array_keypairs.push(read_dewif_v1(&mut bytes[8..], passphrase)?);
            array_keypairs.into_iter()
        }),
        2 => read_dewif_v2(&mut bytes[8..], passphrase),
        other_version => Err(DewifReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

fn read_dewif_v1(bytes: &mut [u8], passphrase: &str) -> Result<KeyPairEnum, DewifReadError> {
    match bytes.len() {
        len if len < super::V1_ENCRYPTED_BYTES_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V1_ENCRYPTED_BYTES_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, bytes, super::V1_AES_BLOCKS_COUNT);

    // Get checked keypair
    bytes_to_checked_keypair(bytes)
}

fn read_dewif_v2(bytes: &mut [u8], passphrase: &str) -> Result<KeyPairsIter, DewifReadError> {
    let mut array_keypairs = KeyPairsArray::new();

    match bytes.len() {
        len if len < super::V2_ENCRYPTED_BYTES_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V2_ENCRYPTED_BYTES_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::decrypt::decrypt_8_blocks(&cipher, bytes);

    array_keypairs.push(bytes_to_checked_keypair(&bytes[..64])?);
    array_keypairs.push(bytes_to_checked_keypair(&bytes[64..])?);

    Ok(array_keypairs.into_iter())
}

fn bytes_to_checked_keypair(bytes: &[u8]) -> Result<KeyPairEnum, DewifReadError> {
    // Wrap bytes into Seed32 and PublicKey
    let seed = Seed32::new(
        (&bytes[..SEED_32_SIZE_IN_BYTES])
            .try_into()
            .expect("dev error"),
    );
    let expected_pubkey =
        PublicKey::try_from(&bytes[PUBKEY_DATAS_SIZE_IN_BYTES..]).expect("dev error");

    // Get keypair
    let keypair = KeyPairFromSeed32Generator::generate(seed);

    // Check pubkey
    if keypair.public_key() != expected_pubkey {
        Err(DewifReadError::CorruptedContent)
    } else {
        Ok(KeyPairEnum::Ed25519(keypair))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn read_unsupported_version() -> Result<(), ()> {
        if let Err(DewifReadError::UnsupportedVersion { .. }) = read_dewif_file_content(
            ExpectedCurrency::Any,
            "ABAAAb30ng3kI9QGMbR7TYCqPhS99J4N5CPUBjG0e02Aqj4U1UmOemI6pweNm1Ab1AR4V6ZWFnwkkp9QPxppVeMv7aaLWdop",
            "toto"
        ) {
            Ok(())
        } else {
            panic!("Read must be fail with error UnsupportedVersion.")
        }
    }

    #[test]
    fn read_too_short_content() -> Result<(), ()> {
        if let Err(DewifReadError::TooShortContent) =
            read_dewif_file_content(ExpectedCurrency::Any, "AAA", "toto")
        {
            Ok(())
        } else {
            panic!("Read must be fail with error TooShortContent.")
        }
    }

    #[test]
    fn read_unexpected_currency() -> Result<(), ()> {
        if let Err(DewifReadError::UnexpectedCurrency { .. }) = read_dewif_file_content(
            ExpectedCurrency::Specific(Currency::from(42)),
            "AAAAARAAAAEx3yd707xD3F5ttjcISbZzXRrko4pKUmCDIF/emfcVU9MvBqCJQS9R2sWlqbtI1Q37sLQhkj/W7tqY+hxm7mFQ",
            "toto titi tata"
        ) {
            Ok(())
        } else {
            panic!("Read must be fail with error UnexpectedCurrency.")
        }
    }

    #[test]
    fn read_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAAARAAAAEx3yd707xD3F5ttjcISbZzXRrko4pKUmCDIF/emfcVU9MvBqCJQS9R2sWlqbtI1Q37sLQhkj/W7tqY+hxm7mFQ";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency =
            ExpectedCurrency::Specific(Currency::from_str("g1-test").expect("unknown currency"));

        // Read DEWIF file content
        // If the file content is correct, we get a key-pair iterator.
        let mut key_pair_iter =
            read_dewif_file_content(expected_currency, dewif_file_content, encryption_passphrase)
                .expect("invalid DEWIF file");

        // Get first key-pair
        let key_pair = key_pair_iter
            .next()
            .expect("DEWIF file must contain at least one keypair");

        assert_eq!(
            "2cC9FrvRiN3uHHcd8S7wuureDS8CAmD5y4afEgSCLHtU",
            &key_pair.public_key().to_string()
        );

        // Generate signator
        // `Signator` is a non-copiable and non-clonable type,
        // so only generate it when you are in the scope where you effectively sign.
        let signator = key_pair.generate_signator();

        // Sign a message with keypair
        let sig = signator.sign(b"message");

        assert_eq!(
            "nCWl7jtCa/nCMKKnk2NJN7daVxd/ER+e1wsFbofdh/pUvDuHxFaa7S5eUMGiqPTJ4uJQOvrmF/BOfOsYIoI2Bg==",
            &sig.to_string()
        )
    }
}
