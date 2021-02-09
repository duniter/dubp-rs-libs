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
use crate::keys::ed25519::{Ed25519KeyPair, PublicKey, PUBKEY_DATAS_SIZE_IN_BYTES};
use crate::keys::{KeyPair, KeyPairEnum};
use crate::seeds::{Seed32, SEED_32_SIZE_IN_BYTES};
use arrayvec::ArrayVec;
use byteorder::ByteOrder;
use std::{
    convert::{TryFrom, TryInto},
    hint::unreachable_unchecked,
};
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

/// read dewif log N
pub fn read_dewif_log_n(
    expected_currency: ExpectedCurrency,
    file_content: &str,
) -> Result<u8, DewifReadError> {
    let bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;

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
        1 | 2 => Ok(12u8),
        3 | 4 => {
            if bytes.len() < 9 {
                Err(DewifReadError::TooShortContent)
            } else {
                Ok(bytes[8])
            }
        }
        other_version => Err(DewifReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

/// read dewif meta data
pub fn read_dewif_meta(file_content: &str) -> Result<super::DewifMeta, DewifReadError> {
    let bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;

    if bytes.len() < 8 {
        return Err(DewifReadError::TooShortContent);
    }

    let version = byteorder::BigEndian::read_u32(&bytes[0..4]);
    let currency = Currency::from(byteorder::BigEndian::read_u32(&bytes[4..8]));

    let log_n = match version {
        1 | 2 => 12u8,
        3 | 4 => {
            if bytes.len() < 9 {
                return Err(DewifReadError::TooShortContent);
            } else {
                bytes[8]
            }
        }
        other_version => {
            return Err(DewifReadError::UnsupportedVersion {
                actual: other_version,
            });
        }
    };

    Ok(super::DewifMeta {
        currency,
        log_n,
        version,
    })
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
            array_keypairs.push(read_dewif_v1(&mut bytes[8..], passphrase)?.upcast());
            array_keypairs.into_iter()
        }),
        2 => read_dewif_v2(&mut bytes[8..], passphrase),
        3 => Ok({
            let mut array_keypairs = KeyPairsArray::new();
            array_keypairs.push(read_dewif_v3(&mut bytes[8..], passphrase)?.upcast());
            array_keypairs.into_iter()
        }),
        #[cfg(feature = "bip32-ed25519")]
        4 => Ok({
            let mut array_keypairs = KeyPairsArray::new();
            array_keypairs.push(read_dewif_v4(&mut bytes[8..], passphrase)?.upcast());
            array_keypairs.into_iter()
        }),
        other_version => Err(DewifReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

fn read_dewif_v1(bytes: &mut [u8], passphrase: &str) -> Result<Ed25519KeyPair, DewifReadError> {
    match bytes.len() {
        len if len < super::V1_DATA_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V1_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, super::V1_LOG_N));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, bytes, super::V1_AES_BLOCKS_COUNT);

    // Get checked keypair
    bytes_to_checked_keypair(bytes)
}

fn read_dewif_v2(bytes: &mut [u8], passphrase: &str) -> Result<KeyPairsIter, DewifReadError> {
    let mut array_keypairs = KeyPairsArray::new();

    match bytes.len() {
        len if len < super::V2_DATA_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V2_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, super::V2_LOG_N));
    crate::aes256::decrypt::decrypt_8_blocks(&cipher, bytes);

    array_keypairs.push(KeyPairEnum::Ed25519(bytes_to_checked_keypair::<
        Ed25519KeyPair,
    >(&bytes[..64])?));
    array_keypairs.push(KeyPairEnum::Ed25519(bytes_to_checked_keypair::<
        Ed25519KeyPair,
    >(&bytes[64..])?));
    Ok(array_keypairs.into_iter())
}

fn read_dewif_v3(bytes: &mut [u8], passphrase: &str) -> Result<Ed25519KeyPair, DewifReadError> {
    match bytes.len() {
        len if len < super::V3_DATA_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V3_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Read log_n
    let log_n = bytes[0];

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, log_n));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, &mut bytes[1..], super::V3_AES_BLOCKS_COUNT);

    // Get checked keypair
    bytes_to_checked_keypair(&bytes[1..])
}

#[cfg(feature = "bip32-ed25519")]
fn read_dewif_v4(
    bytes: &mut [u8],
    passphrase: &str,
) -> Result<crate::keys::ed25519::bip32::KeyPair, DewifReadError> {
    match bytes.len() {
        len if len < super::V3_DATA_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V3_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Read log_n
    let log_n = bytes[0];

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, log_n));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, &mut bytes[1..], super::V3_AES_BLOCKS_COUNT);

    // Get checked keypair
    bytes_to_checked_keypair::<crate::keys::ed25519::bip32::KeyPair>(&bytes[1..])
}

fn bytes_to_checked_keypair<KP: KeyPair<Seed = Seed32, PublicKey = PublicKey>>(
    bytes: &[u8],
) -> Result<KP, DewifReadError> {
    // Wrap bytes into Seed32 and PublicKey
    let seed = Seed32::new(
        (&bytes[..SEED_32_SIZE_IN_BYTES])
            .try_into()
            .unwrap_or_else(|_| unsafe { unreachable_unchecked() }),
    );
    let expected_pubkey = PublicKey::try_from(&bytes[PUBKEY_DATAS_SIZE_IN_BYTES..])
        .map_err(|_| DewifReadError::InvalidFormat)?;

    // Get keypair
    let keypair = KP::from_seed(seed);

    // Check pubkey
    if keypair.public_key() != expected_pubkey {
        Err(DewifReadError::CorruptedContent)
    } else {
        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use crate::dewif::DewifMeta;

    use super::*;
    use unwrap::unwrap;

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
            "AAAAARAAAAGfFDAs+jVZYkfhBlHZZ2fEQIvBqnG16g5+02cY18wSOjW0cUg2JV3SUTJYN2CrbQeRDwGazWnzSFBphchMmiL0",
            "toto titi tata"
        ) {
            Ok(())
        } else {
            panic!("Read must be fail with error UnexpectedCurrency.")
        }
    }

    #[test]
    fn read_v1_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAAARAAAAGfFDAs+jVZYkfhBlHZZ2fEQIvBqnG16g5+02cY18wSOjW0cUg2JV3SUTJYN2CrbQeRDwGazWnzSFBphchMmiL0";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = ExpectedCurrency::Specific(unwrap!(Currency::from_str("g1-test")));

        // Read DEWIF file content
        // If the file content is correct, we get a key-pair iterator.
        assert_eq!(
            unwrap!(read_dewif_log_n(expected_currency, dewif_file_content)),
            12u8
        );
        assert_eq!(
            unwrap!(read_dewif_meta(dewif_file_content)),
            DewifMeta {
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 12u8,
                version: 1
            }
        );
        let mut key_pair_iter = unwrap!(read_dewif_file_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        ));

        // Get first key-pair
        let key_pair = unwrap!(key_pair_iter.next());

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

    #[test]
    fn read_v3_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAAAxAAAAEPdMuBFXF4C6GZPGsJDiPBbacpVKeaLoJwkDsuqLjkwof1c760Z5iVpnZlLt5XEFlEehbdtLllVhccf9OK6Zjn8A==";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = ExpectedCurrency::Specific(unwrap!(Currency::from_str("g1-test")));

        // Read DEWIF file content
        // If the file content is correct, we get a key-pair iterator.
        assert_eq!(
            unwrap!(read_dewif_log_n(expected_currency, dewif_file_content)),
            15u8
        );
        assert_eq!(
            unwrap!(read_dewif_meta(dewif_file_content)),
            DewifMeta {
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 15u8,
                version: 3
            }
        );
        let mut key_pair_iter = unwrap!(read_dewif_file_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        ));

        // Get first key-pair
        let key_pair = unwrap!(key_pair_iter.next());

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

    #[cfg(feature = "bip32-ed25519")]
    #[test]
    fn read_v4_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, PublicKey, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAABBAAAAEPcE3yXhA0T0iElXR/vDbZTRSmdec26lWu42mWKuaczzxZ22bIGVfLmlhfVW9NWmWY7m/P/j0W6Su4QZEiERe8vA==";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = ExpectedCurrency::Specific(unwrap!(Currency::from_str("g1-test")));

        // Read DEWIF file content
        // If the file content is correct, we get a key-pair iterator.
        assert_eq!(
            unwrap!(read_dewif_log_n(expected_currency, dewif_file_content)),
            15u8
        );
        assert_eq!(
            unwrap!(read_dewif_meta(dewif_file_content)),
            DewifMeta {
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 15u8,
                version: 4
            }
        );
        let mut key_pair_iter = unwrap!(read_dewif_file_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        ));

        // Get first key-pair
        let key_pair = unwrap!(key_pair_iter.next());

        assert_eq!(
            "F8jY1tbCWE47NVM8Qj2S5sbNruTBXKhPDL4RjVXgNJsq",
            &key_pair.public_key().to_string()
        );

        // Generate signator
        // `Signator` is a non-copiable and non-clonable type,
        // so only generate it when you are in the scope where you effectively sign.
        let signator = key_pair.generate_signator();

        // Sign a message with keypair
        let sig = signator.sign(b"message");

        assert_eq!(
            "Igm0pwC1Vd5wOXMNeMD7pRzmpRkpAed+j7O+4Co4mQ3/GhWnZuE8+AvgKK3lz4PtpqoCS47y6aUo6MGUA5lJCw==",
            &sig.to_string()
        );
        assert!(key_pair.public_key().verify(b"message", &sig).is_ok());
    }
}
