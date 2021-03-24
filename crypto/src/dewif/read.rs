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
use crate::keys::{
    ed25519::{PublicKey, PUBKEY_DATAS_SIZE_IN_BYTES},
    KeysAlgo,
};
use crate::keys::{KeyPair, KeyPairEnum, Signator};
use crate::seeds::{Seed32, SEED_32_SIZE_IN_BYTES};
use byteorder::ByteOrder;
use std::{
    convert::{TryFrom, TryInto},
    hint::unreachable_unchecked,
};
use thiserror::Error;

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
    /// Unknown algorithm
    #[error("unknown algorithm")]
    UnknownAlgo,
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

    if bytes.len() < 9 {
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
        1 => Ok(bytes[8]),
        other_version => Err(DewifReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

/// read dewif meta data
pub fn read_dewif_meta(file_content: &str) -> Result<super::DewifMeta, DewifReadError> {
    let bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;

    if bytes.len() < 10 {
        return Err(DewifReadError::TooShortContent);
    }

    let version = byteorder::BigEndian::read_u32(&bytes[0..4]);
    let currency = Currency::from(byteorder::BigEndian::read_u32(&bytes[4..8]));

    let log_n = bytes[8];
    let algo = KeysAlgo::from_u8(bytes[9]).map_err(|_| DewifReadError::UnknownAlgo)?;

    Ok(super::DewifMeta {
        algo,
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
) -> Result<KeyPairEnum, DewifReadError> {
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
        1 => read_dewif_v1(&mut bytes[8..], passphrase),
        other_version => Err(DewifReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

fn read_dewif_v1(bytes: &mut [u8], passphrase: &str) -> Result<KeyPairEnum, DewifReadError> {
    match bytes.len() {
        len if len < super::V1_DATA_LEN => return Err(DewifReadError::TooShortContent),
        len if len > super::V1_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Read log_n
    let log_n = bytes[0];
    // Read algo
    let algo = KeysAlgo::from_u8(bytes[1]).map_err(|_| DewifReadError::UnknownAlgo)?;

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, log_n));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, &mut bytes[2..], super::V1_AES_BLOCKS_COUNT);

    // Get checked keypair
    Ok(match algo {
        KeysAlgo::Ed25519 => KeyPairEnum::Ed25519(bytes_to_checked_keypair(&bytes[2..])?),
        KeysAlgo::Bip32Ed25519 => KeyPairEnum::Bip32Ed25519(bytes_to_checked_keypair(&bytes[2..])?),
    })
}

#[cfg(feature = "bip32-ed25519")]
// Internal insecure function, should not expose on public API
pub(super) fn get_dewif_seed_unchecked(bytes: &mut [u8], passphrase: &str) -> Seed32 {
    // Read log_n
    let log_n = bytes[0];

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, log_n));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, &mut bytes[2..], super::V1_AES_BLOCKS_COUNT);

    // Wrap bytes into Seed32
    Seed32::new(
        (&bytes[2..(SEED_32_SIZE_IN_BYTES + 2)])
            .try_into()
            .unwrap_or_else(|_| unsafe { unreachable_unchecked() }),
    )
}

fn bytes_to_checked_keypair<
    S: Signator<PublicKey = PublicKey>,
    KP: KeyPair<Seed = Seed32, Signator = S>,
>(
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
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAAARAAAAEMAN9vzS8DfK3ZePpXUgyV0Vbfb80vA3yt2Xj6V1IMldFWYQlZxHGWyI07G49EiViJqAhMGenY9DP6Svbh62bOAbE=";

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
                algo: KeysAlgo::Ed25519,
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 12u8,
                version: 1
            }
        );
        let key_pair = unwrap!(read_dewif_file_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        ));

        assert_eq!(
            "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS",
            &key_pair.public_key().to_string()
        );

        // Generate signator
        // `Signator` is a non-copiable and non-clonable type,
        // so only generate it when you are in the scope where you effectively sign.
        let signator = key_pair.generate_signator();

        // Sign a message with keypair
        let sig = signator.sign(b"message");

        assert_eq!(
            "JPurBgnHExHND1woow9nB7xVQjKkdHGs1znQbgv0ttZwOz16OlOCDDfvXfKE8e0xUfs2u7winav8IDwo7d1EBQ==",
            &sig.to_string()
        )
    }

    #[test]
    fn read_v1_bip32_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, PublicKey, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content = "AAAAARAAAAEPAXBN8l4QNE9IhJV0f7w22U0UpnXnNupVruNplirmnM88WdtmyBlXy5pYX1VvTVplmO5vz/49FukruEGRIhEXvLw=";

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
                algo: KeysAlgo::Bip32Ed25519,
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 15u8,
                version: 1
            }
        );
        let key_pair = unwrap!(read_dewif_file_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        ));

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
