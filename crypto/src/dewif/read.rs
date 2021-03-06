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

use super::{Currency, DewifContent, DewifPayload, ExpectedCurrency};
use crate::keys::{KeyPair, Signator};
use crate::seeds::{Seed32, SEED_32_SIZE_IN_BYTES};
use crate::{
    keys::{
        ed25519::{PublicKey, PUBKEY_DATAS_SIZE_IN_BYTES},
        KeysAlgo,
    },
    mnemonic::{Language, Mnemonic, MnemonicError},
};
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
    /// Unspecified rand error
    #[error("Unspecified rand error")]
    UnspecifiedRandError,
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

/// read dewif content with user passphrase
pub fn read_dewif_content(
    expected_currency: ExpectedCurrency,
    file_content: &str,
    passphrase: &str,
) -> Result<DewifContent, DewifReadError> {
    let meta = read_dewif_meta(file_content)?;

    let mut bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;

    let version = meta.version;
    let currency = meta.currency;

    if !expected_currency.is_valid(currency) {
        return Err(DewifReadError::UnexpectedCurrency {
            expected: expected_currency,
            actual: currency,
        });
    }

    let payload = match version {
        1 => read_dewif_v1(&mut bytes[8..], passphrase)?,
        other_version => {
            return Err(DewifReadError::UnsupportedVersion {
                actual: other_version,
            });
        }
    };
    Ok(DewifContent { meta, payload })
}

fn read_dewif_v1(bytes: &mut [u8], passphrase: &str) -> Result<DewifPayload, DewifReadError> {
    match bytes.len() {
        len if len < super::V1_BIP32_ED25519_DATA_LEN => {
            return Err(DewifReadError::TooShortContent)
        }
        len if len > super::V1_ED25519_DATA_LEN => return Err(DewifReadError::TooLongContent),
        _ => (),
    }

    // Read log_n
    let log_n = bytes[0];
    // Read algo
    let algo = KeysAlgo::from_u8(bytes[1]).map_err(|_| DewifReadError::UnknownAlgo)?;
    // Read nonce
    let nonce = super::read_nonce(&bytes[2..14]);

    match algo {
        KeysAlgo::Ed25519 => {
            // Decrypt bytes
            let mut decrypted_bytes = [0u8; 64];
            crate::xor_cipher::xor_cipher(
                &bytes[super::V1_CLEAR_HEADERS_LEN..],
                super::gen_xor_seed64(log_n, nonce, passphrase).as_ref(),
                &mut decrypted_bytes,
            );

            // Get checked keypair
            Ok(DewifPayload::Ed25519(bytes_to_checked_keypair(
                &decrypted_bytes,
            )?))
        }
        KeysAlgo::Bip32Ed25519 => {
            // Decrypt bytes
            let mut decrypted_bytes = [0u8; 42];
            crate::xor_cipher::xor_cipher(
                &bytes[super::V1_CLEAR_HEADERS_LEN..(super::V1_CLEAR_HEADERS_LEN + 42)],
                super::gen_xor_seed42(log_n, nonce, passphrase).as_ref(),
                &mut decrypted_bytes,
            );

            // Get checked keypair
            let mnemonic = get_dewif_mnemonic(&decrypted_bytes)
                .map_err(|_| DewifReadError::CorruptedContent)?;
            let checksum = super::compute_checksum(&nonce, decrypted_bytes[0], mnemonic.entropy());
            let expected_checksum = &decrypted_bytes[34..];
            if &checksum[..] != expected_checksum {
                Err(DewifReadError::CorruptedContent)
            } else {
                Ok(DewifPayload::Bip32Ed25519(mnemonic))
            }
        }
    }
}

// Internal insecure function, should not expose on public API
pub(super) fn get_dewif_seed_unchecked(bytes: &mut [u8], passphrase: &str) -> Seed32 {
    // Read log_n
    let log_n = bytes[0];
    // Read nonce
    let nonce = super::read_nonce(&bytes[2..14]);

    // Decrypt bytes
    let mut decrypted_bytes = [0u8; 64];
    crate::xor_cipher::xor_cipher(
        &bytes[super::V1_CLEAR_HEADERS_LEN..],
        super::gen_xor_seed64(log_n, nonce, passphrase).as_ref(),
        &mut decrypted_bytes,
    );

    // Wrap bytes into Seed32
    Seed32::new(
        (&decrypted_bytes[..SEED_32_SIZE_IN_BYTES])
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

#[cfg(feature = "bip32-ed25519")]
fn get_dewif_mnemonic(decrypted_bytes: &[u8]) -> Result<Mnemonic, MnemonicError> {
    // Read mnemonic language
    let lang = Language::from_u8(decrypted_bytes[0])?;

    // Read mnemonic entropy length
    let mnemonic_entropy_len = decrypted_bytes[1];

    Mnemonic::from_entropy(
        &decrypted_bytes[2..(2 + mnemonic_entropy_len as usize)],
        lang,
    )
}

#[cfg(test)]
mod tests {
    use crate::dewif::DewifMeta;

    use super::*;
    use unwrap::unwrap;

    #[test]
    fn read_unsupported_version() -> Result<(), ()> {
        if let Err(DewifReadError::UnsupportedVersion { .. }) = read_dewif_content(
            ExpectedCurrency::Any,
            "ABAAARAAAAEMAAqqbWsirdvN0W7IkpmKdG/Zbt4ZszPx9VcWUu0o4cdxIZ4HHUybCVbyVmQL9Wid8KE6FCWeMRtr5OKAUKYwsNI=",
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
            read_dewif_content(ExpectedCurrency::Any, "AAA", "toto")
        {
            Ok(())
        } else {
            panic!("Read must be fail with error TooShortContent.")
        }
    }

    #[test]
    fn read_unexpected_currency() -> Result<(), ()> {
        if let Err(DewifReadError::UnexpectedCurrency { .. }) = read_dewif_content(
            ExpectedCurrency::Specific(Currency::from(42)),
            "AAAAARAAAAEMAAqqbWsirdvN0W7IkpmKdG/Zbt4ZszPx9VcWUu0o4cdxIZ4HHUybCVbyVmQL9Wid8KE6FCWeMRtr5OKAUKYwsNI=",
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
        let dewif_file_content = "AAAAARAAAAEMACoqKioqKioqKioqKufSmkhlv1gbkEomswG4hQ2uMIVh+YOEym0ZRyNRwX226lsjB2UT2cnWLR11Wf3xm8Dm2lLB4IAfxd+iFiza7h4=";

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
        if let DewifContent {
            payload: DewifPayload::Ed25519(key_pair),
            ..
        } = unwrap!(read_dewif_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        )) {
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
        } else {
            panic!("corrupted dewif");
        }
    }

    #[test]
    fn read_v1_bip32_ok() {
        use crate::dewif::Currency;
        use crate::keys::{KeyPair, PublicKey, Signator};
        use std::str::FromStr;

        // Get DEWIF file content (Usually from disk)
        let dewif_file_content =
            "AAAAARAAAAEOASoqKioqKioqKioqKkIx/qkP1PWhtDNca4MdsvxPWAtvCd7nYriwMOHKxIFO8GJy9ElNngbSVQ==";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = ExpectedCurrency::Specific(unwrap!(Currency::from_str("g1-test")));

        // Read DEWIF file content
        // If the file content is correct, we get a key-pair iterator.
        assert_eq!(
            unwrap!(read_dewif_log_n(expected_currency, dewif_file_content)),
            14u8
        );
        assert_eq!(
            unwrap!(read_dewif_meta(dewif_file_content)),
            DewifMeta {
                algo: KeysAlgo::Bip32Ed25519,
                currency: unwrap!(Currency::from_str("g1-test")),
                log_n: 14u8,
                version: 1
            }
        );
        if let DewifContent {
            payload: DewifPayload::Bip32Ed25519(mnemonic),
            ..
        } = unwrap!(read_dewif_content(
            expected_currency,
            dewif_file_content,
            encryption_passphrase
        )) {
            let key_pair = crate::keys::ed25519::bip32::KeyPair::from_mnemonic(&mnemonic);

            assert_eq!(
                "9TgSNiJPFtQV89Wt2GPnoozpSWTJzAxERpmTQr5Lhv7G",
                &key_pair.public_key().to_string()
            );

            // Generate signator
            // `Signator` is a non-copiable and non-clonable type,
            // so only generate it when you are in the scope where you effectively sign.
            let signator = key_pair.generate_signator();

            // Sign a message with keypair
            let sig = signator.sign(b"message");

            assert_eq!(
                "N1+7Dzjde71hBCkoqSWRc3Ywn4+z7FChKjCgG8OtIlki4BH9w6QLXQ8Pkb7uyoCa9N9VuUgtJDgYSn09ll6yCg==",
                &sig.to_string()
            );
            assert!(key_pair.public_key().verify(b"message", &sig).is_ok());
        } else {
            panic!("corrupted dewif");
        }
    }
}
