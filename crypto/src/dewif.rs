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

//! Handle [DEWIF][dewif-spec] format
//!
//! See [DEWIF format specifications][dewif-spec].
//!
//! [dewif-spec]: https://git.duniter.org/documents/rfcs/blob/dewif/rfc/0013_Duniter_Encrypted_Wallet_Import_Format.md
//!
//! # Summary
//!
//! * [Write DEWIF file](#write-ed25519-key-pair-in-dewif-file)
//! * [Read DEWIF file](#read-dewif-file)
//!
//!
//! ## Write Bip32-Ed25519 key-pair in DEWIF file
//!
//! ```
//! use dup_crypto::dewif::{Currency, G1_TEST_CURRENCY, create_dewif_v1};
//! use dup_crypto::keys::ed25519::bip32::KeyPair;
//! use dup_crypto::mnemonic::{Language, Mnemonic};
//! use std::num::NonZeroU32;
//!
//! // Get user mnemonic (from cli prompt or gui)
//! let mnemonic = Mnemonic::from_phrase(
//!     "crop cash unable insane eight faith inflict route frame loud box vibrant",
//!     Language::English,
//! ).expect("wrong mnemonic");
//!
//! // Generate ed25519 keypair
//! let keypair = KeyPair::from_mnemonic(&mnemonic);
//!
//! // Get user passphrase for DEWIF encryption
//! let encryption_passphrase = "toto titi tata";
//!
//! // Serialize keypair in DEWIF format
//! let dewif_content = create_dewif_v1(Currency::from(G1_TEST_CURRENCY), 12u8, &mnemonic, encryption_passphrase)?;
//!
//! // Then store `dewif_content` somewhere (It is a base64 string)
//!
//! # Ok::<(), dup_crypto::rand::UnspecifiedRandError>(())
//! ```
//!
//! ## Read DEWIF file
//!
//! ```
//! use dup_crypto::dewif::{Currency, G1_TEST_CURRENCY, DewifContent, DewifMeta, DewifPayload, ExpectedCurrency, read_dewif_content};
//! use dup_crypto::keys::{KeysAlgo, KeyPair, Signator};
//! use dup_crypto::mnemonic::{Language, Mnemonic};
//! use std::num::NonZeroU32;
//! use std::str::FromStr;
//!
//! // Get DEWIF content (Usually from disk)
//! let dewif_content = "AAAAARAAAAEOASoqKioqKioqKioqKkIx/qkP1PWhtDNca4MdsvxPWAtvCd7nYriwMOHKxIFO8GJy9ElNngbSVQ==";
//!
//! // Get user passphrase for DEWIF decryption (from cli prompt or gui)
//! let encryption_passphrase = "toto titi tata";
//!
//! // Expected currency
//! let expected_currency = ExpectedCurrency::Specific(Currency::from(G1_TEST_CURRENCY));
//!
//! // Read DEWIF file content
//! let DewifContent { meta, payload } = read_dewif_content(expected_currency, dewif_content, encryption_passphrase)?;
//!
//! assert_eq!(
//!     meta,
//!     DewifMeta {
//!         algo: KeysAlgo::Bip32Ed25519,
//!         currency: Currency::from(G1_TEST_CURRENCY),
//!         log_n: 14,
//!         version: 1
//!     }
//! );
//!
//! if let DewifPayload::Bip32Ed25519(mnemonic) = payload {
//!     let key_pair = dup_crypto::keys::ed25519::bip32::KeyPair::from_mnemonic(&mnemonic);
//!
//!    // Generate signator
//!    // `Signator` is a non-copiable and non-clonable type,
//!    // so only generate it when you are in the scope where you effectively sign.
//!    let signator = key_pair.generate_signator();
//!
//!    // Sign a message with keypair
//!    let sig = signator.sign(b"message");
//!
//!    assert_eq!(
//!        "N1+7Dzjde71hBCkoqSWRc3Ywn4+z7FChKjCgG8OtIlki4BH9w6QLXQ8Pkb7uyoCa9N9VuUgtJDgYSn09ll6yCg==",
//!        &sig.to_string()
//!    );
//! } else {
//!     panic!("corrupted dewif")
//! }
//!
//! # Ok::<(), dup_crypto::dewif::DewifReadError>(())
//! ```
//!

mod currency;
mod read;
mod write;

pub use currency::{Currency, ExpectedCurrency, G1_CURRENCY, G1_TEST_CURRENCY};
pub use read::{read_dewif_content, read_dewif_log_n, read_dewif_meta, DewifReadError};
pub use write::create_dewif_v1;
#[allow(deprecated)]
pub use write::create_dewif_v1_legacy;

#[cfg(feature = "bip32-ed25519")]
use crate::keys::{KeyPair as _, KeysAlgo};
use crate::scrypt::{params::ScryptParams, scrypt};
use crate::seeds::{Seed42, Seed64};
use crate::{hashs::Hash, rand::UnspecifiedRandError};

const HEADERS_LEN: usize = 8;

// v1
static VERSION_V1: &[u8] = &[0, 0, 0, 1];
const V1_CHECKSUM_LEN: usize = 8;
const V1_NONCE_LEN: usize = 12;
const V1_CLEAR_HEADERS_LEN: usize = 2 + V1_NONCE_LEN;

// v1 Ed25519
const V1_ED25519_ENCRYPTED_BYTES_LEN: usize = 64;
const V1_ED25519_DATA_LEN: usize = V1_ED25519_ENCRYPTED_BYTES_LEN + V1_CLEAR_HEADERS_LEN; // 64 + 14 = 78
const V1_ED25519_BYTES_LEN: usize = HEADERS_LEN + V1_ED25519_DATA_LEN; // 8 + 78 = 86
const V1_ED25519_UNENCRYPTED_BYTES_LEN: usize =
    V1_ED25519_BYTES_LEN - V1_ED25519_ENCRYPTED_BYTES_LEN; // 86 - 64 = 22

// v1 Bip32-Ed25519
const V1_BIP32_ED25519_ENCRYPTED_BYTES_LEN: usize = 42;
const V1_BIP32_ED25519_DATA_LEN: usize =
    V1_BIP32_ED25519_ENCRYPTED_BYTES_LEN + V1_CLEAR_HEADERS_LEN;
const V1_BIP32_ED25519_BYTES_LEN: usize = HEADERS_LEN + V1_BIP32_ED25519_DATA_LEN;
const V1_BIP32_ED25519_UNENCRYPTED_BYTES_LEN: usize =
    V1_BIP32_ED25519_BYTES_LEN - V1_BIP32_ED25519_ENCRYPTED_BYTES_LEN;

type Checksum = [u8; V1_CHECKSUM_LEN];
type Nonce = [u8; V1_NONCE_LEN];

#[derive(Debug, PartialEq)]
/// DEWIF content
pub struct DewifContent {
    /// DEWIF meta data
    pub meta: DewifMeta,
    /// DEWIF payload
    pub payload: DewifPayload,
}

/// DEWIF meta data
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DewifMeta {
    /// Algorithm
    pub algo: KeysAlgo,
    /// Currency
    pub currency: Currency,
    /// Scrypt parameter log N
    pub log_n: u8,
    /// DEWIF version
    pub version: u32,
}

#[derive(Debug, PartialEq)]
/// DEWIF payload
pub enum DewifPayload {
    /// Ed25519 algo payload
    Ed25519(crate::keys::ed25519::Ed25519KeyPair),
    /// Bip32-Ed25519 algo payload
    Bip32Ed25519(crate::mnemonic::Mnemonic),
}

/// Change DEWIF passphrase
pub fn change_dewif_passphrase(
    file_content: &str,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<String, DewifReadError> {
    let DewifContent {
        meta:
            DewifMeta {
                algo: _,
                currency,
                log_n,
                version,
            },
        payload,
    } = read_dewif_content(ExpectedCurrency::Any, file_content, old_passphrase)?;
    if version == 1 {
        let mut bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;
        match payload {
            DewifPayload::Ed25519(kp) => {
                let seed = read::get_dewif_seed_unchecked(&mut bytes[8..], old_passphrase);
                write::write_dewif_v1_ed25519(
                    currency,
                    log_n,
                    new_passphrase,
                    &kp.public_key(),
                    &seed,
                )
                .map_err(|_| DewifReadError::UnspecifiedRandError)
            }
            #[cfg(feature = "bip32-ed25519")]
            DewifPayload::Bip32Ed25519(mnemonic) => {
                write::write_dewif_v1_bip_ed25519(currency, log_n, new_passphrase, &mnemonic)
                    .map_err(|_| DewifReadError::UnspecifiedRandError)
            }
        }
    } else {
        Err(DewifReadError::UnsupportedVersion { actual: version })
    }
}

fn compute_checksum(nonce: &Nonce, language_code: u8, mnemonic_entropy: &[u8]) -> Checksum {
    let mut cs_bytes = [0u8; V1_CHECKSUM_LEN];
    let hash = crate::hashs::Hash::compute_multipart(&[
        &nonce[..],
        &[language_code, mnemonic_entropy.len() as u8],
        mnemonic_entropy,
    ]);
    cs_bytes.copy_from_slice(&hash.0[..8]);
    cs_bytes
}

#[cfg(not(test))]
fn gen_nonce() -> Result<Nonce, UnspecifiedRandError> {
    let mut nonce = [0u8; V1_NONCE_LEN];
    crate::rand::gen_random_bytes(&mut nonce[..])?;
    Ok(nonce)
}
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn gen_nonce() -> Result<Nonce, UnspecifiedRandError> {
    Ok([42u8; V1_NONCE_LEN])
}

fn gen_xor_seed42(log_n: u8, nonce: Nonce, passphrase: &str) -> Seed42 {
    let salt = Hash::compute_multipart(&[b"dewif", &nonce[..], passphrase.as_bytes()]);
    let mut seed_bytes = [0u8; 42];
    scrypt(
        passphrase.as_bytes(),
        salt.as_ref(),
        &ScryptParams { log_n, r: 16, p: 1 },
        &mut seed_bytes,
    );
    Seed42::new(seed_bytes)
}

fn gen_xor_seed64(log_n: u8, nonce: Nonce, passphrase: &str) -> Seed64 {
    let salt = Hash::compute_multipart(&[b"dewif", &nonce[..], passphrase.as_bytes()]);
    let mut seed_bytes = [0u8; 64];
    scrypt(
        passphrase.as_bytes(),
        salt.as_ref(),
        &ScryptParams { log_n, r: 16, p: 1 },
        &mut seed_bytes,
    );
    Seed64::new(seed_bytes)
}

fn read_nonce(bytes: &[u8]) -> Nonce {
    let mut nonce = [0u8; V1_NONCE_LEN];
    nonce.copy_from_slice(bytes);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bases::b58::ToBase58 as _;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::seeds::Seed32;
    use unwrap::unwrap;

    #[test]
    fn dewif_v1() {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content_str = unwrap!(write::write_dewif_v1_ed25519(
            currency,
            12,
            "toto",
            &written_keypair.public_key(),
            &written_keypair.seed(),
        ));

        let dewif_content = unwrap!(read_dewif_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content_str,
            "toto"
        ));

        assert_eq!(
            DewifPayload::Ed25519(written_keypair.clone()),
            dewif_content.payload,
        );

        // Change DEWIF passphrase
        let new_dewif_content =
            unwrap!(change_dewif_passphrase(&dewif_content_str, "toto", "titi"));

        let dewif_content = unwrap!(read_dewif_content(
            ExpectedCurrency::Specific(currency),
            &new_dewif_content,
            "titi"
        ));

        assert_eq!(
            DewifPayload::Ed25519(written_keypair),
            dewif_content.payload,
        );
    }

    #[test]
    fn dewif_v1_corrupted() -> Result<(), ()> {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let mut dewif_content = unwrap!(write::write_dewif_v1_ed25519(
            currency,
            12,
            "toto",
            &written_keypair.public_key(),
            &written_keypair.seed(),
        ));

        // Corrupt one byte in dewif_content
        let dewif_bytes_mut = unsafe { dewif_content.as_bytes_mut() };
        dewif_bytes_mut[13] = 0x52;

        if let Err(DewifReadError::CorruptedContent) =
            read_dewif_content(ExpectedCurrency::Specific(currency), &dewif_content, "toto")
        {
            Ok(())
        } else {
            panic!("dewif content must be corrupted.")
        }
    }

    #[test]
    fn dewif_v1_bip32() -> Result<(), crate::mnemonic::MnemonicError> {
        let mnemonic = crate::mnemonic::Mnemonic::from_phrase(
            "crop cash unable insane eight faith inflict route frame loud box vibrant",
            crate::mnemonic::Language::English,
        )?;
        let mnemonic_copy = crate::mnemonic::Mnemonic::from_phrase(
            "crop cash unable insane eight faith inflict route frame loud box vibrant",
            crate::mnemonic::Language::English,
        )?;
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content_str = unwrap!(write::write_dewif_v1_bip_ed25519(
            currency, 12, "toto", &mnemonic
        ));

        let dewif_content = unwrap!(read_dewif_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content_str,
            "toto"
        ));

        assert_eq!(DewifPayload::Bip32Ed25519(mnemonic), dewif_content.payload,);

        // Change DEWIF passphrase
        let new_dewif_content_str =
            unwrap!(change_dewif_passphrase(&dewif_content_str, "toto", "titi"));

        let new_dewif_content = unwrap!(read_dewif_content(
            ExpectedCurrency::Specific(currency),
            &new_dewif_content_str,
            "titi"
        ));

        assert_eq!(
            DewifPayload::Bip32Ed25519(mnemonic_copy),
            new_dewif_content.payload,
        );

        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn dewif_v1_legacy() -> Result<(), DewifReadError> {
        let currency = Currency::from(G1_CURRENCY);
        let dewif = unwrap!(create_dewif_v1_legacy(
            currency,
            12,
            "pass".to_owned(),
            "salt".to_owned(),
            "toto"
        ));

        if let DewifContent {
            payload: DewifPayload::Ed25519(key_pair),
            ..
        } = read_dewif_content(ExpectedCurrency::Specific(currency), &dewif, "toto")?
        {
            assert_eq!(
                "3YumN7F7D8c2hmkHLHf3ZD8wc3tBHiECEK9zLPkaJtAF",
                &key_pair.public_key().to_base58()
            );
        } else {
            panic!("corrupted dewif");
        }

        Ok(())
    }
}
