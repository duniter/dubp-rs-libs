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
//!     "tongue cute mail fossil great frozen same social weasel impact brush kind",
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
//! let dewif_content = create_dewif_v1(Currency::from(G1_TEST_CURRENCY), 12u8, &mnemonic, encryption_passphrase);
//!
//! assert_eq!(
//!     "AAAAARAAAAEMAQ38iXS15idThWb0WUDJe5tpCVUD9IpBvXIGFz9gbsGYOkkesYZS31v+rQ4jxqqjuyNbzJtbiIzjOsFUqvVgwdI=",
//!     dewif_content
//! )
//! ```
//!
//! ## Read DEWIF file
//!
//! ```
//! use dup_crypto::dewif::{Currency, G1_TEST_CURRENCY, ExpectedCurrency, read_dewif_file_content};
//! use dup_crypto::keys::{KeyPair, Signator};
//! use std::num::NonZeroU32;
//! use std::str::FromStr;
//!
//! // Get DEWIF file content (Usually from disk)
//! let dewif_file_content = "AAAAARAAAAEMAQ38iXS15idThWb0WUDJe5tpCVUD9IpBvXIGFz9gbsGYOkkesYZS31v+rQ4jxqqjuyNbzJtbiIzjOsFUqvVgwdI=";
//!
//! // Get user passphrase for DEWIF decryption (from cli prompt or gui)
//! let encryption_passphrase = "toto titi tata";
//!
//! // Expected currency
//! let expected_currency = ExpectedCurrency::Specific(Currency::from(G1_TEST_CURRENCY));
//!
//! // Read DEWIF file content
//! // If the file content is correct, we get a key-pair.
//! let key_pair = read_dewif_file_content(expected_currency, dewif_file_content, encryption_passphrase)?;
//!
//! assert_eq!(
//!     "2thWfGR3BVAMSjwML6X2ZrWZVdyqvBsfMQKKwyWWqW1d",
//!     &key_pair.public_key().to_string()
//! );
//!
//! // Generate signator
//! // `Signator` is a non-copiable and non-clonable type,
//! // so only generate it when you are in the scope where you effectively sign.
//! let signator = key_pair.generate_signator();
//!
//! // Sign a message with keypair
//! let sig = signator.sign(b"message");
//!
//! assert_eq!(
//!     "vg7NWUTR8t4jDaki1nVj1mLV2ibynDL7XayGPvGWVw8gZbnUDjeVTukUIs7esF/MegzicIwbhFBPE216AZEkAw==",
//!     &sig.to_string()
//! );
//! # Ok::<(), dup_crypto::dewif::DewifReadError>(())
//! ```
//!

mod currency;
mod read;
mod write;

pub use currency::{Currency, ExpectedCurrency, G1_CURRENCY, G1_TEST_CURRENCY};
pub use read::{read_dewif_file_content, read_dewif_log_n, read_dewif_meta, DewifReadError};
pub use write::create_dewif_v1;
#[allow(deprecated)]
pub use write::create_dewif_v1_legacy;

use crate::hashs::Hash;
#[cfg(feature = "bip32-ed25519")]
use crate::keys::{KeyPair as _, KeysAlgo};
use crate::scrypt::{params::ScryptParams, scrypt};
use crate::seeds::Seed32;

const HEADERS_LEN: usize = 8;

// v1
static VERSION_V1: &[u8] = &[0, 0, 0, 1];
const V1_ENCRYPTED_BYTES_LEN: usize = 64;
const V1_DATA_LEN: usize = V1_ENCRYPTED_BYTES_LEN + 2;
const V1_BYTES_LEN: usize = HEADERS_LEN + V1_DATA_LEN;
const V1_UNENCRYPTED_BYTES_LEN: usize = V1_BYTES_LEN - V1_ENCRYPTED_BYTES_LEN;
const V1_AES_BLOCKS_COUNT: usize = 4;

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

/// Change DEWIF passphrase
pub fn change_dewif_passphrase(
    file_content: &str,
    old_passphrase: &str,
    new_passphrase: &str,
) -> Result<String, DewifReadError> {
    let DewifMeta {
        algo: _,
        currency,
        log_n,
        version,
    } = read_dewif_meta(file_content)?;
    let keypair = read_dewif_file_content(
        ExpectedCurrency::Specific(currency),
        file_content,
        old_passphrase,
    )?;

    if version == 1 {
        let mut bytes = base64::decode(file_content).map_err(DewifReadError::InvalidBase64Str)?;
        let seed = read::get_dewif_seed_unchecked(&mut bytes[8..], old_passphrase);
        match keypair {
            crate::keys::KeyPairEnum::Ed25519(kp) => Ok(write::write_dewif_v1_content(
                currency,
                KeysAlgo::Ed25519,
                log_n,
                new_passphrase,
                &kp.public_key(),
                &seed,
            )),
            #[cfg(feature = "bip32-ed25519")]
            crate::keys::KeyPairEnum::Bip32Ed25519(kp) => Ok(write::write_dewif_v1_content(
                currency,
                KeysAlgo::Bip32Ed25519,
                log_n,
                new_passphrase,
                &kp.public_key(),
                &seed,
            )),
        }
    } else {
        Err(DewifReadError::UnsupportedVersion { actual: version })
    }
}

fn gen_aes_seed(passphrase: &str, log_n: u8) -> Seed32 {
    let salt = Hash::compute(format!("dewif{}", passphrase).as_bytes());
    let mut aes_seed_bytes = [0u8; 32];
    scrypt(
        passphrase.as_bytes(),
        salt.as_ref(),
        &ScryptParams { log_n, r: 16, p: 1 },
        &mut aes_seed_bytes,
    );
    Seed32::new(aes_seed_bytes)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::keys::KeyPairEnum;
    use crate::seeds::Seed32;
    use unwrap::unwrap;

    #[test]
    fn dewif_v1() {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content = write::write_dewif_v1_content(
            currency,
            KeysAlgo::Ed25519,
            12,
            "toto",
            &written_keypair.public_key(),
            &written_keypair.seed(),
        );

        let keypair_read = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content,
            "toto"
        ));

        assert_eq!(KeyPairEnum::Ed25519(written_keypair.clone()), keypair_read,);

        // Change DEWIF passphrase
        let new_dewif_content = unwrap!(change_dewif_passphrase(&dewif_content, "toto", "titi"));

        let keypair_read = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &new_dewif_content,
            "titi"
        ));

        assert_eq!(KeyPairEnum::Ed25519(written_keypair), keypair_read,);
    }

    #[test]
    fn dewif_v1_corrupted() -> Result<(), ()> {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let mut dewif_content = write::write_dewif_v1_content(
            currency,
            KeysAlgo::Ed25519,
            12,
            "toto",
            &written_keypair.public_key(),
            &written_keypair.seed(),
        );

        // Corrupt one byte in dewif_content
        let dewif_bytes_mut = unsafe { dewif_content.as_bytes_mut() };
        dewif_bytes_mut[13] = 0x52;

        if let Err(DewifReadError::CorruptedContent) =
            read_dewif_file_content(ExpectedCurrency::Specific(currency), &dewif_content, "toto")
        {
            Ok(())
        } else {
            panic!("dewif content must be corrupted.")
        }
    }

    #[test]
    fn dewif_v1_bip32() {
        let seed = Seed32::new([0u8; 32]);
        let written_keypair = crate::keys::ed25519::bip32::KeyPair::from_seed(seed.clone());
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content = write::write_dewif_v1_content(
            currency,
            KeysAlgo::Bip32Ed25519,
            12,
            "toto",
            &written_keypair.public_key(),
            &seed,
        );

        let keypair_read = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content,
            "toto"
        ));

        assert_eq!(
            KeyPairEnum::Bip32Ed25519(written_keypair.clone()),
            keypair_read,
        );

        // Change DEWIF passphrase
        let new_dewif_content = unwrap!(change_dewif_passphrase(&dewif_content, "toto", "titi"));

        let keypair_read = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &new_dewif_content,
            "titi"
        ));

        assert_eq!(KeyPairEnum::Bip32Ed25519(written_keypair), keypair_read,);
    }
}
