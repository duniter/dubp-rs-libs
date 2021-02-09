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
//! ## Write ed25519 key-pair in DEWIF file
//!
//! ```
//! use dup_crypto::dewif::{Currency, G1_TEST_CURRENCY, write_dewif_v1_content};
//! use dup_crypto::keys::ed25519::{KeyPairFromSaltedPasswordGenerator, SaltedPassword};
//! use std::num::NonZeroU32;
//!
//! // Get user credentials (from cli prompt or gui)
//! let credentials = SaltedPassword::new("user salt".to_owned(), "user password".to_owned());
//!
//! // Generate ed25519 keypair
//! let keypair = KeyPairFromSaltedPasswordGenerator::with_default_parameters().generate(credentials);
//!
//! // Get user passphrase for DEWIF encryption
//! let encryption_passphrase = "toto titi tata";
//!
//! // Serialize keypair in DEWIF format
//! let dewif_content = write_dewif_v1_content(Currency::from(G1_TEST_CURRENCY), &keypair, encryption_passphrase);
//!
//! assert_eq!(
//!     "AAAAARAAAAGfFDAs+jVZYkfhBlHZZ2fEQIvBqnG16g5+02cY18wSOjW0cUg2JV3SUTJYN2CrbQeRDwGazWnzSFBphchMmiL0",
//!     dewif_content
//! )
//! ```
//!
//! ## Read DEWIF file
//!
//! ```
//! use dup_crypto::dewif::{Currency, ExpectedCurrency, read_dewif_file_content};
//! use dup_crypto::keys::{KeyPair, Signator};
//! use std::num::NonZeroU32;
//! use std::str::FromStr;
//!
//! // Get DEWIF file content (Usually from disk)
//! let dewif_file_content = "AAAAARAAAAGfFDAs+jVZYkfhBlHZZ2fEQIvBqnG16g5+02cY18wSOjW0cUg2JV3SUTJYN2CrbQeRDwGazWnzSFBphchMmiL0";
//!
//! // Get user passphrase for DEWIF decryption (from cli prompt or gui)
//! let encryption_passphrase = "toto titi tata";
//!
//! // Expected currency
//! let expected_currency = ExpectedCurrency::Specific(Currency::from_str("g1-test").expect("unknown currency"));
//!
//! // Read DEWIF file content
//! // If the file content is correct, we get a key-pair iterator.
//! let mut key_pair_iter = read_dewif_file_content(expected_currency, dewif_file_content, encryption_passphrase)?;
//!
//! // Get first key-pair
//! let key_pair = key_pair_iter
//!     .next()
//!     .expect("DEWIF file must contain at least one keypair");
//!
//! assert_eq!(
//!     "2cC9FrvRiN3uHHcd8S7wuureDS8CAmD5y4afEgSCLHtU",
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
//!     "nCWl7jtCa/nCMKKnk2NJN7daVxd/ER+e1wsFbofdh/pUvDuHxFaa7S5eUMGiqPTJ4uJQOvrmF/BOfOsYIoI2Bg==",
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
#[cfg(feature = "bip32-ed25519")]
pub use write::write_dewif_v4_content;
pub use write::{write_dewif_v1_content, write_dewif_v2_content, write_dewif_v3_content};

use crate::hashs::Hash;
use crate::scrypt::{params::ScryptParams, scrypt};
use crate::seeds::Seed32;

const HEADERS_LEN: usize = 8;

// v1
static VERSION_V1: &[u8] = &[0, 0, 0, 1];
const V1_ENCRYPTED_BYTES_LEN: usize = 64;
const V1_DATA_LEN: usize = V1_ENCRYPTED_BYTES_LEN;
const V1_BYTES_LEN: usize = HEADERS_LEN + V1_DATA_LEN;
const V1_UNENCRYPTED_BYTES_LEN: usize = V1_BYTES_LEN - V1_ENCRYPTED_BYTES_LEN;
const V1_AES_BLOCKS_COUNT: usize = 4;
const V1_LOG_N: u8 = 12;

// v2
static VERSION_V2: &[u8] = &[0, 0, 0, 2];
const V2_ENCRYPTED_BYTES_LEN: usize = 128;
const V2_DATA_LEN: usize = V2_ENCRYPTED_BYTES_LEN;
const V2_BYTES_LEN: usize = HEADERS_LEN + V2_DATA_LEN;
const V2_UNENCRYPTED_BYTES_LEN: usize = V2_BYTES_LEN - V2_ENCRYPTED_BYTES_LEN;
const V2_LOG_N: u8 = 12;

// v3
static VERSION_V3: &[u8] = &[0, 0, 0, 3];
const V3_ENCRYPTED_BYTES_LEN: usize = 64;
const V3_DATA_LEN: usize = V3_ENCRYPTED_BYTES_LEN + 1;
const V3_BYTES_LEN: usize = HEADERS_LEN + V3_DATA_LEN;
const V3_UNENCRYPTED_BYTES_LEN: usize = V3_BYTES_LEN - V3_ENCRYPTED_BYTES_LEN;
const V3_AES_BLOCKS_COUNT: usize = 4;

// v4
#[cfg(feature = "bip32-ed25519")]
static VERSION_V4: &[u8] = &[0, 0, 0, 4];

/// DEWIF meta data
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DewifMeta {
    currency: Currency,
    log_n: u8,
    version: u32,
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

        let dewif_content = write_dewif_v1_content(currency, &written_keypair, "toto");

        let mut keypairs_iter = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content,
            "toto"
        ));
        let keypair_read = unwrap!(keypairs_iter.next());

        assert_eq!(KeyPairEnum::Ed25519(written_keypair), keypair_read,)
    }

    #[test]
    fn dewif_v1_corrupted() -> Result<(), ()> {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let mut dewif_content = write_dewif_v1_content(currency, &written_keypair, "toto");

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
    fn dewif_v2() {
        let written_keypair1 = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let written_keypair2 = KeyPairFromSeed32Generator::generate(Seed32::new([1u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content =
            write_dewif_v2_content(currency, &written_keypair1, &written_keypair2, "toto");

        let mut keypairs_iter = unwrap!(read_dewif_file_content(
            ExpectedCurrency::Specific(currency),
            &dewif_content,
            "toto"
        ));
        let keypair1_read = unwrap!(keypairs_iter.next());
        let keypair2_read = unwrap!(keypairs_iter.next());

        assert_eq!(KeyPairEnum::Ed25519(written_keypair1), keypair1_read,);
        assert_eq!(KeyPairEnum::Ed25519(written_keypair2), keypair2_read,);
    }

    #[test]
    fn dewif_v2_corrupted() -> Result<(), ()> {
        let written_keypair1 = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let written_keypair2 = KeyPairFromSeed32Generator::generate(Seed32::new([1u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let mut dewif_content =
            write_dewif_v2_content(currency, &written_keypair1, &written_keypair2, "toto");

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
}
