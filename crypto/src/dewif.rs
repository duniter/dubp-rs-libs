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
//!     "AAAAARAAAAEx3yd707xD3F5ttjcISbZzXRrko4pKUmCDIF/emfcVU9MvBqCJQS9R2sWlqbtI1Q37sLQhkj/W7tqY+hxm7mFQ",
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
//! let dewif_file_content = "AAAAARAAAAEx3yd707xD3F5ttjcISbZzXRrko4pKUmCDIF/emfcVU9MvBqCJQS9R2sWlqbtI1Q37sLQhkj/W7tqY+hxm7mFQ";
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
pub use read::{read_dewif_file_content, DewifReadError};
pub use write::{write_dewif_v1_content, write_dewif_v2_content};

use crate::hashs::Hash;
use crate::seeds::Seed32;
use arrayvec::ArrayVec;
use unwrap::unwrap;

const UNENCRYPTED_BYTES_LEN: usize = 8;

// v1
static VERSION_V1: &[u8] = &[0, 0, 0, 1];
const V1_BYTES_LEN: usize = 72;
const V1_ENCRYPTED_BYTES_LEN: usize = 64;
const V1_AES_BLOCKS_COUNT: usize = 4;

// v2
static VERSION_V2: &[u8] = &[0, 0, 0, 2];
const V2_BYTES_LEN: usize = 136;
const V2_ENCRYPTED_BYTES_LEN: usize = 128;

fn gen_aes_seed(passphrase: &str) -> Seed32 {
    let mut salt = ArrayVec::<[u8; 37]>::new();
    unwrap!(salt.try_extend_from_slice(b"dewif"));
    let hash = Hash::compute(passphrase.as_bytes());
    unwrap!(salt.try_extend_from_slice(hash.as_ref()));

    let mut aes_seed_bytes = [0u8; 32];
    scrypt::scrypt(
        passphrase.as_bytes(),
        salt.as_ref(),
        &scrypt::ScryptParams::new(12, 16, 1).expect("dev error: invalid scrypt params"),
        &mut aes_seed_bytes,
    )
    .expect("dev error: invalid seed len");
    Seed32::new(aes_seed_bytes)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::keys::KeyPairEnum;
    use crate::seeds::Seed32;

    #[test]
    fn dewif_v1() {
        let written_keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));
        let currency = Currency::from(G1_TEST_CURRENCY);

        let dewif_content = write_dewif_v1_content(currency, &written_keypair, "toto");

        let mut keypairs_iter =
            read_dewif_file_content(ExpectedCurrency::Specific(currency), &dewif_content, "toto")
                .expect("dewif content must be readed successfully");
        let keypair_read = keypairs_iter.next().expect("Must read one keypair");

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

        let mut keypairs_iter =
            read_dewif_file_content(ExpectedCurrency::Specific(currency), &dewif_content, "toto")
                .expect("dewif content must be readed successfully");
        let keypair1_read = keypairs_iter.next().expect("Must read one keypair");
        let keypair2_read = keypairs_iter.next().expect("Must read one keypair");

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
