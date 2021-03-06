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

//! Provide wrappers around public keys, private keys and signatures.
//!
//! - Keys can be converted to/from Base58 string format.
//! - Signatures can be converted to/from Base64 string format.
//!
//! # Generate and use ed25519 key-pair
//!
//! ```ignore
//! use dup_crypto::keys::{KeyPair, PublicKey, Signator, Signature};
//! use dup_crypto::keys::ed25519::{KeyPairFromSaltedPasswordGenerator, SaltedPassword};
//!
//! let generator = KeyPairFromSaltedPasswordGenerator::generate;
//!
//! let keypair = generator.generate(SaltedPassword::new(
//!     "salt".to_owned(),
//!     "password".to_owned(),
//! ));
//!
//! let signator = keypair.generate_signator();
//!
//! let message = "Hello, world!";
//!
//! let signature = signator.sign(&message.as_bytes());
//!
//! assert!(keypair.public_key().verify(&message.as_bytes(), &signature).is_ok());
//! ```
//!
//! # Format
//!
//! - Base58 use the following alphabet :
//! `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
//! - Base64 use the following alphabet :
//! `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
//! with `=` as padding character.

pub mod bin_signable;
pub mod ed25519;
pub mod text_signable;
#[cfg(feature = "x25519")]
pub(crate) mod x25519;

pub use crate::seeds::Seed32;

use crate::bases::b58::ToBase58;
use crate::bases::BaseConversionError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

/// Cryptographic keys algorithms list
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum KeysAlgo {
    /// Ed25519 algorithm
    Ed25519 = 0,
    /// BIP32-Ed25519 algorithm
    Bip32Ed25519 = 1,
}

#[derive(Clone, Copy, Debug, Error)]
#[error("unknown algorithm")]
/// Unknown algorithm
pub(crate) struct UnknownAlgo;

#[allow(dead_code)]
impl KeysAlgo {
    pub(crate) fn from_u8(u8_: u8) -> Result<KeysAlgo, UnknownAlgo> {
        match u8_ {
            0 => Ok(KeysAlgo::Ed25519),
            1 => Ok(KeysAlgo::Bip32Ed25519),
            _ => Err(UnknownAlgo),
        }
    }
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            KeysAlgo::Ed25519 => 0,
            KeysAlgo::Bip32Ed25519 => 1,
        }
    }
}

/// Get the cryptographic algorithm.
pub trait GetKeysAlgo: Clone + Debug + PartialEq + Eq {
    /// Get the cryptographic algorithm.
    fn algo(&self) -> KeysAlgo;
}

/// Errors enumeration for signature verification.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum SigError {
    /// Signature and pubkey are not the same algo
    #[error("Signature and pubkey are not the same algo.")]
    NotSameAlgo,
    /// Invalid signature
    #[error("Invalid signature.")]
    InvalidSig,
    /// Absence of signature
    #[error("Absence of signature.")]
    NotSig,
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerdeError(String),
}

/// SignError
#[derive(Debug, Eq, Error, PartialEq)]
pub enum SignError {
    /// Corrupted key pair
    #[error("Corrupted key pair.")]
    CorruptedKeyPair,
    /// WrongAlgo
    #[error("Wrong algo.")]
    WrongAlgo,
    /// WrongPrivkey
    #[error("Wrong private key.")]
    WrongPrivkey,
    /// AlreadySign
    #[error("Already signed.")]
    AlreadySign,
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerdeError(String),
}

/// Define the operations that can be performed on a cryptographic signature.
///
/// A signature can be converted from/to Base64 format.
/// When converted back and forth the value should be the same.
///
/// A signature can be made with a [`PrivateKey`]
/// and a message, and verified with the associated [`PublicKey`].
///
/// [`PrivateKey`]: trait.PrivateKey.html
/// [`PublicKey`]: trait.PublicKey.html
pub trait Signature: Clone + Display + Debug + PartialEq + Eq + Hash {
    /// Create a `Signature` from a Base64 string.
    ///
    /// The Base64 string should contains only valid Base64 characters
    /// and have a correct length (64 bytes when converted). If it's not the case,
    /// a [`BaseConvertionError`] is returned with the corresponding variant.
    ///
    /// [`BaseConvertionError`]: enum.BaseConvertionError.html
    fn from_base64(base64_string: &str) -> Result<Self, BaseConversionError>;

    /// Convert Signature into butes vector
    fn to_bytes_vector(&self) -> Vec<u8>;

    /// Encode the signature into Base64 string format.
    fn to_base64(&self) -> String;
}

/// Store a cryptographic signature.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Sig {
    /// Store a ed25519 Signature
    Ed25519(ed25519::Signature),
    /// Store a Schnorr Signature
    Schnorr(),
}

impl Sig {
    /// Get Sig size in bytes
    pub fn size_in_bytes(&self) -> usize {
        match *self {
            Sig::Ed25519(_) => ed25519::SIG_SIZE_IN_BYTES + 2,
            Sig::Schnorr() => panic!("Schnorr algo not yet supported !"),
        }
    }
}

impl Display for Sig {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_base64())
    }
}

impl GetKeysAlgo for Sig {
    fn algo(&self) -> KeysAlgo {
        match *self {
            Sig::Ed25519(_) => KeysAlgo::Ed25519,
            Sig::Schnorr() => panic!("Schnorr algo not yet supported !"),
        }
    }
}

impl Signature for Sig {
    #[cfg(not(tarpaulin_include))]
    fn from_base64(_base64_string: &str) -> Result<Self, BaseConversionError> {
        unimplemented!()
    }
    fn to_bytes_vector(&self) -> Vec<u8> {
        match *self {
            Sig::Ed25519(ed25519_sig) => ed25519_sig.to_bytes_vector(),
            Sig::Schnorr() => panic!("Schnorr algo not yet supported !"),
        }
    }
    fn to_base64(&self) -> String {
        match *self {
            Sig::Ed25519(ed25519_sig) => ed25519_sig.to_base64(),
            Sig::Schnorr() => panic!("Schnorr algo not yet supported !"),
        }
    }
}

/// Define the operations that can be performed on a cryptographic public key.
///
/// A `PublicKey` can be converted from/to Base64 format.
/// When converted back and forth the value should be the same.
///
/// A `PublicKey` is used to verify the signature of a message
/// with the associated [`PrivateKey`].
///
/// [`PrivateKey`]: trait.PrivateKey.html
pub trait PublicKey: Clone + Display + Debug + PartialEq + Eq + Hash + ToBase58 {
    /// Signature type of associated cryptosystem.
    type Signature: Signature;

    /// Create a PublicKey from a Base58 string.
    ///
    /// The Base58 string should contains only valid Base58 characters
    /// and have a correct length. If it's not the case,
    /// a [`BaseConvertionError`] is returned with the corresponding variant.
    ///
    /// [`BaseConvertionError`]: enum.BaseConvertionError.html
    fn from_base58(base58_string: &str) -> Result<Self, BaseConversionError>;

    /// Convert into bytes vector
    fn to_bytes_vector(&self) -> Vec<u8>;

    /// Verify a signature with this public key.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), SigError>;
}

/// Store a cryptographic public key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum PubKeyEnum {
    /// Store a ed25519 public key.
    Ed25519(ed25519::PublicKey),
}

#[derive(Clone, Copy, Debug, Eq, Error, Hash, PartialEq)]
/// Error when parsing pubkey bytes
pub enum PubKeyFromBytesError {
    /// Invalid bytes length
    #[error("Invalid bytes len: expected {expected}, found {found}")]
    InvalidBytesLen {
        /// Expected length
        expected: usize,
        /// Found length
        found: usize,
    },
    /// Invalid bytes content
    #[error("Invalid bytes content")]
    InvalidBytesContent,
}

impl PubKeyEnum {
    /// Create pubkey from bytes
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PubKeyFromBytesError> {
        Ok(PubKeyEnum::Ed25519(ed25519::PublicKey::try_from(bytes)?))
    }
    /// Compute PubKey size in bytes
    pub fn size_in_bytes(&self) -> usize {
        match *self {
            PubKeyEnum::Ed25519(_) => ed25519::PUBKEY_SIZE_IN_BYTES + 3,
        }
    }
}

impl Default for PubKeyEnum {
    fn default() -> Self {
        PubKeyEnum::Ed25519(ed25519::PublicKey::default())
    }
}

impl GetKeysAlgo for PubKeyEnum {
    fn algo(&self) -> KeysAlgo {
        match *self {
            PubKeyEnum::Ed25519(_) => KeysAlgo::Ed25519,
        }
    }
}

impl ToBase58 for PubKeyEnum {
    fn to_base58(&self) -> String {
        match *self {
            PubKeyEnum::Ed25519(ed25519_pub) => ed25519_pub.to_base58(),
        }
    }
}

impl Display for PubKeyEnum {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_base58())
    }
}

impl FromStr for PubKeyEnum {
    type Err = BaseConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ed25519::PublicKey::from_base58(s).map(PubKeyEnum::Ed25519)
    }
}

impl PublicKey for PubKeyEnum {
    type Signature = Sig;

    #[cfg(not(tarpaulin_include))]
    fn from_base58(_base58_string: &str) -> Result<Self, BaseConversionError> {
        unimplemented!()
    }
    fn to_bytes_vector(&self) -> Vec<u8> {
        match *self {
            PubKeyEnum::Ed25519(ed25519_pubkey) => ed25519_pubkey.to_bytes_vector(),
        }
    }
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), SigError> {
        match *self {
            PubKeyEnum::Ed25519(ed25519_pubkey) => {
                if let Sig::Ed25519(ed25519_sig) = signature {
                    ed25519_pubkey.verify(message, ed25519_sig)
                } else {
                    Err(SigError::NotSameAlgo)
                }
            }
        }
    }
}

pub(crate) mod inner {
    #[doc(hidden)]
    pub trait KeyPairInner {
        fn scalar_bytes_without_normalization(&self) -> [u8; 32];
    }
}

/// Define the operations that can be performed on a cryptographic key pair.
pub trait KeyPair: Clone + Display + Debug + inner::KeyPairInner + PartialEq + Eq {
    /// Seed
    type Seed: AsRef<[u8]>;
    /// Signator type of associated cryptosystem.
    type Signator: Signator;

    /// Generate signator.
    fn generate_signator(&self) -> Self::Signator;

    /// Generate keypair from seed
    fn from_seed(seed: Self::Seed) -> Self;

    /// Get `PublicKey`
    fn public_key(&self) -> <Self::Signator as Signator>::PublicKey;

    /// Verify a signature with public key.
    fn verify(
        &self,
        message: &[u8],
        signature: &<<Self::Signator as Signator>::PublicKey as PublicKey>::Signature,
    ) -> Result<(), SigError>;

    /// Upcast to KeyPairEnum
    fn upcast(self) -> KeyPairEnum;
}

/// Define the operations that can be performed on a cryptographic signator.
pub trait Signator: Debug {
    /// PublicKey type of associated cryptosystem.
    type PublicKey: PublicKey;

    /// Get `PublicKey`
    fn public_key(&self) -> Self::PublicKey;

    /// Sign a message with private key encasuled in signator.
    fn sign(&self, message: &[u8]) -> <Self::PublicKey as PublicKey>::Signature;
}

/// Store a cryptographic key pair.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyPairEnum {
    /// Store a ed25519 key pair.
    Ed25519(ed25519::Ed25519KeyPair),
    #[cfg(feature = "bip32-ed25519")]
    /// Store a BIP32-ed25519 key pair.
    Bip32Ed25519(ed25519::bip32::KeyPair),
}

impl GetKeysAlgo for KeyPairEnum {
    fn algo(&self) -> KeysAlgo {
        match *self {
            KeyPairEnum::Ed25519(_) => KeysAlgo::Ed25519,
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(_) => KeysAlgo::Bip32Ed25519,
        }
    }
}

impl Display for KeyPairEnum {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            KeyPairEnum::Ed25519(ref ed25519_keypair) => {
                write!(f, "{}", ed25519_keypair)
            }
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(ref keypair) => {
                write!(f, "{}", keypair)
            }
        }
    }
}

impl inner::KeyPairInner for KeyPairEnum {
    fn scalar_bytes_without_normalization(&self) -> [u8; 32] {
        match self {
            KeyPairEnum::Ed25519(ref ed25519_keypair) => {
                ed25519_keypair.scalar_bytes_without_normalization()
            }
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(ref keypair) => keypair.scalar_bytes_without_normalization(),
        }
    }
}

impl KeyPair for KeyPairEnum {
    type Seed = Seed32;
    type Signator = SignatorEnum;

    fn generate_signator(&self) -> Self::Signator {
        match self {
            KeyPairEnum::Ed25519(ref ed25519_keypair) => {
                SignatorEnum::Ed25519(ed25519_keypair.generate_signator())
            }
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(ref keypair) => {
                SignatorEnum::Bip32Ed25519(keypair.generate_signator())
            }
        }
    }
    fn from_seed(_: Self::Seed) -> Self {
        unimplemented!()
    }
    fn public_key(&self) -> <Self::Signator as Signator>::PublicKey {
        match self {
            KeyPairEnum::Ed25519(ref ed25519_keypair) => {
                PubKeyEnum::Ed25519(ed25519_keypair.public_key())
            }
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(ref keypair) => PubKeyEnum::Ed25519(keypair.public_key()),
        }
    }
    fn verify(&self, message: &[u8], signature: &Sig) -> Result<(), SigError> {
        match self {
            KeyPairEnum::Ed25519(ref keypair) => {
                if let Sig::Ed25519(sig) = signature {
                    keypair.verify(message, sig)
                } else {
                    Err(SigError::NotSameAlgo)
                }
            }
            #[cfg(feature = "bip32-ed25519")]
            KeyPairEnum::Bip32Ed25519(ref keypair) => {
                if let Sig::Ed25519(sig) = signature {
                    keypair.verify(message, sig)
                } else {
                    Err(SigError::NotSameAlgo)
                }
            }
        }
    }
    #[inline(always)]
    fn upcast(self) -> KeyPairEnum {
        self
    }
}

/// Store a cryptographic signator.
#[derive(Debug)]
pub enum SignatorEnum {
    /// Store a ed25519 signator.
    Ed25519(ed25519::Signator),
    /// Store a Schnorr signator.
    Schnorr(),
    #[cfg(feature = "bip32-ed25519")]
    /// Store a BIP32-Ed25519 signator.
    Bip32Ed25519(ed25519::bip32::Signator),
}

impl Signator for SignatorEnum {
    type PublicKey = PubKeyEnum;

    fn public_key(&self) -> Self::PublicKey {
        match self {
            SignatorEnum::Ed25519(ref ed25519_signator) => {
                PubKeyEnum::Ed25519(ed25519_signator.public_key())
            }
            SignatorEnum::Schnorr() => panic!("Schnorr algo not yet supported !"),
            #[cfg(feature = "bip32-ed25519")]
            SignatorEnum::Bip32Ed25519(ref signator) => PubKeyEnum::Ed25519(signator.public_key()),
        }
    }

    fn sign(&self, message: &[u8]) -> Sig {
        match self {
            SignatorEnum::Ed25519(ref ed25519_signator) => {
                Sig::Ed25519(ed25519_signator.sign(message))
            }
            SignatorEnum::Schnorr() => panic!("Schnorr algo not yet supported !"),
            #[cfg(feature = "bip32-ed25519")]
            SignatorEnum::Bip32Ed25519(ref signator) => Sig::Ed25519(signator.sign(message)),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use unwrap::unwrap;

    pub fn valid_key_pair_1() -> KeyPairEnum {
        KeyPairEnum::Ed25519(ed25519::KeyPairFromSeed32Generator::generate(Seed32::new(
            [
                59u8, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101,
                50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
            ],
        )))
    }

    #[test]
    fn sig() {
        let sig_bytes = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let sig_str_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_owned();
        let sig = Sig::Ed25519(ed25519::Signature(sig_bytes));

        assert_eq!(sig.size_in_bytes(), ed25519::SIG_SIZE_IN_BYTES + 2);
        assert_eq!(sig_str_b64, format!("{}", sig));

        assert_eq!(KeysAlgo::Ed25519, sig.algo());

        assert_eq!(sig_bytes.to_vec(), sig.to_bytes_vector());

        assert_eq!(sig_str_b64, sig.to_base64());
    }

    #[test]
    fn public_key() {
        let ed25519_pubkey_default = ed25519::PublicKey::default();
        let pubkey_default = PubKeyEnum::Ed25519(ed25519_pubkey_default);
        let pubkey = PubKeyEnum::Ed25519(unwrap!(ed25519::PublicKey::try_from(
            ed25519_pubkey_default.as_ref()
        )));

        let pubkey_str_b58 = "11111111111111111111111111111111".to_owned();
        assert_eq!(
            pubkey_default,
            unwrap!(PubKeyEnum::from_str(&pubkey_str_b58))
        );

        assert_eq!(pubkey.size_in_bytes(), ed25519::PUBKEY_SIZE_IN_BYTES + 3);
        assert_eq!("11111111111111111111111111111111", &format!("{}", pubkey));

        assert_eq!(KeysAlgo::Ed25519, pubkey.algo());

        let mut expected_vec = [0u8; 32].to_vec();
        expected_vec.push(32);
        assert_eq!(expected_vec, pubkey.to_bytes_vector());

        assert_eq!("11111111111111111111111111111111", &pubkey.to_base58());

        assert_eq!(
            Err(SigError::InvalidSig),
            pubkey.verify(
                b"message",
                &Sig::Ed25519(ed25519::Signature([
                    0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]))
            )
        )
    }

    #[test]
    fn seed() {
        let seed_default = Seed32::default();
        let seed_bytes = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let seed = Seed32::new(seed_bytes);

        assert_eq!(seed_default, seed);
        assert_eq!(seed_default, unwrap!(Seed32::from_base58("")));

        assert_eq!("", format!("{}", seed));

        assert_eq!("", seed.to_base58());
    }

    fn false_key_pair_ed25519() -> ed25519::Ed25519KeyPair {
        ed25519::KeyPairFromSeed32Generator::generate(Seed32::new([
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]))
    }

    #[test]
    fn key_pair() {
        let false_key_pair_ed25519 = false_key_pair_ed25519();
        let false_key_pair = KeyPairEnum::Ed25519(false_key_pair_ed25519.clone());

        assert_eq!(KeysAlgo::Ed25519, false_key_pair.algo());
        assert_eq!(
            "(4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS, hidden)".to_owned(),
            format!("{}", false_key_pair)
        );
        assert_eq!(
            PubKeyEnum::Ed25519(false_key_pair_ed25519.public_key()),
            false_key_pair.public_key()
        );
        assert_eq!(
            Err(SigError::InvalidSig),
            false_key_pair.verify(
                b"message",
                &Sig::Ed25519(ed25519::Signature([
                    0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]))
            )
        );
    }

    #[test]
    fn key_pair_verify_wrong_sig_algo() {
        let false_key_pair_ed25519 = false_key_pair_ed25519();
        let false_key_pair = KeyPairEnum::Ed25519(false_key_pair_ed25519);
        assert_eq!(
            Err(SigError::NotSameAlgo),
            false_key_pair.verify(b"message", &Sig::Schnorr()),
        );
    }

    #[test]
    fn pubkey_verify_sig_wrong_algo() {
        let pubkey = PubKeyEnum::default();
        assert_eq!(
            Err(SigError::NotSameAlgo),
            pubkey.verify(b"message", &Sig::Schnorr()),
        );
    }

    #[test]
    #[should_panic(expected = "Schnorr algo not yet supported !")]
    fn signator_schnorr_get_pubkey() {
        let signator = SignatorEnum::Schnorr();
        signator.public_key();
    }

    #[test]
    #[should_panic(expected = "Schnorr algo not yet supported !")]
    fn signator_schnorr_sign() {
        let signator = SignatorEnum::Schnorr();
        signator.sign(b"message");
    }

    #[test]
    fn pubkey_from_bytes() {
        assert_eq!(
            Err(PubKeyFromBytesError::InvalidBytesLen {
                expected: ed25519::PUBKEY_SIZE_IN_BYTES,
                found: 34,
            }),
            PubKeyEnum::from_bytes(&[
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 31, 17
            ]),
        );
    }
}
