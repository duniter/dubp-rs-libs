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

//! Implement [BIP32-Ed25519 specifications](https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view).
//!
//! # Generate an HD wallet
//!
//! ```
//! use dup_crypto::seeds::Seed32;
//! use dup_crypto::keys::KeyPair as _;
//! use dup_crypto::keys::ed25519::bip32::KeyPair;
//!
//! let seed = Seed32::random().expect("fail to generate random seed");
//!
//! let master_key_pair = KeyPair::from_seed(seed);
//!
//! let master_public_key = master_key_pair.public_key();
//! ```
//!
//! `dup_crypto::keys::ed25519::bip32::KeyPair` implement the `dup_crypto::keys::KeyPair` trait, so sign and verify like a classic ed25519 keypair.
//!
//! # Derive private key and public key
//!
//! ```
//! use dup_crypto::seeds::Seed32;
//! use dup_crypto::keys::KeyPair as _;
//! use dup_crypto::keys::ed25519::bip32::{DerivationIndex, KeyPair, PublicKeyWithChainCode};
//!
//! let master_key_pair = KeyPair::from_seed(Seed32::random().expect("fail to generate random seed"));
//! let master_public_key = master_key_pair.public_key();
//!
//! let chain_code = master_key_pair.chain_code();
//! let derivation_index = DerivationIndex::soft(3)?;
//!
//! // Derive key pair
//! let child_key_pair = master_key_pair.derive(derivation_index);
//!
//! // Derive public key
//! let child_public_key = PublicKeyWithChainCode {
//!     public_key: master_public_key,
//!     chain_code
//! }.derive(derivation_index)?.public_key;
//!
//! assert_eq!(child_key_pair.public_key(), child_public_key);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!

use std::fmt::Display;

use crate::bases::b58::ToBase58;
use crate::{
    keys::{KeyPair as KeyPairTrait, PublicKey as _},
    seeds::Seed32,
};
use ring::digest;
use thiserror::Error;
use zeroize::Zeroize;

const CHAIN_CODE_SIZE: usize = 32;
const EXTENDED_SECRET_KEY_SIZE: usize = 64;

/// BIP32 Chain code
pub type ChainCode = [u8; 32];

#[derive(Clone, Copy, Debug, Error)]
#[error("Derivation index must less than 2^31")]
/// Invalid derivation index
/// Derivation index must less than 2^31
pub struct InvalidDerivationIndex;

#[derive(Clone, Copy, Debug, Error)]
/// Derivation error
pub enum DerivationError {
    /// Invalid addition
    #[error("Invalid addition")]
    InvalidAddition,
    /// Expected soft derivation
    #[error("Expected soft derivation")]
    ExpectedSoftDerivation,
}

impl From<ed25519_bip32::DerivationError> for DerivationError {
    fn from(e: ed25519_bip32::DerivationError) -> Self {
        match e {
            ed25519_bip32::DerivationError::InvalidAddition => Self::InvalidAddition,
            ed25519_bip32::DerivationError::ExpectedSoftDerivation => Self::ExpectedSoftDerivation,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// BIP32 Derivation index
pub struct DerivationIndex(u32);

impl Into<u32> for DerivationIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl DerivationIndex {
    /// Hardened derivation
    pub fn hard(index: u32) -> Result<Self, InvalidDerivationIndex> {
        if index < 0x80000000 {
            Ok(Self(index | 0x80000000))
        } else {
            Err(InvalidDerivationIndex)
        }
    }
    /// Soft
    pub fn soft(index: u32) -> Result<Self, InvalidDerivationIndex> {
        if index < 0x80000000 {
            Ok(Self(index))
        } else {
            Err(InvalidDerivationIndex)
        }
    }
}

/// HDWallet extended public key (Ed25519 public key + BIP32 ChainCode)
///
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKeyWithChainCode {
    /// Ed25519 public key
    pub public_key: super::PublicKey,
    /// BIP32 ChainCode
    pub chain_code: ChainCode,
}

impl PublicKeyWithChainCode {
    /// BIP32 Derivation
    ///
    /// May fail in 2 cases :
    ///
    /// * The derivation is of the hardened type
    /// * The public key is not issued from a private key of HD wallet type
    pub fn derive(&self, derivation_index: DerivationIndex) -> Result<Self, DerivationError> {
        let xpub =
            ed25519_bip32::XPub::from_pk_and_chaincode(&self.public_key.datas, &self.chain_code);
        let xpub_derived =
            xpub.derive(ed25519_bip32::DerivationScheme::V2, derivation_index.into())?;
        Ok(Self {
            public_key: super::PublicKey::from_data(xpub_derived.public_key()),
            chain_code: xpub_derived.chain_code(),
        })
    }
}

/// HDWallet extended key pair (Ed25519 extended private key + BIP32 ChainCode)
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    chain_code: [u8; CHAIN_CODE_SIZE],
    extended_secret_key: [u8; EXTENDED_SECRET_KEY_SIZE],
}

impl Display for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, hidden)", self.public_key().to_base58())
    }
}

impl KeyPair {
    /// Get BIP32 chain code
    pub fn chain_code(&self) -> ChainCode {
        self.chain_code
    }
    /// BIP32 derivation
    pub fn derive(&self, derivation_index: DerivationIndex) -> Self {
        let xprv = ed25519_bip32::XPrv::from_extended_and_chaincode(
            &self.extended_secret_key,
            &self.chain_code,
        );
        let xprv_derived =
            xprv.derive(ed25519_bip32::DerivationScheme::V2, derivation_index.into());
        Self {
            chain_code: xprv_derived.chain_code(),
            extended_secret_key: xprv_derived.extended_secret_key(),
        }
    }
}

impl KeyPairTrait for KeyPair {
    type PublicKey = super::PublicKey;
    type Seed = Seed32;
    type Signator = Signator;

    fn generate_signator(&self) -> Self::Signator {
        Signator {
            extended_secret_key: self.extended_secret_key,
        }
    }

    // Generate an HDWallet extended key pair from 32 bytes seed
    fn from_seed(seed: Seed32) -> Self {
        let digest = digest::digest(&digest::SHA512, seed.as_ref());
        let mut extended_secret_key = [0u8; EXTENDED_SECRET_KEY_SIZE];
        extended_secret_key.copy_from_slice(digest.as_ref());
        normalize_bytes_ed25519_force3rd(&mut extended_secret_key);

        Self {
            chain_code: gen_root_chain_code(&seed),
            extended_secret_key,
        }
    }

    fn public_key(&self) -> super::PublicKey {
        super::PublicKey::from_data(cryptoxide::ed25519::to_public(&self.extended_secret_key))
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &super::Signature,
    ) -> Result<(), crate::keys::SigError> {
        self.public_key().verify(message, signature)
    }

    fn upcast(self) -> super::super::KeyPairEnum {
        super::super::KeyPairEnum::Bip32Ed25519(self)
    }
}

/// HDWallet signator
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct Signator {
    extended_secret_key: [u8; EXTENDED_SECRET_KEY_SIZE],
}

impl super::super::Signator for Signator {
    type Signature = super::Signature;
    type PublicKey = super::PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        super::PublicKey::from_data(cryptoxide::ed25519::to_public(&self.extended_secret_key))
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        super::Signature(cryptoxide::ed25519::signature_extended(
            message,
            &self.extended_secret_key,
        ))
    }
}

/// Generate root chain code as specified in the paper BIP32-Ed25519 section V.
///
/// > "Derive c ← H256(0x01||~k), where H256 is SHA-256, and call it the root chain code."
fn gen_root_chain_code(seed: &Seed32) -> ChainCode {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x01]);
    ctx.update(seed.as_ref());
    let digest = ctx.finish();
    let mut chain_code = [0u8; CHAIN_CODE_SIZE];
    chain_code.copy_from_slice(digest.as_ref());

    chain_code
}

/// takes the given raw bytes and perform some modifications to normalize
/// to a valid Ed25519 extended key, but it does also force
/// the 3rd highest bit to be cleared too.
fn normalize_bytes_ed25519_force3rd(bytes: &mut [u8; EXTENDED_SECRET_KEY_SIZE]) {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0001_1111;
    bytes[31] |= 0b0100_0000;
}

#[cfg(test)]
mod tests {
    use crate::keys::{PublicKey, Signator};

    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_derivation_index() {
        assert!(DerivationIndex::soft(0).is_ok());
        assert!(DerivationIndex::soft(u32::MAX).is_err());
        assert!(DerivationIndex::soft(0x80_00_00_00).is_err());
        assert!(DerivationIndex::soft(0x7F_FF_FF_FF).is_ok());

        assert!(DerivationIndex::hard(u32::MAX).is_err());
        assert!(DerivationIndex::hard(0x80_00_00_00).is_err());

        assert!(DerivationIndex::hard(0).is_ok());
        let index: u32 = unwrap!(DerivationIndex::hard(0)).into();
        assert_eq!(index, 0x80_00_00_00);
        assert!(DerivationIndex::hard(0x7F_FF_FF_FF).is_ok());
        let index: u32 = unwrap!(DerivationIndex::hard(0x7F_FF_FF_FF)).into();
        assert_eq!(index, 0xFF_FF_FF_FF);
    }

    #[test]
    fn test_public_key_derivation() {
        let seed = unwrap!(Seed32::from_base58(
            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"
        ));
        let kp = KeyPair::from_seed(seed);
        let public_key = kp.public_key();
        let chain_code = kp.chain_code();

        let derivation_index = unwrap!(DerivationIndex::soft(3));

        let derived_kp = kp.derive(derivation_index);
        let derived_pk = derived_kp.public_key();

        assert_eq!(
            unwrap!(PublicKeyWithChainCode {
                public_key,
                chain_code
            }
            .derive(derivation_index))
            .public_key,
            derived_pk
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let seed = unwrap!(Seed32::from_base58(
            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"
        ));
        let kp = KeyPair::from_seed(seed);
        let public_key = kp.public_key();

        let message = "toto";
        let wrong_message = "titi";
        let sig = kp.generate_signator().sign(message.as_bytes());
        let wrong_sig = kp.generate_signator().sign(wrong_message.as_bytes());

        assert!(public_key.verify(message.as_bytes(), &sig).is_ok());
        assert!(public_key.verify(wrong_message.as_bytes(), &sig).is_err());
        assert!(public_key.verify(message.as_bytes(), &wrong_sig).is_err());
    }
}
