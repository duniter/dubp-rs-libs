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
//! use dup_crypto::keys::ed25519::bip32::{PrivateDerivationPath, KeyPair, PublicKeyWithChainCode};
//! use dup_crypto::utils::U31;
//!
//! let master_keypair = KeyPair::from_seed(Seed32::random().expect("fail to generate random seed"));
//!
//! let account_index = U31::new(2)?;
//! let address_index = U31::new(3)?;
//!
//! // Derive master external keypair
//! let derivation_path = PrivateDerivationPath::opaque(account_index, true, None)?;
//! let external_keypair = master_keypair.derive(derivation_path);
//!
//! // Get master external public key and chain code
//! let external_public_key = external_keypair.public_key();
//! let external_chain_code = external_keypair.chain_code();
//!
//! // Derive a specific address with public derivation
//! let address = PublicKeyWithChainCode {
//!     public_key: external_public_key,
//!     chain_code: external_chain_code,
//! }
//! .derive(address_index)?
//! .public_key;
//!
//! // Verify that the private derivation give us the same address
//! assert_eq!(
//!     address,
//!     master_keypair
//!         .derive(PrivateDerivationPath::opaque(
//!                 account_index,
//!                 true,
//!                 Some(address_index)
//!         )?).public_key()
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!

use crate::{
    bases::b58::ToBase58,
    hashs::{Hash, Hash64},
    keys::{KeyPair as KeyPairTrait, PublicKey as _},
    mnemonic::Mnemonic,
    seeds::Seed32,
    utils::U31,
};
use arrayvec::ArrayVec;
use std::fmt::Display;
use thiserror::Error;
use zeroize::Zeroize;

const CHAIN_CODE_SIZE: usize = 32;
const EXTENDED_SECRET_KEY_SIZE: usize = 64;

/// BIP32 Chain code
pub type ChainCode = [u8; 32];

#[derive(Clone, Copy, Debug, Error)]
#[error("The account index is not compatible with the account type.")]
/// Invalid account index
pub struct InvalidAccountIndex;

#[derive(Clone, Copy, Debug, Error)]
/// Derivation error
pub enum PublicDerivationError {
    /// Invalid addition
    #[error("Invalid addition")]
    InvalidAddition,
    /// Expected soft derivation
    #[error("Expected soft derivation")]
    ExpectedSoftDerivation,
}

impl From<ed25519_bip32::DerivationError> for PublicDerivationError {
    fn from(e: ed25519_bip32::DerivationError) -> Self {
        match e {
            ed25519_bip32::DerivationError::InvalidAddition => Self::InvalidAddition,
            ed25519_bip32::DerivationError::ExpectedSoftDerivation => Self::ExpectedSoftDerivation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// BIP32 Derivation index
struct DerivationIndex(u32);

impl Into<u32> for DerivationIndex {
    fn into(self) -> u32 {
        self.0
    }
}

impl DerivationIndex {
    /// Derivation 0'
    pub const HARD_ZERO: Self = DerivationIndex(0x80000000);
    /// Derivation 1'
    pub const HARD_ONE: Self = DerivationIndex(0x80000001);

    /// Hardened derivation
    fn hard(index: U31) -> Self {
        Self(index.into_u32() | 0x80000000)
    }
    /// Soft
    fn soft(index: U31) -> Self {
        Self(index.into_u32())
    }
}

#[derive(Clone, Debug)]
/// Private Derivation path
pub struct PrivateDerivationPath(ArrayVec<[DerivationIndex; 3]>);

impl PrivateDerivationPath {
    /// Derive transparent account
    pub fn transparent(account_index: U31) -> Result<Self, InvalidAccountIndex> {
        if account_index.into_u32() % 3 == 0 {
            let mut avec = ArrayVec::new();
            avec.push(DerivationIndex::hard(account_index));
            Ok(Self(avec))
        } else {
            Err(InvalidAccountIndex)
        }
    }
    /// Derive internal keypair for semi-opaque account
    pub fn semi_opaque_internal(
        account_index: U31,
        address_index_opt: Option<U31>,
    ) -> Result<Self, InvalidAccountIndex> {
        if account_index.into_u32() % 3 == 1 {
            let mut avec = ArrayVec::new();
            avec.push(DerivationIndex::hard(account_index));
            avec.push(DerivationIndex::HARD_ONE);
            if let Some(address_index) = address_index_opt {
                avec.push(DerivationIndex::soft(address_index))
            }
            Ok(Self(avec))
        } else {
            Err(InvalidAccountIndex)
        }
    }
    /// Derive external chain keypair for semi-opaque account
    pub fn semi_opaque_external(account_index: U31) -> Result<Self, InvalidAccountIndex> {
        if account_index.into_u32() % 3 == 1 {
            let mut avec = ArrayVec::new();
            avec.push(DerivationIndex::hard(account_index));
            avec.push(DerivationIndex::HARD_ZERO);
            Ok(Self(avec))
        } else {
            Err(InvalidAccountIndex)
        }
    }
    /// Derive opaque account
    pub fn opaque(
        account_index: U31,
        external: bool,
        address_index_opt: Option<U31>,
    ) -> Result<Self, InvalidAccountIndex> {
        if account_index.into_u32() % 3 == 2 {
            let mut avec = ArrayVec::new();
            avec.push(DerivationIndex::hard(account_index));
            if external {
                avec.push(DerivationIndex::HARD_ZERO);
            } else {
                avec.push(DerivationIndex::HARD_ONE);
            }
            if let Some(address_index) = address_index_opt {
                avec.push(DerivationIndex::soft(address_index))
            }
            Ok(Self(avec))
        } else {
            Err(InvalidAccountIndex)
        }
    }
    fn into_iter(self) -> impl Iterator<Item = DerivationIndex> {
        self.0.into_iter()
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
    pub fn derive(&self, derivation_index: U31) -> Result<Self, PublicDerivationError> {
        let xpub =
            ed25519_bip32::XPub::from_pk_and_chaincode(&self.public_key.datas, &self.chain_code);
        let xpub_derived = xpub.derive(
            ed25519_bip32::DerivationScheme::V2,
            derivation_index.into_u32(),
        )?;
        Ok(Self {
            public_key: super::PublicKey::from_32_bytes_array(xpub_derived.public_key()),
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
    pub fn derive(&self, derivation_path: PrivateDerivationPath) -> Self {
        let mut kp = self.to_owned();
        for derivation_index in derivation_path.into_iter() {
            kp = kp.derive_inner(derivation_index);
        }
        kp
    }
    /// Create key-pair from a mnemonic
    pub fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        Self::from_seed(crate::mnemonic::mnemonic_to_seed(&mnemonic))
    }
    fn derive_inner(&self, derivation_index: DerivationIndex) -> Self {
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
    type Seed = Seed32;
    type Signator = Signator;

    fn generate_signator(&self) -> Self::Signator {
        Signator {
            extended_secret_key: self.extended_secret_key,
        }
    }

    // Generate an HDWallet extended key pair from 32 bytes seed
    fn from_seed(seed: Seed32) -> Self {
        let digest = Hash64::sha512(seed.as_ref());
        let mut extended_secret_key = [0u8; EXTENDED_SECRET_KEY_SIZE];
        extended_secret_key.copy_from_slice(digest.as_ref());
        normalize_bytes_ed25519_force3rd(&mut extended_secret_key);

        Self {
            chain_code: gen_root_chain_code(&seed),
            extended_secret_key,
        }
    }

    fn public_key(&self) -> super::PublicKey {
        super::PublicKey::from_32_bytes_array(cryptoxide::ed25519::to_public(
            &self.extended_secret_key,
        ))
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
    type PublicKey = super::PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        super::PublicKey::from_32_bytes_array(cryptoxide::ed25519::to_public(
            &self.extended_secret_key,
        ))
    }

    fn sign(&self, message: &[u8]) -> <Self::PublicKey as super::super::PublicKey>::Signature {
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
    Hash::compute_multipart(&[&[0x01], seed.as_ref()]).0
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
        let u31_zero = unwrap!(U31::new(0));
        let index: u32 = DerivationIndex::hard(u31_zero).into();
        assert_eq!(index, 0x80_00_00_00);

        let u31_max = unwrap!(U31::new(0x7F_FF_FF_FF));
        let index: u32 = DerivationIndex::hard(u31_max).into();
        assert_eq!(index, u32::MAX);
    }

    #[test]
    fn test_public_key_derivation() -> Result<(), InvalidAccountIndex> {
        let mnemonic = unwrap!(crate::mnemonic::Mnemonic::from_phrase(
            "acquire flat utility climb filter device liberty beyond matrix satisfy metal essence",
            crate::mnemonic::Language::English
        ));

        println!("mnemonic={:?}", mnemonic.phrase());
        let seed = crate::mnemonic::mnemonic_to_seed(&mnemonic);
        println!("seed={:?}", hex::encode(seed.as_ref()));
        let master_kp = KeyPair::from_seed(seed);

        let account_index = unwrap!(U31::new(2));
        let address_index = unwrap!(U31::new(3));

        let external_chain_kp =
            master_kp.derive(PrivateDerivationPath::opaque(account_index, true, None)?);
        let external_chain_public_key = external_chain_kp.public_key();
        let external_chain_code = external_chain_kp.chain_code();
        println!(
            "external_chain_public_key={:?}",
            external_chain_public_key.to_base58()
        );
        println!(
            "external_chain_code={:?}",
            bs58::encode(external_chain_code).into_string()
        );

        println!(
            "address(m/2'/0'/3)= {}",
            master_kp
                .derive(PrivateDerivationPath::opaque(
                    account_index,
                    true,
                    Some(address_index)
                )?)
                .public_key()
        );

        assert_eq!(
            unwrap!(PublicKeyWithChainCode {
                public_key: external_chain_public_key,
                chain_code: external_chain_code,
            }
            .derive(address_index))
            .public_key,
            master_kp
                .derive(PrivateDerivationPath::opaque(
                    account_index,
                    true,
                    Some(address_index)
                )?)
                .public_key()
        );

        Ok(())
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

    #[test]
    fn test_derivation_index_consts() -> Result<(), crate::utils::U31Error> {
        assert_eq!(
            DerivationIndex::HARD_ZERO,
            DerivationIndex::hard(U31::new(0)?)
        );
        assert_eq!(
            DerivationIndex::HARD_ONE,
            DerivationIndex::hard(U31::new(1)?)
        );
        Ok(())
    }
}
