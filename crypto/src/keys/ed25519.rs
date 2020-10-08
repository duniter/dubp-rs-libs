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

//! Provide wrappers around ed25519 keys and signatures
//!
//! Key pairs can be generated with [`KeyPairGenerator`].
//!
//! [`KeyPairGenerator`]: struct.KeyPairGenerator.html

use super::PublicKey as PublicKeyMethods;
use super::{PubkeyFromBytesError, SigError};
use crate::bases::b58::{bytes_to_str_base58, ToBase58};
use crate::bases::*;
#[cfg(feature = "rand")]
use crate::rand::UnspecifiedRandError;
#[cfg(feature = "scrypt")]
use crate::scrypt::{params::ScryptParams, scrypt};
use crate::seeds::Seed32;
#[cfg(not(target_arch = "wasm32"))]
use ring::signature::{Ed25519KeyPair as RingKeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{
    de::{Deserializer, Error, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
    Deserialize, Serialize,
};
use std::marker::PhantomData;
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
    hint::unreachable_unchecked,
};
#[cfg(feature = "scrypt")]
use zeroize::Zeroize;

/// Size of a public key in bytes
pub const PUBKEY_SIZE_IN_BYTES: usize = 33;
pub(crate) const PUBKEY_DATAS_SIZE_IN_BYTES: usize = 32;
/// constf a signature in bytes
pub const SIG_SIZE_IN_BYTES: usize = 64;

/// Store a ed25519 signature.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Signature(pub [u8; 64]);

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 64])
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for elem in &self.0[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

#[cfg(not(tarpaulin_include))]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor {
            element: PhantomData<u8>,
        }

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = Signature;

            #[cfg(not(tarpaulin_include))]
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 64))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Signature, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().take(64).enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(Signature(arr))
            }
        }

        let visitor: ArrayVisitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(64, visitor)
    }
}

impl super::Signature for Signature {
    #[inline]
    fn from_base64(base64_data: &str) -> Result<Signature, BaseConversionError> {
        Ok(Signature(b64::str_base64_to64bytes(base64_data)?))
    }

    fn to_bytes_vector(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn to_base64(&self) -> String {
        base64::encode(&self.0[..]) // need to take a slice for required trait `AsRef<[u8]>`
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        use super::Signature;

        write!(f, "{}", self.to_base64())
    }
}

impl Debug for Signature {
    // Signature { 1eubHHb... }
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "Signature {{ {} }}", self)
    }
}

/// Store a Ed25519 public key.
///
/// Can be generated with [`KeyPairGenerator`].
///
/// [`KeyPairGenerator`]: struct.KeyPairGenerator.html
#[derive(Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PublicKey {
    pub(crate) datas: [u8; 32],
    count_leading_zero: u8,
}

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey {
            datas: [0u8; 32],
            count_leading_zero: 32,
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.datas.as_ptr(), PUBKEY_SIZE_IN_BYTES) }
    }
}

impl PublicKey {
    /// Verify if bytes represents a valid point on the Edwards form of Curve25519.
    #[cfg(feature = "pubkey_check")]
    fn check_bytes(bytes: &[u8]) -> bool {
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes)
            .decompress()
            .is_some()
    }
    #[cfg(not(feature = "pubkey_check"))]
    fn check_bytes(_: &[u8]) -> bool {
        true
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = PubkeyFromBytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() > PUBKEY_SIZE_IN_BYTES {
            Err(PubkeyFromBytesError::InvalidBytesLen {
                expected: PUBKEY_SIZE_IN_BYTES,
                found: bytes.len(),
            })
        } else {
            let (count_leading_zero, datas_bytes) = if bytes.len() <= PUBKEY_DATAS_SIZE_IN_BYTES {
                (0, bytes)
            } else {
                (
                    bytes[PUBKEY_DATAS_SIZE_IN_BYTES],
                    &bytes[..PUBKEY_DATAS_SIZE_IN_BYTES],
                )
            };
            // Ensure that given bytes represents a valid point on the Edwards form of Curve25519.
            if Self::check_bytes(datas_bytes) {
                let mut u8_array = [0; PUBKEY_DATAS_SIZE_IN_BYTES];
                u8_array[(PUBKEY_DATAS_SIZE_IN_BYTES - datas_bytes.len())..]
                    .copy_from_slice(datas_bytes);

                Ok(PublicKey {
                    datas: u8_array,
                    count_leading_zero,
                })
            } else {
                Err(PubkeyFromBytesError::InvalidBytesContent)
            }
        }
    }
}

impl ToBase58 for PublicKey {
    fn to_base58(&self) -> String {
        bytes_to_str_base58(self.datas.as_ref(), self.count_leading_zero)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            bytes_to_str_base58(self.datas.as_ref(), self.count_leading_zero)
        )
    }
}

impl Debug for PublicKey {
    // PublicKey { DNann1L... }
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "PublicKey {{ {} }}", self)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(match self.datas.cmp(&other.datas) {
            Ordering::Equal => self.count_leading_zero.cmp(&other.count_leading_zero),
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
        })
    }
}

impl super::PublicKey for PublicKey {
    type Signature = Signature;

    #[inline]
    fn from_base58(base58_data: &str) -> Result<Self, BaseConversionError> {
        let (datas, count_leading_zero) = b58::str_base58_to_32bytes(base58_data)?;
        Ok(PublicKey {
            datas,
            count_leading_zero,
        })
    }

    fn to_bytes_vector(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), SigError> {
        if cryptoxide::ed25519::verify(message, self.datas.as_ref(), &signature.0[..]) {
            Ok(())
        } else {
            Err(SigError::InvalidSig)
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), SigError> {
        Ok(UnparsedPublicKey::new(&ED25519, self.datas.as_ref())
            .verify(message, &signature.0)
            .map_err(|_| SigError::InvalidSig)?)
    }
}

#[cfg(target_arch = "wasm32")]
#[cfg(not(tarpaulin_include))]
fn get_cryptoxide_ed25519_pubkey(pubkey_bytes: [u8; 32]) -> PublicKey {
    PublicKey::try_from(&pubkey_bytes[..]).unwrap_or_else(|_| unsafe { unreachable_unchecked() })
}
#[cfg(not(target_arch = "wasm32"))]
fn get_ring_ed25519_pubkey(ring_key_pair: &RingKeyPair) -> PublicKey {
    let ring_pubkey: <RingKeyPair as KeyPair>::PublicKey = *ring_key_pair.public_key();
    PublicKey::try_from(ring_pubkey.as_ref()).unwrap_or_else(|_| unsafe { unreachable_unchecked() })
}

#[cfg(target_arch = "wasm32")]
#[cfg(not(tarpaulin_include))]
/// Store a ed25519 cryptographic signator
#[allow(missing_copy_implementations)]
pub struct Signator {
    public_key: PublicKey,
    secret_key: [u8; 64],
}
#[cfg(target_arch = "wasm32")]
#[cfg(not(tarpaulin_include))]
impl Debug for Signator {
    // Signature { 1eubHHb... }
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Signator {{ public_key: {}, secret_key: hidden }}",
            self.public_key
        )
    }
}
#[cfg(not(target_arch = "wasm32"))]
/// Store a ed25519 cryptographic signator
#[derive(Debug)]
pub struct Signator(RingKeyPair);

impl super::Signator for Signator {
    type Signature = Signature;
    type PublicKey = PublicKey;

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    fn public_key(&self) -> Self::PublicKey {
        self.public_key
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn public_key(&self) -> Self::PublicKey {
        get_ring_ed25519_pubkey(&self.0)
    }
    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    fn sign(&self, message: &[u8]) -> Self::Signature {
        let sig_bytes = cryptoxide::ed25519::signature(message, &self.secret_key[..]);
        Signature(sig_bytes)
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(tarpaulin_include))]
    fn sign(&self, message: &[u8]) -> Self::Signature {
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(self.0.sign(message).as_ref());
        Signature(sig_bytes)
    }
}

/// Store a ed25519 cryptographic key pair (`PublicKey` + `PrivateKey`)
#[derive(Debug, Clone, Eq)]
pub struct Ed25519KeyPair {
    /// Store a Ed25519 public key.
    pubkey: PublicKey,
    /// Store a seed of 32 bytes.
    seed: Seed32,
}

impl Ed25519KeyPair {
    #[cfg(feature = "rand")]
    /// Generate random keypair
    pub fn generate_random() -> Result<Self, UnspecifiedRandError> {
        Ok(KeyPairFromSeed32Generator::generate(Seed32::random()?))
    }
    pub(crate) fn seed(&self) -> &Seed32 {
        &self.seed
    }
}

impl Display for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "({}, hidden)", self.pubkey.to_base58())
    }
}

impl PartialEq<Ed25519KeyPair> for Ed25519KeyPair {
    fn eq(&self, other: &Ed25519KeyPair) -> bool {
        self.pubkey.eq(&other.pubkey) && self.seed.eq(&other.seed)
    }
}

impl super::KeyPair for Ed25519KeyPair {
    type Signator = Signator;

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    fn generate_signator(&self) -> Self::Signator {
        let (secret_key, public_key) = cryptoxide::ed25519::keypair(self.seed.as_ref());
        Signator {
            public_key: get_cryptoxide_ed25519_pubkey(public_key),
            secret_key,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn generate_signator(&self) -> Self::Signator {
        Signator(
            RingKeyPair::from_seed_unchecked(self.seed.as_ref())
                .unwrap_or_else(|_| unsafe { unreachable_unchecked() }),
        )
    }

    fn public_key(&self) -> PublicKey {
        self.pubkey
    }

    fn seed(&self) -> &Seed32 {
        &self.seed
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &<Self::Signator as super::Signator>::Signature,
    ) -> Result<(), SigError> {
        self.public_key().verify(message, signature)
    }
}

/// Keypair generator with seed
#[derive(Debug, Copy, Clone)]
pub struct KeyPairFromSeed32Generator {}

impl KeyPairFromSeed32Generator {
    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    /// Create a keypair based on a given seed.
    ///
    /// The [`PublicKey`](struct.PublicKey.html) will be able to verify messaged signed with
    /// the [`PrivateKey`](struct.PrivateKey.html).
    pub fn generate(seed: Seed32) -> Ed25519KeyPair {
        Ed25519KeyPair {
            pubkey: get_cryptoxide_ed25519_pubkey(cryptoxide::ed25519::keypair(seed.as_ref()).1),
            seed,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Create a keypair based on a given seed.
    ///
    /// The [`PublicKey`](struct.PublicKey.html) will be able to verify messaged signed with
    /// the [`PrivateKey`](struct.PrivateKey.html).
    pub fn generate(seed: Seed32) -> Ed25519KeyPair {
        let ring_key_pair = RingKeyPair::from_seed_unchecked(seed.as_ref())
            .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
        Ed25519KeyPair {
            pubkey: get_ring_ed25519_pubkey(&ring_key_pair),
            seed,
        }
    }
}

#[cfg(feature = "scrypt")]
#[derive(Zeroize)]
#[zeroize(drop)]
/// Salted password
pub struct SaltedPassword {
    salt: String,
    password: String,
}

#[cfg(feature = "scrypt")]
impl SaltedPassword {
    /// Create new salted password
    pub fn new(salt: String, password: String) -> SaltedPassword {
        SaltedPassword { salt, password }
    }
}
#[cfg(feature = "scrypt")]
/// Keypair generator with given parameters for `scrypt` keypair function.
#[derive(Copy, Clone)]
pub struct KeyPairFromSaltedPasswordGenerator {
    scrypt_params: ScryptParams,
}

#[cfg(feature = "scrypt")]
impl KeyPairFromSaltedPasswordGenerator {
    /// Create a `KeyPairGenerator` with default arguments `(log_n: 12, r: 16, p: 1)`
    pub fn with_default_parameters() -> KeyPairFromSaltedPasswordGenerator {
        KeyPairFromSaltedPasswordGenerator {
            scrypt_params: ScryptParams::default(),
        }
    }

    /// Create a `KeyPairFromSaltedPasswordGenerator` with given arguments.
    ///
    /// # Arguments
    ///
    /// - log_n - The log2 of the Scrypt parameter N
    /// - r - The Scrypt parameter r
    /// - p - The Scrypt parameter p
    pub fn with_parameters(log_n: u8, r: u32, p: u32) -> KeyPairFromSaltedPasswordGenerator {
        KeyPairFromSaltedPasswordGenerator {
            scrypt_params: ScryptParams::new(log_n, r, p),
        }
    }

    /// Create a seed based on a given password and salt.
    pub fn generate_seed(&self, password: &[u8], salt: &[u8]) -> Seed32 {
        let mut seed = [0u8; 32];

        scrypt(password, salt, &self.scrypt_params, &mut seed);

        Seed32::new(seed)
    }

    /// Create a keypair based on a given password and salt.
    ///
    /// The [`PublicKey`](struct.PublicKey.html) will be able to verify messaged signed with
    /// the [`PrivateKey`](struct.PrivateKey.html).
    pub fn generate(&self, salted_password: SaltedPassword) -> Ed25519KeyPair {
        // Generate seed from tuple (password + salt)
        let seed = self.generate_seed(
            salted_password.password.as_bytes(),
            salted_password.salt.as_bytes(),
        );
        // Generate keypair from seed
        KeyPairFromSeed32Generator::generate(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyPair, Sig, Signator, Signature};
    use crate::seeds::Seed32;
    use std::{collections::hash_map::DefaultHasher, hash::Hasher};
    use unwrap::unwrap;

    #[test]
    fn base58_seed() {
        let seed58 = "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV";

        // Test base58 encoding/decoding (loop for every bytes)
        let seed = unwrap!(Seed32::from_base58(seed58));
        assert_eq!(seed.to_base58(), seed58);

        // Test seed display and debug
        assert_eq!(
            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV".to_owned(),
            format!("{}", seed)
        );
        assert_eq!(
            "Seed32 { DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV }".to_owned(),
            format!("{:?}", seed)
        );

        // Test seed equality
        let same_seed = seed.clone();
        let other_seed = Seed32::default();
        assert!(seed.eq(&same_seed));
        assert!(!seed.eq(&other_seed));

        // Test seed parsing
        assert_eq!(
            Seed32::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQd<<").unwrap_err(),
            BaseConversionError::InvalidCharacter {
                character: '<',
                offset: 42
            }
        );
    }

    #[test]
    fn test_pubkey_111_from_base58() -> Result<(), bincode::Error> {
        let public58 = "11111111111111111111111111111111111111111111";
        let public_key = unwrap!(super::PublicKey::from_base58(public58));
        assert_eq!(
            &[
                0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 44
            ][..],
            public_key.as_ref(),
        );
        assert_eq!(
            bincode::serialize(&public_key)?,
            public_key.to_bytes_vector(),
        );
        Ok(())
    }

    #[test]
    fn test_pubkey_with_leading_1() -> Result<(), bincode::Error> {
        let public58 = "13fn6X3XWVgshHTgS8beZMo9XiyScx6MB6yPsBB5ZBia";
        let public_key = unwrap!(super::PublicKey::from_base58(public58));
        assert_eq!(
            bincode::serialize(&public_key)?,
            public_key.to_bytes_vector(),
        );
        Ok(())
    }

    #[test]
    fn test_other_pubkey_with_leading_1() -> Result<(), bincode::Error> {
        let public58 = "1V27SH9TiVEDs8TWFPydpRKxhvZari7wjGwQnPxMnkr";
        let public_key = unwrap!(super::PublicKey::from_base58(public58));
        assert_eq!(
            bincode::serialize(&public_key)?,
            public_key.to_bytes_vector(),
        );
        Ok(())
    }

    #[test]
    fn base58_public_key() -> Result<(), bincode::Error> {
        let public58 = "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV";
        let public_key = unwrap!(super::PublicKey::from_base58(public58));

        // Test base58 encoding/decoding (loop for every bytes)
        assert_eq!(public_key.to_base58(), public58);
        let public_raw = unwrap!(b58::str_base58_to_32bytes(public58));
        assert_eq!(
            public_raw.0.to_vec(),
            &public_key.to_bytes_vector()[..PUBKEY_DATAS_SIZE_IN_BYTES]
        );
        for (key, raw) in public_key.datas.as_ref().iter().zip(public_raw.0.iter()) {
            assert_eq!(key, raw);
        }

        // Test binary encoding/decoding
        assert_eq!(
            bincode::serialize(&public_key)?,
            public_key.to_bytes_vector(),
        );

        // Test pubkey debug
        assert_eq!(
            "PublicKey { DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV }".to_owned(),
            format!("{:?}", public_key)
        );

        // Test pubkey with 43 characters
        let pubkey43 = unwrap!(super::PublicKey::from_base58(
            "2nV7Dv4nhTJ9dZUvRJpL34vFP9b2BkDjKWv9iBW2JaR"
        ));
        println!("pubkey43={:?}", pubkey43.as_ref());
        assert_eq!(
            format!("{:?}", pubkey43),
            "PublicKey { 2nV7Dv4nhTJ9dZUvRJpL34vFP9b2BkDjKWv9iBW2JaR }".to_owned(),
        );
        assert_eq!(
            super::PublicKey::from_base58("DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQd<<")
                .unwrap_err(),
            BaseConversionError::InvalidCharacter {
                character: '<',
                offset: 42
            }
        );
        Ok(())
    }

    #[test]
    fn base64_signature() {
        let signature64 = "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FG\
                           MMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==";
        let signature = unwrap!(super::Signature::from_base64(signature64));

        // Test signature base64 encoding/decoding (loop for every bytes)
        assert_eq!(signature.to_base64(), signature64);
        let signature_raw = unwrap!(base64::decode(signature64));
        for (sig, raw) in signature.0.iter().zip(signature_raw.iter()) {
            assert_eq!(sig, raw);
        }

        // Test signature display and debug
        assert_eq!(
            "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg==".to_owned(),
            format!("{}", signature)
        );
        assert_eq!(
            "Signature { 1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FGMMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg== }".to_owned(),
            format!("{:?}", signature)
        );

        // Test signature hash
        let mut hasher = DefaultHasher::new();
        signature.hash(&mut hasher);
        let hash1 = hasher.finish();
        let mut hasher = DefaultHasher::new();
        let signature_copy = signature;
        signature_copy.hash(&mut hasher);
        let hash2 = hasher.finish();
        assert_eq!(hash1, hash2);

        // Test signature serialization/deserialization
        let mut bin_sig = unwrap!(bincode::serialize(&signature));
        assert_eq!(SIG_SIZE_IN_BYTES, bin_sig.len());
        assert_eq!(signature.to_bytes_vector(), bin_sig);
        assert_eq!(signature, unwrap!(bincode::deserialize(&bin_sig)),);
        bin_sig.push(0); // add on byte to simulate invalid length
        bincode::deserialize::<Sig>(&bin_sig)
            .expect_err("Deserialization must be fail because length is invalid !");

        // Test signature parsing
        assert_eq!(
            super::Signature::from_base64("YmhlaW9iaHNlcGlvaGVvaXNlcGl2ZXBvdm5pc2U=").unwrap_err(),
            BaseConversionError::InvalidLength {
                found: 29,
                expected: 64
            }
        );
        assert_eq!(
            super::Signature::from_base64(
                "YmhlaW9iaHNlcGlvaGVvaXNlcGl2ZXBvdm5pc2V2c2JlaW9idmVpb3Zqc\
                 2V2Z3BpaHNlamVwZ25qZXNqb2dwZWpnaW9zZXNkdnNic3JicmJyZGJyZGI=",
            )
            .unwrap_err(),
            BaseConversionError::InvalidBaseConverterLength
        );
        assert_eq!(
            super::Signature::from_base64(
                "ziv50X9Ch7rWiN87BG0QWzjHu/VKqJVYStC3G4pd8ck8jT0XAeN0mMxZ5LE2IRs/B81L7GsQWjKA/eiTocsCAw<<",
            )
            .unwrap_err(),
            BaseConversionError::InvalidCharacter {
                character: '<',
                offset: 86
            }
        );
        assert_eq!(
            super::Signature::from_base64(
                "1eubHHbuNfilHMM0G2bI30iZzebQ2cQ1PC7uPAw08FG\
                 MMmQCRerlF/3pc4sAcsnexsxBseA/3lY03KlONqJBAg===",
            )
            .unwrap_err(),
            BaseConversionError::InvalidBaseConverterLength,
        );
    }

    #[test]
    fn message_sign_verify() {
        let seed = unwrap!(Seed32::from_base58(
            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"
        ));

        let expected_signature = unwrap!(super::Signature::from_base64(
            "9ARKYkEAwp+kQ01rgvWUwJLchVLpZvHg3t/3H32XwWOoG119NiVCtfPSPtR4GDOeOz6Y+29drOLahqhzy+ciBw==",
        ));

        let message = "Version: 10
Type: Identity
Currency: duniter_unit_test_currency
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
UniqueID: tic
Timestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
";

        let signator = KeyPairFromSeed32Generator::generate(seed).generate_signator();
        let pubkey = signator.public_key();
        let sig = signator.sign(message.as_bytes());
        let wrong_sig = Signature([
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]);

        assert_eq!(sig, expected_signature);
        assert_eq!(Ok(()), pubkey.verify(message.as_bytes(), &sig));
        assert_eq!(
            Err(SigError::InvalidSig),
            pubkey.verify(message.as_bytes(), &wrong_sig)
        );
    }

    #[test]
    #[cfg(feature = "scrypt")]
    fn keypair_generate() {
        let key_pair1 = KeyPairFromSaltedPasswordGenerator::with_default_parameters().generate(
            SaltedPassword::new(
                "JhxtHB7UcsDbA9wMSyMKXUzBZUQvqVyB32KwzS9SWoLkjrUhHV".to_owned(),
                "JhxtHB7UcsDbA9wMSyMKXUzBZUQvqVyB32KwzS9SWoLkjrUhHV_".to_owned(),
            ),
        );

        assert_eq!(
            key_pair1.pubkey.to_string(),
            "7iMV3b6j2hSj5WtrfchfvxivS9swN3opDgxudeHq64fb"
        );

        let key_pair2 = KeyPairFromSaltedPasswordGenerator::with_parameters(12u8, 16, 1)
            .generate(SaltedPassword::new("toto".to_owned(), "toto".to_owned()));

        // Test signature display and debug
        assert_eq!(
            "(EA7Dsw39ShZg4SpURsrgMaMqrweJPUFPYHwZA8e92e3D, hidden)".to_owned(),
            format!("{}", key_pair2)
        );

        // Test key_pair equality
        let same_key_pair = key_pair2.clone();
        let other_key_pair = KeyPairFromSeed32Generator::generate(Seed32::new([
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]));
        assert!(key_pair2.eq(&same_key_pair));
        assert!(!key_pair2.eq(&other_key_pair));
    }

    #[test]
    #[cfg(feature = "scrypt")]
    fn keypair_generate_sign_and_verify() {
        let keypair = KeyPairFromSaltedPasswordGenerator::with_default_parameters().generate(
            SaltedPassword::new("password".to_owned(), "salt".to_owned()),
        );

        let message = "Version: 10
Type: Identity
Currency: duniter_unit_test_currency
Issuer: DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV
UniqueID: tic
Timestamp: 0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
";

        let sig = keypair.generate_signator().sign(message.as_bytes());
        assert!(keypair.verify(message.as_bytes(), &sig).is_ok());
    }

    #[test]
    #[cfg(feature = "pubkey_check")]
    fn invalid_pubkey() -> Result<(), ()> {
        let invalid_bytes = [
            206u8, 58, 67, 221, 20, 133, 0, 225, 86, 115, 26, 104, 142, 116, 140, 132, 119, 51,
            175, 45, 82, 225, 14, 195, 7, 107, 43, 212, 8, 37, 234, 23,
        ];
        if let Err(PubkeyFromBytesError::InvalidBytesContent) =
            PublicKey::try_from(&invalid_bytes[..])
        {
            Ok(())
        } else {
            panic!("expected PubkeyFromBytesError::InvalidBytesContent");
        }
    }

    #[test]
    fn test_parse_expanded_base58_private_key() {
        let bytes = unwrap!(bs58::decode(
            "31uSnvigJtJEUgG4YDqJB99awp4hkYgYqb3Yzu8P1LP5ZPMHtwNoCohVhm6jKcG9HFHbagDWdcoPgYBgHhdg5Efo"
        ).into_vec());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&bytes[32..64]);

        let keypair = KeyPairFromSeed32Generator::generate(Seed32::new(seed));
        println!("seed={}", keypair.seed());
        assert_eq!(
            "8hgzaeFnjkNCsemcaL4rmhB2999B79BydtE8xow4etB7",
            &keypair.public_key().to_base58()
        );
        assert_eq!(
            "8hgzaeFnjkNCsemcaL4rmhB2999B79BydtE8xow4etB7",
            &bs58::encode(&pubkey_bytes).into_string(),
        );
    }
}
