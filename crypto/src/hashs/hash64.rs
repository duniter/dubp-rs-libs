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

//! Provide wrapper for cryptographic hash of 64 bytes size
//!
//! # Summary
//!
//! * [Compute Sha512 hash](#compute-sha512-hash)
//!
//! ## Compute sha512 hash
//!
//! ```
//! use dup_crypto::hashs::Hash64;
//!
//! let hash: Hash64 = Hash64::sha512(b"datas");
//!
//! assert_eq!(
//!     "7F01265FD4F8CB88170139B81379C526429217317FB2D5CD209FFDFC8CA9FA1997222E640F50993A404CAE239D0D7480371E938B937FDF558C2C4194B77A0111",
//!     &hash.to_hex(),
//! );
//! ```
//!

use crate::bases::*;
use crate::rand::UnspecifiedRandError;
#[cfg(target_arch = "wasm32")]
use cryptoxide::{digest::Digest, sha2::Sha512};
#[cfg(not(target_arch = "wasm32"))]
use ring::digest;
use std::{
    fmt::{Debug, Display, Error, Formatter},
    str::FromStr,
};

/// A hash wrapper.
///
/// A hash is often provided as string composed of 64 hexadecimal character (0 to 9 then A to F).
#[derive(
    Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, zerocopy::AsBytes, zerocopy::FromBytes,
)]
#[repr(transparent)]
pub struct Hash64(pub [u8; 64]);

impl AsRef<[u8]> for Hash64 {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Display for Hash64 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.to_hex())
    }
}

impl Debug for Hash64 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "Hash64({})", self)
    }
}

impl Default for Hash64 {
    fn default() -> Hash64 {
        Hash64([0; 64])
    }
}

impl FromStr for Hash64 {
    type Err = BaseConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash64::from_hex(s)
    }
}

impl Hash64 {
    /// Hash64 size (in bytes).
    pub const SIZE_IN_BYTES: usize = 64;

    /// Generate a random Hash64
    #[inline]
    pub fn random() -> Result<Self, UnspecifiedRandError> {
        let mut random_bytes = [0u8; 64];
        crate::rand::gen_random_bytes(&mut random_bytes).map_err(|_| UnspecifiedRandError)?;
        Ok(Hash64(random_bytes))
    }

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    /// Compute SHA512 hash of any binary data
    pub fn sha512(data: &[u8]) -> Hash64 {
        let mut hasher = Sha512::new();
        hasher.input(data);
        let mut hash_buffer = [0u8; 64];
        hasher.result(&mut hash_buffer);
        Hash64(hash_buffer)
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Compute SHA512  hash of any binary data
    pub fn sha512(datas: &[u8]) -> Hash64 {
        let mut hash_buffer = [0u8; 64];
        hash_buffer.copy_from_slice(digest::digest(&digest::SHA512, datas).as_ref());
        Hash64(hash_buffer)
    }

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(tarpaulin_include))]
    /// Compute SHA512 hash of any binary data on several parts
    pub fn sha512_multipart(data_parts: &[&[u8]]) -> Hash64 {
        let mut hasher = Sha512::new();
        for data in data_parts {
            hasher.input(data);
        }
        let mut hash_buffer = [0u8; 64];
        hasher.result(&mut hash_buffer);
        Hash64(hash_buffer)
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Compute SHA512 hash of any binary data on several parts
    pub fn sha512_multipart(data_parts: &[&[u8]]) -> Hash64 {
        let mut ctx = digest::Context::new(&digest::SHA512);
        for data in data_parts {
            ctx.update(data);
        }
        let mut hash_buffer = [0u8; 64];
        hash_buffer.copy_from_slice(ctx.finish().as_ref());
        Hash64(hash_buffer)
    }

    /// Convert Hash64 into bytes vector
    pub fn to_bytes_vector(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Convert a `Hash` to an hex string.
    pub fn to_hex(&self) -> String {
        let strings: Vec<String> = self.0.iter().map(|b| format!("{:02X}", b)).collect();

        strings.join("")
    }

    /// Convert a hex string in a `Hash`.
    ///
    /// The hex string must only contains hex characters
    /// and produce a 64 bytes value.
    #[inline]
    pub fn from_hex(text: &str) -> Result<Hash64, BaseConversionError> {
        Ok(Hash64(b16::str_hex_to_64bytes(text)?))
    }

    /// Return tha maximum hash value
    ///
    /// Hexadecimal representation is `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`
    pub const fn max() -> Hash64 {
        Hash64([255; 64])
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_hash_random() {
        let hash1 = Hash64::random();
        let hash2 = Hash64::random();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_debug() {
        assert_eq!(
            "Hash64(00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)".to_owned(),
            format!("{:?}", Hash64::default()),
        );
    }

    #[test]
    fn test_hash_to_bytes() {
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ],
            Hash64::default().to_bytes_vector(),
        );
    }

    #[test]
    fn test_hash_computation() {
        assert_eq!(
            unwrap!(Hash64::from_hex(
                "9B71D224BD62F3785D96D46AD3EA3D73319BFBC2890CAADAE2DFF72519673CA72323C3D99BA5C11D7C7ACC6E14B8C5DA0C4663475C2E5C3ADEF46F73BCDEC043"
            )),
            Hash64::sha512(b"hello"),
        );
    }

    #[test]
    fn test_hash_from_hex() {
        assert_eq!(
            Ok(Hash64::default()),
            Hash64::from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            Err(BaseConversionError::InvalidLength {
                expected: 128,
                found: 130,
            }),
            Hash64::from_hex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            Err(BaseConversionError::InvalidCharacter {
                character: '_',
                offset: 0,
            }),
            Hash64::from_hex("_0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            Err(BaseConversionError::InvalidCharacter {
                character: '_',
                offset: 1,
            }),
            Hash64::from_hex("0_000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
    }
}
