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

//! Provide wrappers around cryptographic seeds

use crate::bases::b58::{bytes_to_str_base58, ToBase58};
use crate::bases::*;
#[cfg(feature = "rand")]
use crate::rand::UnspecifiedRandError;
#[cfg(feature = "ser")]
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use zeroize::Zeroize;

/// Seed32 size in bytes
pub const SEED_32_SIZE_IN_BYTES: usize = 32;

/// Store a 32 bytes seed used to generate keys.
#[cfg_attr(feature = "ser", derive(Deserialize, Serialize))]
#[derive(Clone, Default, PartialEq, Eq, Hash, Zeroize)]
#[zeroize(drop)]
pub struct Seed32([u8; SEED_32_SIZE_IN_BYTES]);

impl AsRef<[u8]> for Seed32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToBase58 for Seed32 {
    fn to_base58(&self) -> String {
        bytes_to_str_base58(&self.0[..], 0)
    }
}

impl Debug for Seed32 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Seed32 {{ {} }}", self)
    }
}

impl Display for Seed32 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_base58())
    }
}

impl Seed32 {
    #[inline]
    /// Create new seed
    pub fn new(seed_bytes: [u8; SEED_32_SIZE_IN_BYTES]) -> Seed32 {
        Seed32(seed_bytes)
    }
    #[inline]
    /// Create seed from base58 str
    pub fn from_base58(base58_str: &str) -> Result<Self, BaseConvertionError> {
        Ok(Seed32::new(b58::str_base58_to_32bytes(base58_str)?.0))
    }
    #[cfg(feature = "rand")]
    #[inline]
    /// Generate random seed
    pub fn random() -> Result<Seed32, UnspecifiedRandError> {
        let random_bytes = crate::rand::gen_32_bytes().map_err(|_| UnspecifiedRandError)?;
        Ok(Seed32::new(random_bytes))
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "rand")]
    use super::*;

    #[cfg(feature = "rand")]
    #[test]
    fn test_gen_random_seed() {
        assert_ne!(Seed32::random(), Seed32::random());
    }
}
