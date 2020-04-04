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

//! Provide x25519 tools:
//! - Converters from ed25519 keys to x25519 keys
//! - Diffie hellman exchange

use super::ed25519::PublicKey;
use crate::seeds::Seed32;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ring::digest;
use zeroize::Zeroize;

/// x25519 public key
#[derive(Clone, Copy, Debug)]
pub(crate) struct X25519PublicKey(MontgomeryPoint);

impl From<&PublicKey> for X25519PublicKey {
    fn from(ed25519_public_key: &PublicKey) -> Self {
        let compressed_edwards_y =
            CompressedEdwardsY::from_slice(ed25519_public_key.datas.as_ref());
        let edwards_point = compressed_edwards_y
            .decompress()
            .expect("dev error: invalid ed25519 public key");
        X25519PublicKey(edwards_point.to_montgomery())
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct X25519SecretKey([u8; 32]);

impl From<&Seed32> for X25519SecretKey {
    fn from(seed: &Seed32) -> Self {
        let mut hash = [0u8; 64];
        hash.copy_from_slice(digest::digest(&digest::SHA512, seed.as_ref()).as_ref());

        let mut x25519_sk = [0; 32];
        x25519_sk[..32].copy_from_slice(&hash[..32]);
        x25519_sk[0] &= 248;
        x25519_sk[31] &= 127;
        x25519_sk[31] |= 64;

        X25519SecretKey(x25519_sk)
    }
}

pub(crate) fn diffie_hellman<F, R>(
    my_secret_key: X25519SecretKey,
    their_public_key: X25519PublicKey,
    key_derivation_function: F,
) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    key_derivation_function((Scalar::from_bits(my_secret_key.0) * their_public_key.0).as_bytes())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::keys::KeyPair;

    #[test]
    fn test_dh() -> Result<(), crate::rand::UnspecifiedRandError> {
        let keypair1 = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let keypair2 = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let shared_secret_1 = diffie_hellman(
            X25519SecretKey::from(keypair1.seed()),
            X25519PublicKey::from(&keypair2.public_key()),
            |key_material| key_material.to_vec(),
        );

        let shared_secret_2 = diffie_hellman(
            X25519SecretKey::from(keypair2.seed()),
            X25519PublicKey::from(&keypair1.public_key()),
            |key_material| key_material.to_vec(),
        );

        assert_eq!(shared_secret_1, shared_secret_2,);

        Ok(())
    }
}
