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

//! Module to generate Mnemonic

mod error;
mod language;
mod mnemonic_gen;
mod mnemonic_type;
mod utils;

pub use error::MnemonicError;
pub use language::Language;
pub use mnemonic_gen::Mnemonic;
pub use mnemonic_type::MnemonicType;

///
/// Generate seed from [`Mnemonic`][Mnemonic]
///
/// # Example
///
/// ```
/// use dup_crypto::mnemonic::*;
/// use dup_crypto::keys::{ed25519::KeyPairFromSeed32Generator, KeyPair};
///
/// let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English).expect("fail to generate random bytes");
///
/// let seed = mnemonic_to_seed(&mnemonic);
///
/// let keypair = KeyPairFromSeed32Generator::generate(seed);
///
/// println!("public key: {}", keypair.public_key());
///
/// ```
///
/// [Mnemonic]: ./mnemonic/struct.Mnemonic.html
/// [Mnemonic::phrase()]: ./mnemonic/struct.Mnemonic.html#method.phrase
pub fn mnemonic_to_seed(mnemonic: &Mnemonic) -> crate::keys::Seed32 {
    let mnemonic_bytes = mnemonic.phrase().as_bytes();
    let salt = crate::hashs::Hash::compute(format!("dubp{}", mnemonic.phrase()).as_bytes());
    crate::keys::ed25519::KeyPairFromSaltedPasswordGenerator::with_default_parameters()
        .generate_seed(mnemonic_bytes, salt.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_to_seed() -> Result<(), MnemonicError> {
        let m = Mnemonic::from_phrase(
            "tongue cute mail fossil great frozen same social weasel impact brush kind",
            Language::English,
        )?;

        let seed = mnemonic_to_seed(&m);

        assert_eq!(
            "qGdvpbP9lJe7ZG4ZUSyu33KFeAEs/KkshAp9gEI4ReY=",
            &base64::encode(seed.as_ref())
        );

        Ok(())
    }
}
