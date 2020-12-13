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

#[cfg(feature = "scrypt")]
/// Generate seed from `Mnemonic`
pub fn mnemonic_to_seed(mnemonic: &Mnemonic) -> crate::keys::Seed32 {
    let mnemonic_bytes = mnemonic.phrase().as_bytes();
    let salt = crate::hashs::Hash::compute(format!("dubp{}", mnemonic.phrase()).as_bytes());
    crate::keys::ed25519::KeyPairFromSaltedPasswordGenerator::with_default_parameters()
        .generate_seed(mnemonic_bytes, salt.as_ref())
}
