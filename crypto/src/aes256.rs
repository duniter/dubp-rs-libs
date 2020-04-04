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

//! Aes256 encryption/decryption

pub(crate) mod decrypt;
pub(crate) mod encrypt;

pub use aes::Aes256;
pub use decrypt::decrypt_bytes;
pub use encrypt::encrypt_bytes;

use crate::seeds::Seed32;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

type Block = GenericArray<u8, <Aes256 as BlockCipher>::BlockSize>;
type ParBlocks = <Aes256 as BlockCipher>::ParBlocks;

/// Create cipher from seed of 32 bytes
pub fn new_cipher(seed: Seed32) -> Aes256 {
    Aes256::new(GenericArray::from_slice(seed.as_ref()))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encrypt_and_decrypt_128_bytes() {
        let cipher = new_cipher(Seed32::default());

        let bytes = [3u8; 128];
        let mut encrypted_bytes = bytes;

        encrypt_bytes(&cipher, &mut encrypted_bytes);

        decrypt_bytes(&cipher, &mut encrypted_bytes);

        for i in 0..128 {
            assert_eq!(bytes[i], encrypted_bytes[i]);
        }
    }
}
