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

//! Aes256 decryption

use super::{Aes256, Block, ParBlocks};
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

/// Decrypt bytes.
/// The length of the bytes slice must be a multiple of 16 !
/// Panics if the length of the bytes slice is not a multiple of 16.
pub fn decrypt_bytes(cipher: &Aes256, bytes: &mut [u8]) {
    assert!(bytes.len() % 16 == 0);

    let mut remaining_len = bytes.len();
    let par_len = bytes.len() / 128;
    if par_len > 0 {
        decrypt_par_n_blocks(cipher, &mut bytes[..par_len], par_len / 8);
        remaining_len -= par_len;
    }
    if remaining_len > 0 {
        decrypt_n_blocks(cipher, &mut bytes[par_len..], remaining_len / 16);
    }
}

fn decrypt_par_n_blocks(cipher: &Aes256, bytes: &mut [u8], n: usize) {
    for i in (0..n).step_by(8) {
        decrypt_8_blocks(cipher, &mut bytes[i..i + 128]);
    }
}

pub(crate) fn decrypt_8_blocks(cipher: &Aes256, bytes: &mut [u8]) {
    let mut blocks: GenericArray<Block, ParBlocks> = (0..8)
        .map(|i| {
            let begin = i * 16;
            let end = begin + 16;
            GenericArray::clone_from_slice(&bytes[begin..end])
        })
        .collect();

    cipher.decrypt_blocks(&mut blocks);

    for (i, block) in blocks.into_iter().enumerate() {
        let begin = i * 16;
        let end = (i + 1) * 16;
        bytes[begin..end].copy_from_slice(block.as_slice());
    }
}

pub(crate) fn decrypt_n_blocks(cipher: &Aes256, bytes: &mut [u8], n: usize) {
    for i in 0..n {
        let begin = i * 16;
        let end = (i + 1) * 16;
        let mut block = GenericArray::from_mut_slice(&mut bytes[begin..end]);
        cipher.decrypt_block(&mut block);
    }
}
