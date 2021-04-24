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

//! XOR Cipher

pub(crate) fn xor_cipher(input: &[u8], key: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), key.len());
    assert_eq!(input.len(), output.len());

    for i in 0..input.len() {
        output[i] = input[i] ^ key[i];
    }
}
