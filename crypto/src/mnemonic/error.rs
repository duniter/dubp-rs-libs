//  Copyright (C) 2020 Eloïs SANCHEZ.
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

use super::mnemonic_type::MnemonicType;
use crate::rand::UnspecifiedRandError;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
/// Mnemonic error
pub enum MnemonicError {
    /// invalid checksum
    #[error("invalid checksum")]
    InvalidChecksum,
    /// invalid word in phrase
    #[error("invalid word in phrase")]
    InvalidWord,
    /// invalid keysize
    #[error("invalid keysize: {0}")]
    InvalidKeysize(usize),
    /// invalid number of words in phrase
    #[error("invalid number of words in phrase: {0}")]
    InvalidWordLength(usize),
    /// invalid entropy length
    #[error("invalid entropy length {0} bits for mnemonic type {1:?}")]
    InvalidEntropyLength(usize, MnemonicType),
    /// Unknown language
    #[error("Unknown language")]
    UnknownLanguage,
    /// Unspecified rand error
    #[error("Unspecified rand error")]
    UnspecifiedRandError(UnspecifiedRandError),
}
