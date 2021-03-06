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

//! Common utils

use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
/// U31Error
#[error("Integer must less than 2^31")]
pub struct U31Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Unsigned 31 bits integer
pub struct U31(u32);

impl U31 {
    /// New U31 from u32
    pub fn new(u32_: u32) -> Result<Self, U31Error> {
        if u32_ < 0x80000000 {
            Ok(Self(u32_))
        } else {
            Err(U31Error)
        }
    }
    #[inline(always)]
    /// Into u32
    pub fn into_u32(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u31() {
        assert!(U31::new(0).is_ok());
        assert!(U31::new(u32::MAX).is_err());
        assert!(U31::new(0x80_00_00_00).is_err());
        assert!(U31::new(0x7F_FF_FF_FF).is_ok());
    }
}
