//  Copyright (C) 2020  Éloïs SANCHEZ.
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

//! Manage cryptographic operations for DUniter Protocols and the Duniter eco-system most broadly.
//!
//! Scrypt parameters

use std::mem::size_of;

/// The Scrypt parameter values.
#[derive(Clone, Copy)]
pub struct ScryptParams {
    pub(crate) log_n: u8,
    pub(crate) r: u32,
    pub(crate) p: u32,
}

impl Default for ScryptParams {
    fn default() -> Self {
        ScryptParams {
            log_n: 12,
            r: 16,
            p: 1,
        }
    }
}

impl ScryptParams {
    ///
    /// Create a new instance of ScryptParams.
    ///
    /// # Arguments
    ///
    /// * `log_n` - The log2 of the Scrypt parameter N
    /// * `r` - The Scrypt parameter r
    /// * `p` - The Scrypt parameter p
    ///
    ///
    pub fn new(log_n: u8, r: u32, p: u32) -> ScryptParams {
        assert!(r > 0);
        assert!(p > 0);
        assert!(log_n > 0);
        assert!((log_n as usize) < size_of::<usize>() * 8);
        assert!(
            size_of::<usize>() >= size_of::<u32>()
                || (r <= std::usize::MAX as u32 && p < std::usize::MAX as u32)
        );

        let r = r as usize;
        let p = p as usize;

        let n: usize = 1 << log_n;

        // check that r * 128 doesn't overflow
        let r128 = if let Some(r128) = r.checked_mul(128) {
            r128
        } else {
            panic!("Invalid Scrypt parameters.");
        };

        // check that n * r * 128 doesn't overflow
        if r128.checked_mul(n).is_none() {
            panic!("Invalid Scrypt parameters.");
        };

        // check that p * r * 128 doesn't overflow
        if r128.checked_mul(p).is_none() {
            panic!("Invalid Scrypt parameters.");
        };

        // This check required by Scrypt:
        // check: n < 2^(128 * r / 8)
        // r * 16 won't overflow since r128 didn't
        assert!((log_n as usize) < r * 16);

        // This check required by Scrypt:
        // check: p <= ((2^32-1) * 32) / (128 * r)
        // It takes a bit of re-arranging to get the check above into this form, but, it is indeed
        // the same.
        assert!(r * p < 0x4000_0000);

        ScryptParams {
            log_n,
            r: r as u32,
            p: p as u32,
        }
    }
}
