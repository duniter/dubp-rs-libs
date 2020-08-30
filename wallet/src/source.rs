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

//! Define DUBP currency source.

pub mod v10;

use crate::*;

/// Wrap a source amount
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Deserialize, Hash, Serialize)]
pub struct SourceAmount {
    pub amount: isize,
    pub base: usize,
}

impl SourceAmount {
    pub fn with_base0(amount: isize) -> Self {
        Self { amount, base: 0 }
    }
}

impl Add for SourceAmount {
    type Output = SourceAmount;
    fn add(self, a: SourceAmount) -> Self::Output {
        if self.base == a.base {
            SourceAmount {
                amount: self.amount + a.amount,
                base: self.base,
            }
        } else {
            todo!()
        }
    }
}

impl Sub for SourceAmount {
    type Output = SourceAmount;
    fn sub(self, a: SourceAmount) -> Self::Output {
        if self.base == a.base {
            SourceAmount {
                amount: self.amount - a.amount,
                base: self.base,
            }
        } else {
            todo!()
        }
    }
}
