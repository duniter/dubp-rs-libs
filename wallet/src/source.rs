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
    pub fn increment_base(self) -> Self {
        Self {
            amount: self.amount / 10,
            base: self.base + 1,
        }
    }
}

impl Add for SourceAmount {
    type Output = SourceAmount;

    #[allow(clippy::comparison_chain)]
    fn add(self, a: SourceAmount) -> Self::Output {
        if self.base == a.base {
            SourceAmount {
                amount: self.amount + a.amount,
                base: self.base,
            }
        } else if self.base > a.base {
            self.add(a.increment_base())
        } else {
            self.increment_base().add(a)
        }
    }
}

impl Sub for SourceAmount {
    type Output = SourceAmount;

    #[allow(clippy::comparison_chain)]
    fn sub(self, a: SourceAmount) -> Self::Output {
        if self.base == a.base {
            SourceAmount {
                amount: self.amount - a.amount,
                base: self.base,
            }
        } else if self.base > a.base {
            self.sub(a.increment_base())
        } else {
            self.increment_base().sub(a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_sources_amount() {
        let sa1 = SourceAmount {
            amount: 12,
            base: 1,
        };
        let sa2 = SourceAmount {
            amount: 24,
            base: 1,
        };
        let sa3 = SourceAmount {
            amount: 123,
            base: 0,
        };

        assert_eq!(
            SourceAmount {
                amount: 36,
                base: 1
            },
            sa1 + sa2,
        );
        assert_eq!(
            SourceAmount {
                amount: 36,
                base: 1
            },
            sa2 + sa3,
        );
        assert_eq!(
            SourceAmount {
                amount: 36,
                base: 1
            },
            sa3 + sa2,
        );
    }

    #[test]
    fn test_sub_sources_amount() {
        let sa1 = SourceAmount {
            amount: 12,
            base: 1,
        };
        let sa2 = SourceAmount {
            amount: 36,
            base: 1,
        };
        let sa3 = SourceAmount {
            amount: 123,
            base: 0,
        };

        assert_eq!(
            SourceAmount {
                amount: 24,
                base: 1
            },
            sa2 - sa1,
        );
        assert_eq!(
            SourceAmount {
                amount: 24,
                base: 1
            },
            sa2 - sa3,
        );
        assert_eq!(SourceAmount { amount: 0, base: 1 }, sa3 - sa1,);
    }
}
