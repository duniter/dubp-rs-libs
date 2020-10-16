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
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    Ord,
    PartialOrd,
    Deserialize,
    Serialize,
    zerocopy::AsBytes,
    zerocopy::FromBytes,
)]
#[repr(transparent)]
pub struct SourceAmount([u8; 16]);

impl std::fmt::Display for SourceAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.amount(), self.base())
    }
}

impl SourceAmount {
    pub fn new(amount: i64, base: i64) -> Self {
        let mut buffer = [0; 16];
        buffer[..8].copy_from_slice(&amount.to_be_bytes()[..]);
        buffer[8..].copy_from_slice(&base.to_be_bytes()[..]);
        Self(buffer)
    }
    pub fn amount(&self) -> i64 {
        zerocopy::LayoutVerified::<_, zerocopy::I64<byteorder::BigEndian>>::new(&self.0[..8])
            .unwrap_or_else(|| unreachable!())
            .get()
    }
    pub fn base(&self) -> i64 {
        zerocopy::LayoutVerified::<_, zerocopy::I64<byteorder::BigEndian>>::new(&self.0[8..])
            .unwrap_or_else(|| unreachable!())
            .get()
    }
    pub fn with_base0(amount: i64) -> Self {
        let mut buffer = [0; 16];
        buffer[..8].copy_from_slice(&amount.to_be_bytes()[..]);
        Self(buffer)
    }
    pub fn increment_base(self) -> Self {
        Self::new(self.amount() / 10, self.base() + 1)
    }
}

impl PartialEq for SourceAmount {
    #[allow(clippy::comparison_chain)]
    fn eq(&self, other: &Self) -> bool {
        if self.base() == other.base() {
            self.amount().eq(&other.amount())
        } else if self.base() > other.base() {
            self.eq(&(*other).increment_base())
        } else {
            self.increment_base().eq(other)
        }
    }
}

impl Add for SourceAmount {
    type Output = SourceAmount;

    #[allow(clippy::comparison_chain)]
    fn add(self, a: SourceAmount) -> Self::Output {
        if self.base() == a.base() {
            SourceAmount::new(self.amount() + a.amount(), self.base())
        } else if self.base() > a.base() {
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
        if self.base() == a.base() {
            SourceAmount::new(self.amount() - a.amount(), self.base())
        } else if self.base() > a.base() {
            self.sub(a.increment_base())
        } else {
            self.increment_base().sub(a)
        }
    }
}

impl Sum for SourceAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(SourceAmount::with_base0(0), Add::add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_sources_amount() {
        let sa1 = SourceAmount::new(12, 1);
        let sa2 = SourceAmount::new(24, 1);
        let sa3 = SourceAmount::new(123, 0);

        assert_eq!(SourceAmount::new(36, 1), sa1 + sa2,);
        assert_eq!(SourceAmount::new(36, 1), sa2 + sa3,);
        /*assert_eq!(
            SourceAmount::new(36, 1),
            sa3 + sa2,
        );*/
    }

    #[test]
    fn test_sub_sources_amount() {
        let sa1 = SourceAmount::new(12, 1);
        assert_eq!(sa1.amount(), 12);
        assert_eq!(sa1.base(), 1);
        let sa2 = SourceAmount::new(36, 1);
        //let sa3 = SourceAmount::new(123, 0);

        assert_eq!(SourceAmount::new(24, 1), sa2 - sa1,);
        /*assert_eq!(
            SourceAmount::new(24, 1),
            sa2 - sa3,
        );c
        assert_eq!(SourceAmount::new(0, 1), sa3 - sa1,);*/
    }
}
