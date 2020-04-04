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

//! Define DEWIF currency field

use std::fmt::Display;
use std::num::NonZeroU32;
use std::str::FromStr;

/// Ğ1 currency
pub const G1_CURRENCY: u32 = 1;
const G1_CURRENCY_STR: &str = "g1";

/// Ğ1-Test currency
pub const G1_TEST_CURRENCY: u32 = 268_435_457;
const G1_TEST_CURRENCY_STR: &str = "g1-test";

#[derive(Copy, Clone, Debug, PartialEq)]
/// Expected DEWIF currency
pub enum ExpectedCurrency {
    /// Expected any currency (no limitation)
    Any,
    /// Expected specific currency
    Specific(Currency),
}

impl ExpectedCurrency {
    pub(crate) fn is_valid(self, currency: Currency) -> bool {
        match self {
            Self::Any => true,
            Self::Specific(expected_currency) => expected_currency == currency,
        }
    }
}

impl Display for ExpectedCurrency {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Self::Any => write!(f, "Any"),
            Self::Specific(expected_currency) => expected_currency.fmt(f),
        }
    }
}

/// DEWIF currency
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Currency(Option<NonZeroU32>);

impl Currency {
    /// None currency
    pub fn none() -> Self {
        Currency(None)
    }
}

impl Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        if let Some(currency_code) = self.0 {
            match currency_code.get() {
                G1_CURRENCY => write!(f, "{}", G1_CURRENCY_STR),
                G1_TEST_CURRENCY => write!(f, "{}", G1_TEST_CURRENCY_STR),
                other => write!(f, "{}", other),
            }
        } else {
            write!(f, "None")
        }
    }
}

impl From<u32> for Currency {
    fn from(source: u32) -> Self {
        Self(NonZeroU32::new(source))
    }
}

impl Into<u32> for Currency {
    fn into(self) -> u32 {
        if let Some(currency_code) = self.0 {
            currency_code.get()
        } else {
            0u32
        }
    }
}

/// Unknown currency name
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct UnknownCurrencyName;

impl FromStr for Currency {
    type Err = UnknownCurrencyName;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        match source {
            "" => Ok(Currency(None)),
            G1_CURRENCY_STR => Ok(Currency(NonZeroU32::new(G1_CURRENCY))),
            G1_TEST_CURRENCY_STR => Ok(Currency(NonZeroU32::new(G1_TEST_CURRENCY))),
            _ => Err(UnknownCurrencyName),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn display_expected_currency() {
        assert_eq!(
            "None",
            &format!("{}", ExpectedCurrency::Specific(Currency::from(0))),
        );
        assert_eq!("Any", &format!("{}", ExpectedCurrency::Any));
    }

    #[test]
    fn display_currency() {
        assert_eq!(G1_CURRENCY_STR, &format!("{}", Currency::from(G1_CURRENCY)),);
        assert_eq!(
            G1_TEST_CURRENCY_STR,
            &format!("{}", Currency::from(G1_TEST_CURRENCY)),
        );
        assert_eq!("42", &format!("{}", Currency::from(42)),);
        assert_eq!("None", &format!("{}", Currency::from(0)),);
    }

    #[test]
    fn currency_from_str() {
        assert_eq!(
            Currency::from(G1_CURRENCY),
            Currency::from_str(G1_CURRENCY_STR).expect("unknown currency"),
        );
        assert_eq!(
            Currency::from(G1_TEST_CURRENCY),
            Currency::from_str(G1_TEST_CURRENCY_STR).expect("unknown currency"),
        );
        assert_eq!(
            Err(UnknownCurrencyName),
            Currency::from_str("unknown currency"),
        );
    }
}
