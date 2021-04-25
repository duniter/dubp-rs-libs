//  Copyright (C) 2019 Eloïs SANCHEZ.
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

use super::error::MnemonicError;
use super::utils::{Bits, Bits11};
use std::{collections::HashMap, str::FromStr};

pub struct WordMap {
    inner: HashMap<&'static str, Bits11>,
}

pub struct WordList {
    inner: Vec<&'static str>,
}

impl WordMap {
    pub fn get_bits(&self, word: &str) -> Result<Bits11, MnemonicError> {
        match self.inner.get(word) {
            Some(n) => Ok(*n),
            None => Err(MnemonicError::InvalidWord),
        }
    }
}

impl WordList {
    pub fn get_word(&self, bits: Bits11) -> &'static str {
        self.inner[bits.bits() as usize]
    }
}

mod lazy {
    use super::{Bits11, WordList, WordMap};
    use once_cell::sync::Lazy;

    /// lazy generation of the word list
    fn gen_wordlist(lang_words: &'static str) -> WordList {
        let inner: Vec<_> = lang_words.split_whitespace().collect();

        debug_assert!(inner.len() == 2048, "Invalid wordlist length");

        WordList { inner }
    }

    /// lazy generation of the word map
    fn gen_wordmap(wordlist: &WordList) -> WordMap {
        let inner = wordlist
            .inner
            .iter()
            .enumerate()
            .map(|(i, item)| (*item, Bits11::from(i as u16)))
            .collect();

        WordMap { inner }
    }

    pub static WORDLIST_ENGLISH: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/english.txt")));
    #[cfg(feature = "mnemonic_chinese_simplified")]
    pub static WORDLIST_CHINESE_SIMPLIFIED: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/chinese_simplified.txt")));
    #[cfg(feature = "mnemonic_chinese_traditional")]
    pub static WORDLIST_CHINESE_TRADITIONAL: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/chinese_traditional.txt")));
    #[cfg(feature = "mnemonic_french")]
    pub static WORDLIST_FRENCH: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/french.txt")));
    #[cfg(feature = "mnemonic_italian")]
    pub static WORDLIST_ITALIAN: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/italian.txt")));
    #[cfg(feature = "mnemonic_japanese")]
    pub static WORDLIST_JAPANESE: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/japanese.txt")));
    #[cfg(feature = "mnemonic_korean")]
    pub static WORDLIST_KOREAN: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/korean.txt")));
    #[cfg(feature = "mnemonic_spanish")]
    pub static WORDLIST_SPANISH: Lazy<WordList> =
        Lazy::new(|| gen_wordlist(include_str!("langs/spanish.txt")));

    pub static WORDMAP_ENGLISH: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_ENGLISH));
    #[cfg(feature = "mnemonic_chinese_simplified")]
    pub static WORDMAP_CHINESE_SIMPLIFIED: Lazy<WordMap> =
        Lazy::new(|| gen_wordmap(&WORDLIST_CHINESE_SIMPLIFIED));
    #[cfg(feature = "mnemonic_chinese_traditional")]
    pub static WORDMAP_CHINESE_TRADITIONAL: Lazy<WordMap> =
        Lazy::new(|| gen_wordmap(&WORDLIST_CHINESE_TRADITIONAL));
    #[cfg(feature = "mnemonic_french")]
    pub static WORDMAP_FRENCH: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_FRENCH));
    #[cfg(feature = "mnemonic_italian")]
    pub static WORDMAP_ITALIAN: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_ITALIAN));
    #[cfg(feature = "mnemonic_japanese")]
    pub static WORDMAP_JAPANESE: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_JAPANESE));
    #[cfg(feature = "mnemonic_korean")]
    pub static WORDMAP_KOREAN: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_KOREAN));
    #[cfg(feature = "mnemonic_spanish")]
    pub static WORDMAP_SPANISH: Lazy<WordMap> = Lazy::new(|| gen_wordmap(&WORDLIST_SPANISH));
}

/// The language determines which words will be used in a mnemonic phrase, but also indirectly
/// determines the binary value of each word when a [`Mnemonic`][Mnemonic] is turned into a [`Seed`][Seed].
///
/// These are not of much use right now, and may even be removed from the crate, as there is no
/// official language specified by the standard except English.
///
/// [Mnemonic]: ./mnemonic/struct.Mnemonic.html
/// [Seed]: ./seed/struct.Seed.html
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Language {
    /// English
    English,
    #[cfg(feature = "mnemonic_chinese_simplified")]
    /// Chinese simplified
    ChineseSimplified,
    #[cfg(feature = "mnemonic_chinese_traditional")]
    /// Chinese traditional
    ChineseTraditional,
    #[cfg(feature = "mnemonic_french")]
    /// French
    French,
    #[cfg(feature = "mnemonic_italian")]
    /// Italian
    Italian,
    #[cfg(feature = "mnemonic_japanese")]
    /// Japanese
    Japanese,
    #[cfg(feature = "mnemonic_korean")]
    /// Korean
    Korean,
    #[cfg(feature = "mnemonic_spanish")]
    /// Spanish
    Spanish,
}

impl Language {
    /// Get the word list for this language
    pub fn wordlist(self) -> &'static WordList {
        match self {
            Language::English => &lazy::WORDLIST_ENGLISH,
            #[cfg(feature = "mnemonic_chinese_simplified")]
            Language::ChineseSimplified => &lazy::WORDLIST_CHINESE_SIMPLIFIED,
            #[cfg(feature = "mnemonic_chinese_traditional")]
            Language::ChineseTraditional => &lazy::WORDLIST_CHINESE_TRADITIONAL,
            #[cfg(feature = "mnemonic_french")]
            Language::French => &lazy::WORDLIST_FRENCH,
            #[cfg(feature = "mnemonic_italian")]
            Language::Italian => &lazy::WORDLIST_ITALIAN,
            #[cfg(feature = "mnemonic_japanese")]
            Language::Japanese => &lazy::WORDLIST_JAPANESE,
            #[cfg(feature = "mnemonic_korean")]
            Language::Korean => &lazy::WORDLIST_KOREAN,
            #[cfg(feature = "mnemonic_spanish")]
            Language::Spanish => &lazy::WORDLIST_SPANISH,
        }
    }

    /// Get a [`WordMap`][WordMap] that allows word -> index lookups in the word list
    ///
    /// The index of an individual word in the word list is used as the binary value of that word
    /// when the phrase is turned into a [`Seed`][Seed].
    pub fn wordmap(self) -> &'static WordMap {
        match self {
            Language::English => &lazy::WORDMAP_ENGLISH,
            #[cfg(feature = "mnemonic_chinese_simplified")]
            Language::ChineseSimplified => &lazy::WORDMAP_CHINESE_SIMPLIFIED,
            #[cfg(feature = "mnemonic_chinese_traditional")]
            Language::ChineseTraditional => &lazy::WORDMAP_CHINESE_TRADITIONAL,
            #[cfg(feature = "mnemonic_french")]
            Language::French => &lazy::WORDMAP_FRENCH,
            #[cfg(feature = "mnemonic_italian")]
            Language::Italian => &lazy::WORDMAP_ITALIAN,
            #[cfg(feature = "mnemonic_japanese")]
            Language::Japanese => &lazy::WORDMAP_JAPANESE,
            #[cfg(feature = "mnemonic_korean")]
            Language::Korean => &lazy::WORDMAP_KOREAN,
            #[cfg(feature = "mnemonic_spanish")]
            Language::Spanish => &lazy::WORDMAP_SPANISH,
        }
    }

    pub(crate) fn from_u8(source: u8) -> Result<Self, MnemonicError> {
        match source {
            0 => Ok(Self::English),
            #[cfg(feature = "mnemonic_chinese_simplified")]
            1 => Ok(Self::ChineseSimplified),
            #[cfg(feature = "mnemonic_chinese_traditional")]
            2 => Ok(Self::ChineseTraditional),
            #[cfg(feature = "mnemonic_french")]
            3 => Ok(Self::French),
            #[cfg(feature = "mnemonic_italian")]
            4 => Ok(Self::Italian),
            #[cfg(feature = "mnemonic_japanese")]
            5 => Ok(Self::Japanese),
            #[cfg(feature = "mnemonic_korean")]
            6 => Ok(Self::Korean),
            #[cfg(feature = "mnemonic_spanish")]
            7 => Ok(Self::Spanish),
            _ => Err(MnemonicError::UnknownLanguage),
        }
    }

    pub(crate) fn to_u8(self) -> u8 {
        match self {
            Language::English => 0,
            #[cfg(feature = "mnemonic_chinese_simplified")]
            Language::ChineseSimplified => 1,
            #[cfg(feature = "mnemonic_chinese_traditional")]
            Language::ChineseTraditional => 2,
            #[cfg(feature = "mnemonic_french")]
            Language::French => 3,
            #[cfg(feature = "mnemonic_italian")]
            Language::Italian => 4,
            #[cfg(feature = "mnemonic_japanese")]
            Language::Japanese => 5,
            #[cfg(feature = "mnemonic_korean")]
            Language::Korean => 6,
            #[cfg(feature = "mnemonic_spanish")]
            Language::Spanish => 7,
        }
    }
}

impl Default for Language {
    fn default() -> Language {
        Language::English
    }
}

impl FromStr for Language {
    type Err = MnemonicError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        match source {
            "en" => Ok(Self::English),
            #[cfg(feature = "mnemonic_chinese_simplified")]
            "zh_HANS" => Ok(Self::ChineseSimplified),
            #[cfg(feature = "mnemonic_chinese_traditional")]
            "zh_HANT" => Ok(Self::ChineseTraditional),
            #[cfg(feature = "mnemonic_french")]
            "fr" => Ok(Self::French),
            #[cfg(feature = "mnemonic_italian")]
            "it" => Ok(Self::Italian),
            #[cfg(feature = "mnemonic_japanese")]
            "ja" => Ok(Self::Japanese),
            #[cfg(feature = "mnemonic_korean")]
            "ko" => Ok(Self::Korean),
            #[cfg(feature = "mnemonic_spanish")]
            "es" => Ok(Self::Spanish),
            _ => unreachable!(),
        }
    }
}
