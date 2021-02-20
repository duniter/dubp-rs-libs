//  Copyright (C) 2020 Éloïs SANCHEZ.
//
// This  account_id: (), language: (), shares_count: (), share_index: (), threshold: () account_id: (), language: (), shares_count: (), share_index: (), threshold: ()program is free software: you can redistribute it and/or modify
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

//! Mnemonic share (Shamir's Secret Sharing)
//!
//! ## Split mnemonic into several fragments and reconstruct mnemonic
//!
//! ```
//! use dup_crypto::bases::b58::ToBase58;
//! use dup_crypto::mnemonic::*;
//! use std::str::FromStr;
//!
//! let mnemonic = Mnemonic::from_phrase(
//!     "tongue cute mail fossil great frozen same social weasel impact brush kind",
//!     Language::English,
//! ).expect("invalid mnemonic");
//!
//! // Split mnemonic into several fragments (named "share").
//! let shares: Vec<String> = mnemonic_to_shares(mnemonic, 5, 3)?.map(|share| share.to_base58()).collect();
//!
//! // Merging of fragments
//! let reconstructed_mnemonic = mnemonic_from_shares(
//!     shares
//!     .into_iter()
//!     .map(|share| Share::from_str(&share).expect("invalid share")),
//! )?;
//!
//! assert_eq!(
//!     reconstructed_mnemonic.phrase(),
//!     "tongue cute mail fossil great frozen same social weasel impact brush kind"
//! );
//! # Ok::<(), MnemonicSSSErr>(())
//! ```
//!

use super::{Language, Mnemonic};
use crate::{
    bases::{b58::ToBase58, BaseConversionError},
    hashs::Hash,
    rand::{gen_random_bytes, UnspecifiedRandError},
};
use arrayvec::ArrayVec;
use std::{convert::TryFrom, str::FromStr};
use thiserror::Error;

const ACCOUNT_ID_SIZE: usize = 2;

const MAX_SHARES_COUNT: usize = 16;
const MNEMONIC_MAX_ENTROPY: usize = 32;

const SECRET_CHECKSUM_SIZE: usize = 2;
const SECRET_MAX_SIZE: usize = MNEMONIC_MAX_ENTROPY + SECRET_META_SIZE;
const SECRET_META_SIZE: usize = SECRET_CHECKSUM_SIZE + 1; // 1 for I/L

const SHARE_CHECKSUM_SIZE: usize = 2;
const SHARE_MIN_SIZE: usize = SHARE_META_SIZE + SECRET_META_SIZE;
const SHARE_MAX_SIZE: usize = SECRET_MAX_SIZE + SHARE_META_SIZE;
const SHARE_META_SIZE: usize = ACCOUNT_ID_SIZE + SHARE_CHECKSUM_SIZE + 1; // 1 for T/N

#[derive(Clone, Debug, Error)]
/// Mnemonic Shamir's Secret Sharing error
pub enum MnemonicSSSErr {
    /// Corrupted mnemonic
    #[error("Corrupted mnemonic: invalid checksum")]
    CorruptedMnemonic,
    /// Empty shares
    #[error("No share provided")]
    EmptyShares,
    /// Invalid share checksum
    #[error("Share corrupted: invalid checksum")]
    InvalidShareChecksum,
    /// Invalid threshold
    #[error("Invalid threshold")]
    InvalidThreshold,
    /// Invalid shares count
    #[error("Shares count must be beetween 2 and 16.")]
    InvalidSharesCount,
    /// Malicious share
    #[error("Malicious share")]
    MaliciousShare,
    /// Not enough shares
    #[error(
        "Not enough shares: expected at least {expected} shares, but only {found} are provided."
    )]
    NotEnoughShares {
        /// expected
        expected: u8,
        /// found
        found: usize,
    },
    /// Other
    #[error("{0}")]
    Other(String),
    /// Several accounts
    #[error("Several accounts")]
    SeveralAccounts,
    /// too short
    #[error("A Share must be at least 6 bytes long")]
    TooShortShare,
    /// Unknown language
    #[error("Unknown language")]
    UnknownLanguage,
    /// Unspecified rand error
    #[error("Unspecified rand error")]
    UnspecifiedRandError(UnspecifiedRandError),
}

/// Iterator of share
pub struct Shares {
    inner: SharesContainer,
}
impl Iterator for Shares {
    type Item = Share;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.pop().map(Share)
    }
}

/// One share
#[derive(Clone)]
pub struct Share(ShareContainer);
impl FromStr for Share {
    type Err = BaseConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buffer = [0u8; SHARE_MAX_SIZE];
        let written_len = bs58::decode(s).into(&mut buffer)?;
        let mut container = ShareContainer::from(buffer);
        container.truncate(written_len);
        Ok(Share(container))
    }
}
impl ToBase58 for Share {
    fn to_base58(&self) -> String {
        bs58::encode(self.0.as_ref()).into_string()
    }
}

type ShareContainer = ArrayVec<[u8; SHARE_MAX_SIZE]>;
type SharesContainer = ArrayVec<[ShareContainer; MAX_SHARES_COUNT]>;

/// Get share meta data
pub fn get_share_meta(share: &Share) -> Result<MnemonicShareMeta, MnemonicSSSErr> {
    let share = MnemonicShare::try_from(share.0.as_ref())?;

    Ok(MnemonicShareMeta {
        account_id: u16::from_be_bytes(share.account_id),
        language: share.language,
        shares_count: share.shares_count,
        share_index: share.share_index,
        threshold: share.threshold,
    })
}
/// Use Shamir's Secret Sharing fragments to reconstruct the mnemonic
pub fn mnemonic_from_shares<I: Iterator<Item = Share>>(
    shares: I,
) -> Result<Mnemonic, MnemonicSSSErr> {
    let shares = shares
        .map(|share| MnemonicShare::try_from(share.0.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;

    if shares.is_empty() {
        Err(MnemonicSSSErr::EmptyShares)
    } else {
        let account_id = shares[0].account_id;
        let language = shares[0].language;
        let threshold = shares[0].threshold;

        for share in &shares[1..] {
            if share.account_id != account_id {
                return Err(MnemonicSSSErr::SeveralAccounts);
            }
            if share.threshold != threshold {
                return Err(MnemonicSSSErr::MaliciousShare);
            }
        }

        if shares.len() < threshold as usize {
            return Err(MnemonicSSSErr::NotEnoughShares {
                expected: threshold,
                found: shares.len(),
            });
        }

        let shares: Vec<sharks::Share> = shares.into_iter().map(|share| share.share).collect();
        let secret_bytes = sharks::Sharks(threshold)
            .recover(&shares)
            .map_err(|s| MnemonicSSSErr::Other(s.to_owned()))?;

        let secret = SharedSecret::from_bytes_and_language(&secret_bytes[..], language)?;

        Ok(secret.mnemonic)
    }
}
/// Split a mnemonic into several piece via Shamir's Secret Sharing
pub fn mnemonic_to_shares(
    mnemonic: Mnemonic,
    shares_count: u8,
    threshold: u8,
) -> Result<Shares, MnemonicSSSErr> {
    #[allow(clippy::manual_range_contains)]
    if shares_count < 2 || shares_count > MAX_SHARES_COUNT as u8 {
        return Err(MnemonicSSSErr::InvalidSharesCount);
    }
    if threshold < 2 || threshold > shares_count {
        return Err(MnemonicSSSErr::InvalidThreshold);
    }

    let mut account_id = [0u8; ACCOUNT_ID_SIZE];
    gen_random_bytes(&mut account_id[..]).map_err(MnemonicSSSErr::UnspecifiedRandError)?;

    let language = mnemonic.language();
    let shared_secret: ArrayVec<[u8; SECRET_MAX_SIZE]> = SharedSecret { mnemonic }.into();

    Ok(Shares {
        inner: sharks::Sharks(threshold)
            .dealer(&shared_secret)
            .take(shares_count as usize)
            .enumerate()
            .map(|(i, share)| {
                MnemonicShare {
                    account_id,
                    language,
                    share,
                    share_index: i as u8 + 1,
                    shares_count,
                    threshold,
                }
                .into()
            })
            .collect(),
    })
}

/// A mnemonic share
pub struct MnemonicShare {
    account_id: [u8; ACCOUNT_ID_SIZE],
    language: Language,
    share: sharks::Share,
    share_index: u8,
    shares_count: u8,
    threshold: u8,
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Mnemonic share meta data
pub struct MnemonicShareMeta {
    pub account_id: u16,
    pub language: Language,
    pub shares_count: u8,
    pub share_index: u8,
    pub threshold: u8,
}

impl TryFrom<&[u8]> for MnemonicShare {
    type Error = MnemonicSSSErr;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() > SHARE_MIN_SIZE {
            let mut account_id = [0u8; ACCOUNT_ID_SIZE];
            account_id.copy_from_slice(&bytes[..ACCOUNT_ID_SIZE]);
            let threshold = bytes[ACCOUNT_ID_SIZE] >> 4;
            let shares_count = bytes[ACCOUNT_ID_SIZE] & 0b_0000_1111;
            //println!("TMP: (T; N)=({};{})", threshold, n);
            let share_end = bytes.len() - SHARE_CHECKSUM_SIZE;

            // Read language
            let mut secret = Vec::from(&bytes[ACCOUNT_ID_SIZE + 1..share_end]);
            let language =
                Language::from_u8(secret[0] >> 4).map_err(|_| MnemonicSSSErr::UnknownLanguage)?;
            secret[0] &= 0b_0000_1111;

            // Read share_index
            let share_index = secret[0];

            // Parse inner share
            let share = sharks::Share::try_from(&secret[..]).unwrap_or_else(|_| unreachable!());

            // Read expected checksum
            let mut expected_checksum = [0u8; SHARE_CHECKSUM_SIZE];
            expected_checksum.copy_from_slice(&bytes[share_end..]);

            if Hash::compute(&bytes[..share_end]).as_ref()[..SHARE_CHECKSUM_SIZE]
                != expected_checksum
            {
                Err(MnemonicSSSErr::InvalidShareChecksum)
            } else {
                Ok(MnemonicShare {
                    account_id,
                    language,
                    share,
                    share_index,
                    shares_count,
                    threshold,
                })
            }
        } else {
            Err(MnemonicSSSErr::TooShortShare)
        }
    }
}

impl Into<ArrayVec<[u8; SHARE_MAX_SIZE]>> for MnemonicShare {
    fn into(self) -> ArrayVec<[u8; SHARE_MAX_SIZE]> {
        let mut share_bytes = Vec::from(&self.share);
        share_bytes[0] |= self.language.to_u8() << 4;
        let share_bytes_len = share_bytes.len();
        let checksum_begin = share_bytes_len + SHARE_META_SIZE - SHARE_CHECKSUM_SIZE;

        let mut vec = ArrayVec::new();
        vec.try_extend_from_slice(&self.account_id)
            .unwrap_or_else(|_| unreachable!());
        vec.push((self.threshold << 4) | self.shares_count);
        //println!("TMP: vec[ACCOUNT_ID_SIZE]={:?}", vec[ACCOUNT_ID_SIZE]);

        vec.try_extend_from_slice(&share_bytes)
            .unwrap_or_else(|_| unreachable!());

        let checksum_hash = Hash::compute(&vec[..checksum_begin]);
        vec.try_extend_from_slice(&checksum_hash.as_ref()[..SHARE_CHECKSUM_SIZE])
            .unwrap_or_else(|_| unreachable!());

        vec
    }
}

struct SharedSecret {
    mnemonic: Mnemonic,
}

impl SharedSecret {
    fn from_bytes_and_language(bytes: &[u8], language: Language) -> Result<Self, MnemonicSSSErr> {
        let checksum_begin = bytes.len() - SECRET_CHECKSUM_SIZE;
        let mnemonic = Mnemonic::from_entropy(&bytes[..checksum_begin], language)
            .map_err(|_| MnemonicSSSErr::CorruptedMnemonic)?;

        let actual_checksum = &bytes[checksum_begin..];
        if &Hash::compute(&bytes[..checksum_begin]).as_ref()[..SECRET_CHECKSUM_SIZE]
            != actual_checksum
        {
            Err(MnemonicSSSErr::CorruptedMnemonic)
        } else {
            Ok(SharedSecret { mnemonic })
        }
    }
}

impl Into<ArrayVec<[u8; SECRET_MAX_SIZE]>> for SharedSecret {
    fn into(self) -> ArrayVec<[u8; SECRET_MAX_SIZE]> {
        let mnemonic_entropy = self.mnemonic.entropy();
        let mnemonic_entropy_len = mnemonic_entropy.len();

        let mut secret = ArrayVec::new();
        secret
            .try_extend_from_slice(mnemonic_entropy)
            .unwrap_or_else(|_| unreachable!());
        let checksum_hash = Hash::compute(&secret[..mnemonic_entropy_len]);
        secret
            .try_extend_from_slice(&checksum_hash.as_ref()[..SECRET_CHECKSUM_SIZE])
            .unwrap_or_else(|_| unreachable!());

        secret
    }
}

#[cfg(test)]
mod tests {
    use super::super::MnemonicType;
    use super::*;
    use unwrap::unwrap;

    #[test]
    fn test_bytes() -> Result<(), MnemonicSSSErr> {
        let mnemonic = unwrap!(Mnemonic::new(MnemonicType::Words12, Language::English));
        let mnemonic_phrase = mnemonic.phrase().to_owned();

        let e = mnemonic.entropy();
        println!("e.len()={}", e.len());
        //println!("e={:?}", e);

        let shares: Vec<_> = mnemonic_to_shares(mnemonic, 5, 3)?.collect();
        //21bChTes2TYUn7RQvz7WvXytR1zV
        let mut i = 5;
        for share in shares.iter() {
            println!("share.len()={}", share.0.as_ref().len());
            let meta = get_share_meta(share)?;
            assert_eq!(meta.language, Language::English);
            assert_eq!(meta.shares_count, 5);
            assert_eq!(meta.share_index, i);
            i -= 1;
            assert_eq!(meta.threshold, 3);
        }

        let reconstructed_mnemonic = mnemonic_from_shares(shares.into_iter())?;

        assert_eq!(&mnemonic_phrase, reconstructed_mnemonic.phrase());

        Ok(())
    }

    #[test]
    fn test_b58() -> Result<(), MnemonicSSSErr> {
        let mnemonic = unwrap!(Mnemonic::new(MnemonicType::Words12, Language::English));
        let mnemonic_phrase = mnemonic.phrase().to_owned();

        let e = mnemonic.entropy();
        println!("e.len()={}", e.len());
        //println!("e={:?}", e);

        let shares: Vec<String> = mnemonic_to_shares(mnemonic, 5, 3)?
            .map(|share| share.to_base58())
            .collect();

        let mut i = 5;
        for share in shares.iter() {
            println!("share.len()={}", share.len());
            println!("share={}", share);
            let meta = get_share_meta(&unwrap!(Share::from_str(share)))?;
            assert_eq!(meta.language, Language::English);
            assert_eq!(meta.shares_count, 5);
            assert_eq!(meta.share_index, i);
            i -= 1;
            assert_eq!(meta.threshold, 3);
        }

        let reconstructed_mnemonic = mnemonic_from_shares(
            shares
                .into_iter()
                .map(|share| unwrap!(Share::from_str(&share))),
        )?;

        assert_eq!(&mnemonic_phrase, reconstructed_mnemonic.phrase());

        Ok(())
    }
}
