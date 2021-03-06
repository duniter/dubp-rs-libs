//  Copyright (C) 2017-2019  The AXIOM TEAM Association.
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

//! Wrappers around Block document.

pub mod v10;

use crate::*;
use dubp_documents::dubp_wallet::prelude::SourceAmount;
pub use v10::{
    DubpBlockV10, DubpBlockV10AfterPowData, DubpBlockV10Builder, DubpBlockV10Content,
    DubpBlockV10Stringified,
};

/// Wrap a Block document.
///
/// Must be created by parsing a text document or using a builder.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum DubpBlock {
    V10(DubpBlockV10),
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// Error when verifying a hash of a block
pub enum VerifyBlockHashError {
    /// The hash is missing
    MissingHash { block_number: BlockNumber },
    /// Hash is invalid
    InvalidHash {
        block_number: BlockNumber,
        expected_hash: Hash,
        actual_hash: Hash,
    },
}

pub trait DubpBlockTrait {
    type Signator: Signator;

    /// Common time in block (also known as 'blockchain time')
    fn common_time(&self) -> u64;
    /// Compute hash
    fn compute_hash(&self) -> BlockHash {
        BlockHash(Hash::compute(self.compute_hashed_string().as_bytes()))
    }
    /// Compute inner hash
    fn compute_inner_hash(&self) -> Hash {
        Hash::compute(&self.generate_compact_inner_text().as_bytes())
    }
    /// Compute the character string that hashed
    fn compute_hashed_string(&self) -> String;
    /// Compute the character string that will be signed
    fn compute_signed_string(&self) -> String;
    /// Get currency name
    fn currency_name(&self) -> CurrencyName;
    /// Get currency parameters
    fn currency_parameters(&self) -> Option<CurrencyParameters>;
    /// Get current frame size (in blocks)
    fn current_frame_size(&self) -> usize;
    /// Get universal dividend amount
    fn dividend(&self) -> Option<SourceAmount>;
    /// Generate compact inner text (for compute inner_hash)
    fn generate_compact_inner_text(&self) -> String;
    /// Get block hash
    fn hash(&self) -> BlockHash;
    /// Get block inner hash
    fn inner_hash(&self) -> Hash;
    /// Get block issuer
    fn issuer(&self) -> <Self::Signator as Signator>::PublicKey;
    /// Get number of compute members in the current frame
    fn issuers_count(&self) -> usize;
    /// Get size of the current frame (in blocks)
    fn issuers_frame(&self) -> usize;
    /// Get local time
    fn local_time(&self) -> u64;
    /// Get number of members in wot
    fn members_count(&self) -> usize;
    /// Get monetary mass
    fn monetary_mass(&self) -> u64;
    /// Get block nonce
    fn nonce(&self) -> u64;
    /// Get block number
    fn number(&self) -> BlockNumber;
    /// Get common difficulty (PoW)
    fn pow_min(&self) -> usize;
    /// Get previous hash
    fn previous_hash(&self) -> Hash;
    /// Get previous blockstamp
    fn previous_blockstamp(&self) -> Blockstamp;
    /// Lightens the block (for example to store it while minimizing the space required)
    fn reduce(&mut self);
    /// Verify inner hash
    fn verify_inner_hash(&self) -> Result<(), VerifyBlockHashError>;
    /// Verify signature
    fn verify_signature(&self) -> Result<(), SigError>;
    /// Verify block hash
    fn verify_hash(&self) -> Result<(), VerifyBlockHashError>;
    /// Sign block
    fn sign(&mut self, signator: &Self::Signator) -> Result<(), SignError>;
    /// Get block signature
    fn signature(&self) -> <<Self::Signator as Signator>::PublicKey as PublicKey>::Signature;
    /// Get unit base
    fn unit_base(&self) -> usize;
}

macro_rules! dubp_block_fn {
    ($fn_name:ident, $return_type:ty) => {
        #[inline(always)]
        fn $fn_name(&self) -> $return_type {
            match self {
                DubpBlock::V10(block) => block.$fn_name(),
            }
        }
    };
}
macro_rules! dubp_block_fn_mut {
    ($fn_name:ident) => {
        #[inline(always)]
        fn $fn_name(&mut self) {
            match self {
                DubpBlock::V10(block) => block.$fn_name(),
            }
        }
    };
}

impl DubpBlockTrait for DubpBlock {
    type Signator = SignatorEnum;

    dubp_block_fn!(compute_hash, BlockHash);
    dubp_block_fn!(compute_hashed_string, String);
    dubp_block_fn!(compute_signed_string, String);
    dubp_block_fn!(currency_name, CurrencyName);
    dubp_block_fn!(currency_parameters, Option<CurrencyParameters>);
    dubp_block_fn!(current_frame_size, usize);
    dubp_block_fn!(dividend, Option<SourceAmount>);
    dubp_block_fn!(generate_compact_inner_text, String);
    dubp_block_fn!(hash, BlockHash);
    dubp_block_fn!(inner_hash, Hash);
    dubp_block_fn!(issuers_count, usize);
    dubp_block_fn!(issuers_frame, usize);
    dubp_block_fn!(local_time, u64);
    dubp_block_fn!(members_count, usize);
    dubp_block_fn!(monetary_mass, u64);
    dubp_block_fn!(common_time, u64);
    dubp_block_fn!(nonce, u64);
    dubp_block_fn!(number, BlockNumber);
    dubp_block_fn!(pow_min, usize);
    dubp_block_fn!(previous_blockstamp, Blockstamp);
    dubp_block_fn!(previous_hash, Hash);
    dubp_block_fn_mut!(reduce);
    dubp_block_fn!(verify_inner_hash, Result<(), VerifyBlockHashError>);
    dubp_block_fn!(verify_signature, Result<(), SigError>);
    dubp_block_fn!(verify_hash, Result<(), VerifyBlockHashError>);
    dubp_block_fn!(unit_base, usize);
    #[inline]
    fn issuer(&self) -> PubKeyEnum {
        match self {
            DubpBlock::V10(block) => PubKeyEnum::Ed25519(block.issuer()),
        }
    }
    #[inline]
    fn sign(&mut self, signator: &Self::Signator) -> Result<(), SignError> {
        match self {
            DubpBlock::V10(block) => {
                if let SignatorEnum::Ed25519(ed25519_signator) = signator {
                    block.sign(ed25519_signator)
                } else {
                    Err(SignError::WrongAlgo)
                }
            }
        }
    }
    #[inline]
    fn signature(&self) -> Sig {
        match self {
            DubpBlock::V10(block) => Sig::Ed25519(block.signature()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DubpBlockStringified {
    V10(DubpBlockV10Stringified),
}

impl ToStringObject for DubpBlock {
    type StringObject = DubpBlockStringified;

    fn to_string_object(&self) -> Self::StringObject {
        match self {
            DubpBlock::V10(block) => DubpBlockStringified::V10(block.to_string_object()),
        }
    }
}
