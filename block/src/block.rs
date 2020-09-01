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
pub use v10::{DubpBlockV10, DubpBlockV10Stringified};

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
    /// Common time in block (also known as 'blockchain time')
    fn common_time(&self) -> u64;
    /// Compute hash
    fn compute_hash(&self) -> BlockHash {
        BlockHash(Hash::compute_str(&self.compute_will_hashed_string()))
    }
    /// Compute inner hash
    fn compute_inner_hash(&self) -> Hash {
        Hash::compute_str(&self.generate_compact_inner_text())
    }
    /// Compute the character string that will be hashed
    fn compute_will_hashed_string(&self) -> String;
    /// Compute the character string that will be signed
    fn compute_will_signed_string(&self) -> String;
    /// Get current frame size (in blocks)
    fn current_frame_size(&self) -> usize;
    /// Generate compact inner text (for compute inner_hash)
    fn generate_compact_inner_text(&self) -> String;
    /// Compute hash and save it in document
    fn generate_hash(&mut self);
    /// Compute inner hash and save it in document
    fn generate_inner_hash(&mut self);
    /// Get block hash
    fn hash(&self) -> Option<BlockHash>;
    /// Get block inner hash
    fn inner_hash(&self) -> Option<Hash>;
    /// Get number of compute members in the current frame
    fn issuers_count(&self) -> usize;
    /// Get number of members in wot
    fn members_count(&self) -> usize;
    /// Get block number
    fn number(&self) -> BlockNumber;
    /// Get common difficulty (PoW)
    fn pow_min(&self) -> usize;
    /// Get previous hash
    fn previous_hash(&self) -> Option<Hash>;
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
    fn sign(&mut self, signator: &SignatorEnum);
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
    dubp_block_fn!(compute_hash, BlockHash);
    dubp_block_fn!(compute_will_hashed_string, String);
    dubp_block_fn!(compute_will_signed_string, String);
    dubp_block_fn!(current_frame_size, usize);
    dubp_block_fn!(generate_compact_inner_text, String);
    dubp_block_fn_mut!(generate_hash);
    dubp_block_fn_mut!(generate_inner_hash);
    dubp_block_fn!(hash, Option<BlockHash>);
    dubp_block_fn!(inner_hash, Option<Hash>);
    dubp_block_fn!(issuers_count, usize);
    dubp_block_fn!(members_count, usize);
    dubp_block_fn!(common_time, u64);
    dubp_block_fn!(number, BlockNumber);
    dubp_block_fn!(pow_min, usize);
    dubp_block_fn!(previous_blockstamp, Blockstamp);
    dubp_block_fn!(previous_hash, Option<Hash>);
    dubp_block_fn_mut!(reduce);
    dubp_block_fn!(verify_inner_hash, Result<(), VerifyBlockHashError>);
    dubp_block_fn!(verify_signature, Result<(), SigError>);
    dubp_block_fn!(verify_hash, Result<(), VerifyBlockHashError>);
    #[inline]
    fn sign(&mut self, signator: &SignatorEnum) {
        match self {
            DubpBlock::V10(block) => block.sign(signator),
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
