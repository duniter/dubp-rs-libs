//! Provide common tools for DUBP.

#![deny(
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces
)]

mod block_hash;
mod block_number;
mod blockstamp;
mod bytes_traits;
mod currency_name;
pub mod errors;
/*pub mod parser;
pub mod traits;*/

// Re export crates
pub use dup_crypto as crypto;

// Prelude
pub mod prelude {
    pub use crate::block_hash::BlockHash;
    pub use crate::block_number::BlockNumber;
    pub use crate::blockstamp::{
        Blockstamp, BlockstampFromBytesError, BlockstampParseError, PreviousBlockstamp,
    };
    pub use crate::bytes_traits::{AsBytes, FromBytes};
    pub use crate::currency_name::CurrencyName;
    pub use crate::errors::StringErr;
    pub use thiserror::Error;
}

// Crate imports
pub(crate) use crate::prelude::*;
pub(crate) use dup_crypto::{bases::BaseConversionError, hashs::Hash};
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use std::{
    cmp::Ordering,
    error::Error,
    fmt::{Debug, Display, Error as FmtError, Formatter},
    str::FromStr,
};
