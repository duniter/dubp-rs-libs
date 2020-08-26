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

pub mod bin_file;
mod block_hash;
mod block_number;
mod blockstamp;
mod bytes_traits;
mod currency_name;
pub mod errors;
mod unescape_str;

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
    pub use crate::errors::{DocumentSigsErr, StringErr};
    pub use crate::unescape_str::unescape_str;
    pub use thiserror::Error;
}

// Crate imports
pub(crate) use crate::prelude::*;
pub(crate) use dup_crypto::{bases::BaseConversionError, hashs::Hash, keys::SigError};
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use std::{
    cmp::Ordering,
    collections::HashMap,
    error::Error,
    fmt::{Debug, Display, Error as FmtError, Formatter},
    fs::File,
    io::Read,
    io::Write,
    path::Path,
    str::FromStr,
};
