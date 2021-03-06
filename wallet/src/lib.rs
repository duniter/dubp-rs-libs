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

//! Define DUBP Wallet.

#![deny(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces
)]

mod script;
mod source;

// re-export crates
pub use dubp_common;
pub use smallvec;

// prelude
pub mod prelude {
    pub use crate::script::v10::{
        ScriptNeverUnlockableError, WalletConditionV10, WalletScriptNodesV10, WalletScriptV10,
        WalletSubScriptV10, WalletUnlockProofV10,
    };
    pub use crate::source::v10::{
        SourceIdV10, SourceV10, SourceV10NotUnlockableError, UdSourceIdV10, UtxoIdV10,
    };
    pub use crate::source::SourceAmount;
}

// Crate imports
pub(crate) use crate::prelude::*;
pub(crate) use dubp_common::crypto::hashs::Hash;
pub(crate) use dubp_common::crypto::keys::ed25519::PublicKey;
pub(crate) use dubp_common::prelude::*;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use smallvec::SmallVec;
pub(crate) use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    iter::Sum,
    ops::{Add, Sub},
};
pub(crate) use thiserror::Error;
