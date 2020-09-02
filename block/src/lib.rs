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

mod block;
pub mod parser;

// Prelude
pub mod prelude {
    pub use crate::block::{
        DubpBlock, DubpBlockTrait, DubpBlockV10, DubpBlockV10Stringified, VerifyBlockHashError,
    };
}

// Crate imports
pub(crate) use crate::prelude::*;
pub(crate) use dubp_documents::dubp_common::crypto::bases::BaseConversionError;
pub(crate) use dubp_documents::dubp_common::crypto::hashs::Hash;
pub(crate) use dubp_documents::dubp_common::crypto::keys::*;
pub(crate) use dubp_documents::dubp_common::currency_params::*;
pub(crate) use dubp_documents::dubp_common::prelude::*;
pub(crate) use dubp_documents::membership::v10::MembershipType;
pub(crate) use dubp_documents::prelude::*;
pub(crate) use dubp_documents_parser::prelude::*;
pub(crate) use log::{error, warn};
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde_json::Value;
pub(crate) use std::{collections::HashMap, convert::TryFrom, str::FromStr};
pub(crate) use thiserror::Error;

pub use block::{
    DubpBlock, DubpBlockStringified, DubpBlockV10, DubpBlockV10AfterPowData, DubpBlockV10Builder,
    DubpBlockV10Content, DubpBlockV10Stringified,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use unwrap::unwrap;

    pub(crate) fn pk(pk_b58: &str) -> ed25519::PublicKey {
        unwrap!(ed25519::PublicKey::from_base58(pk_b58))
    }
}
