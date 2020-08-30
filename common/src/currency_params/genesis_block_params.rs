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

//! Duniter protocol currency parameters in genesis block

mod v10;

pub use v10::BlockV10Parameters;

use crate::*;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
/// Currency parameters in genesis block
pub enum GenesisBlockParams {
    /// Currency parameters in genesis block v10
    V10(BlockV10Parameters),
}

#[derive(Debug, Clone, Error)]
/// Store error in block parameters parsing
pub enum ParseParamsError {
    /// ParseIntError
    #[error("Fail to parse params : {0}")]
    ParseIntError(std::num::ParseIntError),
    /// ParseFloatError
    #[error("Fail to parse params : {0}")]
    ParseFloatError(std::num::ParseFloatError),
}

impl From<std::num::ParseIntError> for ParseParamsError {
    fn from(err: std::num::ParseIntError) -> ParseParamsError {
        ParseParamsError::ParseIntError(err)
    }
}

impl From<std::num::ParseFloatError> for ParseParamsError {
    fn from(err: std::num::ParseFloatError) -> ParseParamsError {
        ParseParamsError::ParseFloatError(err)
    }
}
