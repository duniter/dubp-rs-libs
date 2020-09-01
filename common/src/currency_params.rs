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

//! DUBP protocol currency parameters

mod genesis_block_params;

pub use genesis_block_params::{BlockV10Parameters, GenesisBlockParams, ParseParamsError};

use crate::*;

/// Default value for sig_renew_period parameter
pub static DEFAULT_SIG_RENEW_PERIOD: &u64 = &5_259_600;
/// Default value for ms_period parameter
pub static DEFAULT_MS_PERIOD: &u64 = &5_259_600;
/// Default value for tx_window parameter
pub static DEFAULT_TX_WINDOW: &u64 = &604_800;
/// Default maximum roolback length
pub static DEFAULT_FORK_WINDOW_SIZE: &usize = &100;

#[derive(Copy, Clone, Debug, PartialEq)]
/// Currency parameters
pub struct CurrencyParameters {
    /// Protocol version
    pub protocol_version: usize,
    /// UD target growth rate (see Relative Theorie of Money)
    pub c: f64,
    /// Duration between the creation of two UD (in seconds)
    pub dt: u64,
    /// Amount of the initial UD
    pub ud0: usize,
    /// Minimum duration between the writing of 2 certifications from the same issuer (in seconds)
    pub sig_period: u64,
    /// Minimum duration between two renewals of the same certification
    pub sig_renew_period: u64,
    /// Maximum number of active certifications at the same time (for the same issuer)
    pub sig_stock: usize,
    /// Maximum retention period of a pending certification
    pub sig_window: u64,
    /// Time to expiry of written certification
    pub sig_validity: u64,
    /// Minimum number of certifications required to become a member
    pub sig_qty: usize,
    /// Maximum retention period of a pending identity
    pub idty_window: u64,
    /// Maximum retention period of a pending membership
    pub ms_window: u64,
    /// Maximum retention period of a pending transaction
    pub tx_window: u64,
    /// Percentage of referring members who must be within step_max steps of each member
    pub x_percent: f64,
    /// Time to expiry of written membership
    pub ms_validity: u64,
    /// Minimum duration between the writing of 2 memberships from the same issuer (in seconds)
    pub ms_period: u64,
    /// For a member to respect the distance rule,
    /// there must exist for more than x_percent % of the referring members
    /// a path of less than step_max steps from the referring member to the evaluated member.
    pub step_max: usize,
    /// Number of blocks used for calculating median time.
    pub median_time_blocks: usize,
    /// The average time for writing 1 block (wished time)
    pub avg_gen_time: u64,
    /// The number of blocks required to evaluate again PoWMin value
    pub dt_diff_eval: usize,
    /// The percent of previous issuers to reach for personalized difficulty
    pub percent_rot: f64,
    /// Time of first UD.
    pub ud_time0: u64,
    /// Time of first reevaluation of the UD.
    pub ud_reeval_time0: u64,
    /// Time period between two re-evaluation of the UD.
    pub dt_reeval: u64,
    /// Maximum roolback length
    pub fork_window_size: usize,
}

impl From<(&CurrencyName, BlockV10Parameters)> for CurrencyParameters {
    fn from(source: (&CurrencyName, BlockV10Parameters)) -> CurrencyParameters {
        let (currency_name, block_params) = source;
        let sig_renew_period = match currency_name.0.as_str() {
            "g1" => 5_259_600,
            "g1-test" => 5_259_600 / 5,
            _ => *DEFAULT_SIG_RENEW_PERIOD,
        };
        let ms_period = match currency_name.0.as_str() {
            "g1" => 5_259_600,
            "g1-test" => 5_259_600 / 5,
            _ => *DEFAULT_MS_PERIOD,
        };
        let tx_window = match currency_name.0.as_str() {
            "g1" => 604_800,
            "g1-test" => 604_800,
            _ => *DEFAULT_TX_WINDOW,
        };
        let fork_window_size = match currency_name.0.as_str() {
            "g1" => 100,
            "g1-test" => 100,
            _ => *DEFAULT_FORK_WINDOW_SIZE,
        };
        CurrencyParameters {
            protocol_version: 10,
            c: block_params.c,
            dt: block_params.dt,
            ud0: block_params.ud0,
            sig_period: block_params.sig_period,
            sig_renew_period,
            sig_stock: block_params.sig_stock,
            sig_window: block_params.sig_window,
            sig_validity: block_params.sig_validity,
            sig_qty: block_params.sig_qty,
            idty_window: block_params.idty_window,
            ms_window: block_params.ms_window,
            tx_window,
            x_percent: block_params.x_percent,
            ms_validity: block_params.ms_validity,
            ms_period,
            step_max: block_params.step_max,
            median_time_blocks: block_params.median_time_blocks,
            avg_gen_time: block_params.avg_gen_time,
            dt_diff_eval: block_params.dt_diff_eval,
            percent_rot: block_params.percent_rot,
            ud_time0: block_params.ud_time0,
            ud_reeval_time0: block_params.ud_reeval_time0,
            dt_reeval: block_params.dt_reeval,
            fork_window_size,
        }
    }
}

impl CurrencyParameters {
    /// Get max value of connectivity (=1/x_percent)
    pub fn max_connectivity(&self) -> f64 {
        1.0 / self.x_percent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_params() {
        let genesis_params = BlockV10Parameters {
            c: 0.0488,
            dt: 86_400,
            ud0: 1_000,
            sig_period: 432_000,
            sig_stock: 100,
            sig_window: 5_259_600,
            sig_validity: 63_115_200,
            sig_qty: 5,
            idty_window: 5_259_600,
            ms_window: 5_259_600,
            x_percent: 0.8,
            ms_validity: 31557600,
            step_max: 5,
            median_time_blocks: 24,
            avg_gen_time: 300,
            dt_diff_eval: 12,
            percent_rot: 0.67,
            ud_time0: 1_488_970_800,
            ud_reeval_time0: 1_490_094_000,
            dt_reeval: 15_778_800,
        };

        let currency_params_g1 =
            CurrencyParameters::from((&CurrencyName("g1".to_owned()), genesis_params));

        assert_eq!(
            CurrencyParameters {
                protocol_version: 10,
                c: 0.0488,
                dt: 86_400,
                ud0: 1_000,
                sig_period: 432_000,
                sig_renew_period: 5_259_600,
                sig_stock: 100,
                sig_window: 5_259_600,
                sig_validity: 63_115_200,
                sig_qty: 5,
                idty_window: 5_259_600,
                ms_window: 5_259_600,
                tx_window: 604_800,
                x_percent: 0.8,
                ms_validity: 31557600,
                ms_period: 5_259_600,
                step_max: 5,
                median_time_blocks: 24,
                avg_gen_time: 300,
                dt_diff_eval: 12,
                percent_rot: 0.67,
                ud_time0: 1_488_970_800,
                ud_reeval_time0: 1_490_094_000,
                dt_reeval: 15_778_800,
                fork_window_size: 100,
            },
            currency_params_g1,
        );

        let currency_params_gt =
            CurrencyParameters::from((&CurrencyName("g1-test".to_owned()), genesis_params));

        assert_eq!(
            CurrencyParameters {
                protocol_version: 10,
                c: 0.0488,
                dt: 86_400,
                ud0: 1_000,
                sig_period: 432_000,
                sig_renew_period: 5_259_600 / 5,
                sig_stock: 100,
                sig_window: 5_259_600,
                sig_validity: 63_115_200,
                sig_qty: 5,
                idty_window: 5_259_600,
                ms_window: 5_259_600,
                tx_window: 604_800,
                x_percent: 0.8,
                ms_validity: 31557600,
                ms_period: 5_259_600 / 5,
                step_max: 5,
                median_time_blocks: 24,
                avg_gen_time: 300,
                dt_diff_eval: 12,
                percent_rot: 0.67,
                ud_time0: 1_488_970_800,
                ud_reeval_time0: 1_490_094_000,
                dt_reeval: 15_778_800,
                fork_window_size: 100,
            },
            currency_params_gt,
        );

        let currency_params_default =
            CurrencyParameters::from((&CurrencyName(DEFAULT_CURRENCY.to_owned()), genesis_params));

        assert_eq!(
            CurrencyParameters {
                protocol_version: 10,
                c: 0.0488,
                dt: 86_400,
                ud0: 1_000,
                sig_period: 432_000,
                sig_renew_period: *DEFAULT_SIG_RENEW_PERIOD,
                sig_stock: 100,
                sig_window: 5_259_600,
                sig_validity: 63_115_200,
                sig_qty: 5,
                idty_window: 5_259_600,
                ms_window: 5_259_600,
                tx_window: *DEFAULT_TX_WINDOW,
                x_percent: 0.8,
                ms_validity: 31557600,
                ms_period: *DEFAULT_MS_PERIOD,
                step_max: 5,
                median_time_blocks: 24,
                avg_gen_time: 300,
                dt_diff_eval: 12,
                percent_rot: 0.67,
                ud_time0: 1_488_970_800,
                ud_reeval_time0: 1_490_094_000,
                dt_reeval: 15_778_800,
                fork_window_size: *DEFAULT_FORK_WINDOW_SIZE,
            },
            currency_params_default,
        );
    }
}
