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

//! Define duniter peer card.

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

pub(crate) use dubp_common::{
    crypto::{
        bases::b58::ToBase58,
        keys::{
            ed25519::{PublicKey, Signature},
            PublicKey as _, Signature as _,
        },
    },
    prelude::*,
};
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use smallvec::SmallVec;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct PeerV10 {
    pub currency: String,
    pub pubkey: PublicKey,
    pub blockstamp: Blockstamp,
    pub endpoints: SmallVec<[String; 4]>,
    pub signature: Signature,
}

impl PeerV10 {
    pub fn to_raw_string(&self) -> String {
        format!(
            "{}{}\n",
            self.to_raw_unsigned_string(),
            self.signature.to_base64(),
        )
    }
    fn to_raw_unsigned_string(&self) -> String {
        format!(
            "Version: 10\nType: Peer\nCurrency: {}\nPublicKey: {}\nBlock: {}\nEndpoints:\n{}\n",
            self.currency,
            self.pubkey.to_base58(),
            self.blockstamp,
            self.endpoints.join("\n"),
        )
    }
    pub fn verify_sig(&self) -> Result<(), dubp_common::crypto::keys::SigError> {
        self.pubkey
            .verify(self.to_raw_unsigned_string().as_bytes(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use std::str::FromStr;
    use unwrap::unwrap;

    #[test]
    fn test_peer_sig() {
        let peer = PeerV10 {
            currency: "g1".to_owned(),
            pubkey: unwrap!(PublicKey::from_base58("8iVdpXqFLCxGyPqgVx5YbFSkmWKkceXveRd2yvBKeARL")),
            blockstamp: unwrap!(Blockstamp::from_str("423354-00000033A87209DC21BD643088ED8AD52464A80C04BE3F8FBFA4291A9999BE50")),
            endpoints: smallvec![
                "BMAS g1.duniter.org 443".to_owned(),
                "BASIC_MERKLED_API 91.121.157.13 10901".to_owned(),
                "WS2P e66254bf g1.duniter.org 443 ws2p".to_owned()
            ],
            signature: unwrap!(Signature::from_base64("qr6Cnr/Qsgw/clbt0LbdkaFaUwhdgBJw5Fzpn8EhI9zM5/rGbVF6kqiB5pRJxf17XtI45qQ7H7SBbl8X2kAtCA==")),
        };

        let peer_raw = peer.to_raw_unsigned_string();
        assert_eq!(
            &peer_raw,
            "Version: 10\nType: Peer\nCurrency: g1\nPublicKey: 8iVdpXqFLCxGyPqgVx5YbFSkmWKkceXveRd2yvBKeARL\nBlock: 423354-00000033A87209DC21BD643088ED8AD52464A80C04BE3F8FBFA4291A9999BE50\nEndpoints:\nBMAS g1.duniter.org 443\nBASIC_MERKLED_API 91.121.157.13 10901\nWS2P e66254bf g1.duniter.org 443 ws2p\n",
        );
        assert!(peer.verify_sig().is_ok());
    }
}
