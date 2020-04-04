//  Copyright (C) 2020 Éloïs SANCHEZ.
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

//! Write [DEWIF](https://git.duniter.org/nodes/common/doc/blob/dewif/rfc/0013_Duniter_Encrypted_Wallet_Import_Format.md) file content

use super::Currency;
use crate::keys::ed25519::Ed25519KeyPair;
use crate::keys::KeyPair;
use arrayvec::ArrayVec;
use unwrap::unwrap;

/// Write dewif v1 file content with user passphrase
pub fn write_dewif_v1_content(
    currency: Currency,
    keypair: &Ed25519KeyPair,
    passphrase: &str,
) -> String {
    let mut bytes = ArrayVec::<[u8; super::V1_BYTES_LEN]>::new();
    unwrap!(bytes.try_extend_from_slice(super::VERSION_V1));
    let currency_code: u32 = currency.into();
    unwrap!(bytes.try_extend_from_slice(&currency_code.to_be_bytes()));
    unwrap!(bytes.try_extend_from_slice(keypair.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair.public_key().datas.as_ref()));

    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::encrypt::encrypt_n_blocks(
        &cipher,
        &mut bytes[super::UNENCRYPTED_BYTES_LEN..],
        super::V1_AES_BLOCKS_COUNT,
    );

    base64::encode(bytes.as_ref())
}

/// Write dewif v2 file content with user passphrase
pub fn write_dewif_v2_content(
    currency: Currency,
    keypair1: &Ed25519KeyPair,
    keypair2: &Ed25519KeyPair,
    passphrase: &str,
) -> String {
    let mut bytes = ArrayVec::<[u8; super::V2_BYTES_LEN]>::new();
    unwrap!(bytes.try_extend_from_slice(super::VERSION_V2));
    let currency_code: u32 = currency.into();
    unwrap!(bytes.try_extend_from_slice(&currency_code.to_be_bytes()));
    unwrap!(bytes.try_extend_from_slice(keypair1.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair1.public_key().datas.as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair2.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair2.public_key().datas.as_ref()));

    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::encrypt::encrypt_8_blocks(&cipher, &mut bytes[super::UNENCRYPTED_BYTES_LEN..]);

    base64::encode(bytes.as_ref())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::seeds::Seed32;
    use std::str::FromStr;

    #[test]
    fn write_dewif_v1() {
        let keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));

        let dewif_content = write_dewif_v1_content(Currency::none(), &keypair, "toto");
        println!("{}", dewif_content);
        assert_eq!(
            "AAAAAQAAAAC99J4N5CPUBjG0e02Aqj4UvfSeDeQj1AYxtHtNgKo+FBJYqJ2hzrdJL/nmloBkhpKz9S0H7sIr7r4O/vZ9IHdf",
            dewif_content
        )
    }

    #[test]
    fn write_ok() {
        use crate::dewif::write_dewif_v1_content;
        use crate::keys::ed25519::{KeyPairFromSaltedPasswordGenerator, SaltedPassword};

        // Get user credentials (from cli prompt or gui)
        let credentials = SaltedPassword::new("user salt".to_owned(), "user password".to_owned());

        // Generate ed25519 keypair
        let keypair =
            KeyPairFromSaltedPasswordGenerator::with_default_parameters().generate(credentials);

        // Get user passphrase for DEWIF encryption
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = Currency::from_str("g1-test").expect("unknown currency");

        // Serialize keypair in DEWIF format
        let dewif_content =
            write_dewif_v1_content(expected_currency, &keypair, encryption_passphrase);

        assert_eq!(
            "AAAAARAAAAEx3yd707xD3F5ttjcISbZzXRrko4pKUmCDIF/emfcVU9MvBqCJQS9R2sWlqbtI1Q37sLQhkj/W7tqY+hxm7mFQ",
            dewif_content
        )
    }
}
