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
use std::hint::unreachable_unchecked;

/// Write dewif v1 file content with user passphrase
pub fn write_dewif_v1_content(
    currency: Currency,
    keypair: &Ed25519KeyPair,
    passphrase: &str,
) -> String {
    let mut bytes = ArrayVec::<[u8; super::V1_BYTES_LEN]>::new();
    bytes
        .try_extend_from_slice(super::VERSION_V1) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    let currency_code: u32 = currency.into();

    bytes
        .try_extend_from_slice(&currency_code.to_be_bytes()) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair.seed().as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair.public_key().datas.as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });

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
    bytes
        .try_extend_from_slice(super::VERSION_V2) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    let currency_code: u32 = currency.into();
    bytes
        .try_extend_from_slice(&currency_code.to_be_bytes()) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair1.seed().as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair1.public_key().datas.as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair2.seed().as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(keypair2.public_key().datas.as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });

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
    use unwrap::unwrap;

    #[test]
    fn write_dewif_v1_seed() {
        let keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));

        let dewif_content = write_dewif_v1_content(Currency::none(), &keypair, "toto");
        println!("{}", dewif_content);
        assert_eq!(
            "AAAAAQAAAABV0QsqZJF91QDICeFgrn2MVdELKmSRfdUAyAnhYK59jJNqW1MhiUWqCmepOHFC8tawkY8aqYHe5M5ia/n6S2Ph",
            dewif_content
        )
    }

    #[test]
    fn write_dewif_v1_credentials() {
        use crate::dewif::write_dewif_v1_content;
        use crate::keys::ed25519::{KeyPairFromSaltedPasswordGenerator, SaltedPassword};

        // Get user credentials (from cli prompt or gui)
        let credentials = SaltedPassword::new("user salt".to_owned(), "user password".to_owned());

        // Generate ed25519 keypair
        let keypair =
            KeyPairFromSaltedPasswordGenerator::with_default_parameters().generate(credentials);

        println!("seed: {}", hex::encode(keypair.seed()));
        println!("pubkey bytes: {:?}", keypair.public_key().as_ref());
        println!("pubkey hex: {}", hex::encode(keypair.public_key()));

        // Get user passphrase for DEWIF encryption
        let encryption_passphrase = "toto titi tata";

        // Expected currency
        let expected_currency = unwrap!(Currency::from_str("g1-test"));

        // Serialize keypair in DEWIF format
        let dewif_content =
            write_dewif_v1_content(expected_currency, &keypair, encryption_passphrase);

        assert_eq!(
            "AAAAARAAAAF0y4EVcXgLoZk8awkOI8FtpylUp5ougnCQOy6ouOTCh/VzvrRnmJWmdmUu3lcQWUR6Ft20uWVWFxx/04rpmOfw",
            dewif_content
        )
    }
}
