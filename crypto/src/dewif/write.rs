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
use crate::{
    keys::{ed25519::SaltedPassword, KeyPair as _, KeysAlgo},
    mnemonic::{mnemonic_to_seed, Mnemonic},
};
use arrayvec::ArrayVec;
use std::hint::unreachable_unchecked;

/// Create dewif v1 file
pub fn create_dewif_v1(
    currency: Currency,
    log_n: u8,
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> String {
    let seed = mnemonic_to_seed(mnemonic);
    let kp = crate::keys::ed25519::bip32::KeyPair::from_seed(seed.clone());
    write_dewif_v1_content(
        currency,
        KeysAlgo::Bip32Ed25519,
        log_n,
        passphrase,
        &kp.public_key(),
        &seed,
    )
}

/// Create dewif v1 file from legacy credentials (salt + password)
/// This funtion is deprected, use it for compatibility purpose only!
#[deprecated]
pub fn create_dewif_v1_legacy(
    currency: Currency,
    log_n: u8,
    password: String,
    salt: String,
    passphrase: &str,
) -> String {
    let kp = crate::keys::ed25519::KeyPairFromSaltedPasswordGenerator::with_default_parameters()
        .generate(SaltedPassword::new(salt, password));
    write_dewif_v1_content(
        currency,
        KeysAlgo::Ed25519,
        log_n,
        passphrase,
        &kp.public_key(),
        &kp.seed(),
    )
}

/// Write dewif v1 file content with user passphrase
pub(super) fn write_dewif_v1_content(
    currency: Currency,
    algo: KeysAlgo,
    log_n: u8,
    passphrase: &str,
    public_key: &crate::keys::ed25519::PublicKey,
    seed: &crate::seeds::Seed32,
) -> String {
    let mut bytes = ArrayVec::<[u8; super::V1_BYTES_LEN]>::new();
    bytes
        .try_extend_from_slice(super::VERSION_V1) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    let currency_code: u32 = currency.into();

    bytes
        .try_extend_from_slice(&currency_code.to_be_bytes()) // 4
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes.push(log_n); // log_n
    bytes.push(algo.to_u8()); // algo
    bytes
        .try_extend_from_slice(seed.as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });
    bytes
        .try_extend_from_slice(public_key.datas.as_ref()) // 32
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() });

    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase, log_n));
    crate::aes256::encrypt::encrypt_n_blocks(
        &cipher,
        &mut bytes[super::V1_UNENCRYPTED_BYTES_LEN..],
        super::V1_AES_BLOCKS_COUNT,
    );

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
        println!("pubkey={}", keypair.public_key());

        let dewif_content = write_dewif_v1_content(
            unwrap!(Currency::from_str("g1-test")),
            KeysAlgo::Ed25519,
            12,
            "toto titi tata",
            &keypair.public_key(),
            keypair.seed(),
        );
        println!("{}", dewif_content);
        assert_eq!(
            "AAAAARAAAAEMAN9vzS8DfK3ZePpXUgyV0Vbfb80vA3yt2Xj6V1IMldFWYQlZxHGWyI07G49EiViJqAhMGenY9DP6Svbh62bOAbE=",
            dewif_content
        )
    }

    #[test]
    fn write_dewif_v1_legacy_credentials() {
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

        // Serialize keypair in DEWIF format
        let dewif_content = write_dewif_v1_content(
            unwrap!(Currency::from_str("g1-test")),
            KeysAlgo::Ed25519,
            12,
            encryption_passphrase,
            &keypair.public_key(),
            keypair.seed(),
        );

        assert_eq!(
            "AAAAARAAAAEMAJ8UMCz6NVliR+EGUdlnZ8RAi8GqcbXqDn7TZxjXzBI6NbRxSDYlXdJRMlg3YKttB5EPAZrNafNIUGmFyEyaIvQ=",
            dewif_content
        )
    }

    #[test]
    fn test_write_dewif_v1_bip32() {
        use crate::keys::ed25519::bip32::KeyPair;

        let seed = unwrap!(Seed32::from_base58(
            "DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV"
        ));
        println!("seed: {}", hex::encode(seed.as_ref()));

        // Generate BIP32-Ed25519 keypair
        let keypair = KeyPair::from_seed(seed.clone());

        println!("pubkey: {}", keypair.public_key());
        println!("pubkey bytes: {:?}", keypair.public_key().as_ref());
        println!("pubkey hex: {}", hex::encode(keypair.public_key()));

        // Get user passphrase for DEWIF encryption
        let encryption_passphrase = "toto titi tata";

        // Serialize keypair in DEWIF format
        let dewif_content = write_dewif_v1_content(
            unwrap!(Currency::from_str("g1-test")),
            KeysAlgo::Bip32Ed25519,
            15,
            encryption_passphrase,
            &keypair.public_key(),
            &seed,
        );

        assert_eq!(
            "AAAAARAAAAEPAXBN8l4QNE9IhJV0f7w22U0UpnXnNupVruNplirmnM88WdtmyBlXy5pYX1VvTVplmO5vz/49FukruEGRIhEXvLw=",
            dewif_content
        )
    }
}
