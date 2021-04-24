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
    mnemonic::Mnemonic,
};

/// Create dewif v1 file
pub fn create_dewif_v1(
    currency: Currency,
    log_n: u8,
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> String {
    write_dewif_v1_bip_ed25519(currency, log_n, passphrase, &mnemonic)
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
    write_dewif_v1_ed25519(currency, log_n, passphrase, &kp.public_key(), &kp.seed())
}

/// Write dewif v1 file content with algo Bip32-Ed25519
pub(super) fn write_dewif_v1_bip_ed25519(
    currency: Currency,
    log_n: u8,
    passphrase: &str,
    mnemonic: &Mnemonic,
) -> String {
    let mut bytes = [0u8; super::V1_BIP32_ED25519_BYTES_LEN];

    // Clear meta data
    bytes[..4].copy_from_slice(super::VERSION_V1); // 4
    let currency_code: u32 = currency.into();

    bytes[4..8].copy_from_slice(&currency_code.to_be_bytes()); // 4
    bytes[8] = log_n; // log_n
    bytes[9] = KeysAlgo::Bip32Ed25519.to_u8(); // algo

    // Prepare encrypted data
    let language_code = mnemonic.language().to_u8();
    let mnemonic_entropy = mnemonic.entropy();
    let mnemonic_entropy_len = mnemonic_entropy.len();
    let mnemonic_entropy_len_u8 = mnemonic_entropy_len as u8;
    let checksum = crate::hashs::Hash::compute_multipart(&[
        &[language_code, mnemonic_entropy_len_u8],
        mnemonic_entropy,
    ]);
    println!("checksum={}", hex::encode(&checksum.0[..8]));

    // Encrypt
    let mut bytes_to_encrypt = [0u8; 42];
    bytes_to_encrypt[0] = mnemonic.language().to_u8();
    bytes_to_encrypt[1] = mnemonic_entropy_len_u8;
    bytes_to_encrypt[2..(2 + mnemonic_entropy_len)].copy_from_slice(mnemonic_entropy);
    bytes_to_encrypt[34..].copy_from_slice(&checksum.0[..8]);
    crate::xor_cipher::xor_cipher(
        &bytes_to_encrypt,
        super::gen_xor_seed42(passphrase, log_n).as_ref(),
        &mut bytes[super::V1_BIP32_ED25519_UNENCRYPTED_BYTES_LEN
            ..(super::V1_BIP32_ED25519_UNENCRYPTED_BYTES_LEN + 42)],
    );

    base64::encode(bytes.as_ref())
}

/// Write dewif v1 file content with algo Ed25519
pub(super) fn write_dewif_v1_ed25519(
    currency: Currency,
    log_n: u8,
    passphrase: &str,
    public_key: &crate::keys::ed25519::PublicKey,
    seed: &crate::seeds::Seed32,
) -> String {
    let mut bytes = [0u8; super::V1_ED25519_BYTES_LEN];

    // Clear meta data
    bytes[..4].copy_from_slice(super::VERSION_V1); // 4
    let currency_code: u32 = currency.into();

    bytes[4..8].copy_from_slice(&currency_code.to_be_bytes()); // 4
    bytes[8] = log_n; // log_n
    bytes[9] = KeysAlgo::Ed25519.to_u8(); // algo

    // Encrypted data
    let mut bytes_to_encrypt = [0u8; 64];
    bytes_to_encrypt[..32].copy_from_slice(seed.as_ref()); // 32
    bytes_to_encrypt[32..].copy_from_slice(public_key.datas.as_ref()); // 32
    crate::xor_cipher::xor_cipher(
        &bytes_to_encrypt,
        super::gen_xor_seed64(passphrase, log_n).as_ref(),
        &mut bytes[super::V1_ED25519_UNENCRYPTED_BYTES_LEN..],
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

        let dewif_content = write_dewif_v1_ed25519(
            unwrap!(Currency::from_str("g1-test")),
            12,
            "toto titi tata",
            &keypair.public_key(),
            keypair.seed(),
        );
        println!("{}", dewif_content);
        assert_eq!(
            "AAAAARAAAAEMAAqqbWsirdvN0W7IkpmKdG/Zbt4ZszPx9VcWUu0o4cdxIZ4HHUybCVbyVmQL9Wid8KE6FCWeMRtr5OKAUKYwsNI=",
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
        let dewif_content = write_dewif_v1_ed25519(
            unwrap!(Currency::from_str("g1-test")),
            12,
            encryption_passphrase,
            &keypair.public_key(),
            keypair.seed(),
        );

        assert_eq!(
            "AAAAARAAAAEMALUJm4gAYvodNzw/CPBV4Pckm+pv1taVmMdXpbthi9YyDSu9ioexcFO1YJpKPKATZR5IMBpeOOnZkzhTb3k2SYo=",
            dewif_content
        )
    }

    #[test]
    fn test_write_dewif_v1_bip32() -> Result<(), crate::mnemonic::MnemonicError> {
        let mnemonic = Mnemonic::from_phrase(
            "crop cash unable insane eight faith inflict route frame loud box vibrant",
            crate::mnemonic::Language::English,
        )?;

        // Get user passphrase for DEWIF encryption
        let encryption_passphrase = "toto titi tata";

        // Serialize keypair in DEWIF format
        let dewif_content = write_dewif_v1_bip_ed25519(
            unwrap!(Currency::from_str("g1-test")),
            14,
            encryption_passphrase,
            &mnemonic,
        );

        assert_eq!(
            "AAAAARAAAAEOAVdFrhPxVIhaRvWaM7vMCKg3C8Tvpn66v+z/7frzCONBABhrDBygESqnEg==",
            dewif_content
        );

        Ok(())
    }
}
