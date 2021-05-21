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

//! Encrypt transaction comment

use crate::{
    keys::{
        ed25519::PublicKey,
        x25519::{diffie_hellman, X25519PublicKey, X25519SecretKey},
        KeyPair,
    },
    rand::{self, UnspecifiedRandError},
};
use arrayvec::{ArrayString, ArrayVec};
use std::convert::TryInto;
use thiserror::Error;

const MAGIC_VALUE: [u8; 2] = [0x27, 0xb6];
const MAX_ENCRYPTED_LEN: usize = MAX_MSG_LEN + 1;
const MAX_B64_LEN: usize = 255;
const MAX_LEN: usize = MAX_MSG_LEN + META_LEN + 1;
const MAX_MSG_LEN: usize = 170;
const META_LEN: usize = 4 + NONCE_LEN;
const NONCE_LEN: usize = 16;
const V1: u8 = 1;

type Nonce = [u8; NONCE_LEN];

/// Decrypt transaction comment error
#[derive(Clone, Debug, Error)]
pub enum DecryptTxCommentErr {
    /// Invalid base 64 encoding
    #[error("Invalid base 64 encoding: {0}")]
    Base64Err(base64::DecodeError),
    /// Too short
    #[error("Too short data")]
    TooShort,
    /// Too long
    #[error("Too long data")]
    TooLong,
    /// Malicious input
    #[error("malicious input")]
    MaliciousInput,
    /// Invalid utf8 message
    #[error("Invalid utf8 message: {0}")]
    Utf8Err(std::str::Utf8Error),
    /// Unsupported version
    #[error("Unsupported version")]
    UnsupportedVersion,
    /// Wrong format
    #[error("Wrong format")]
    WrongFormat,
    /// Wrong magic value
    #[error("Wrong magic value")]
    WrongMagicValue,
}

/// Shared key
#[allow(missing_copy_implementations)]
pub struct SharedKey([u8; 32]);

/// compute shared key
pub fn compute_shared_key<K: KeyPair>(my_keypair: &K, its_pubkey: &PublicKey) -> SharedKey {
    let precomputed_key = diffie_hellman(
        X25519SecretKey::from_bytes(my_keypair.scalar_bytes()),
        X25519PublicKey::from(its_pubkey),
        |shared_secret| {
            let mut buffer = [0; 32];
            cryptoxide::salsa20::hsalsa20(shared_secret, &[0; 16], &mut buffer);
            buffer
        },
    );

    let mut shared_key = SharedKey([0; 32]);
    shared_key.0.copy_from_slice(&precomputed_key[..]);
    shared_key
}

/// Read message type of an encrypted tx comment
pub fn get_message_type(
    encrypted_tx_comment: &ArrayString<MAX_B64_LEN>,
) -> Result<u8, DecryptTxCommentErr> {
    let (version, bytes) = verify_magic_value_and_read_version(encrypted_tx_comment)?;

    // Verify version
    if version != V1 {
        return Err(DecryptTxCommentErr::UnsupportedVersion);
    }

    // Verify length for meta data
    if bytes.len() <= META_LEN {
        return Err(DecryptTxCommentErr::TooShort);
    }

    // Read message type
    let message_type = bytes[3];

    Ok(message_type)
}

/// Decrypt transaction comment
pub fn decrypt_tx_comment<K: KeyPair>(
    my_keypair: &K,
    other_pubkey: &PublicKey,
    encrypted_tx_comment: &ArrayString<MAX_B64_LEN>,
) -> Result<ArrayString<MAX_MSG_LEN>, DecryptTxCommentErr> {
    let shared_key = compute_shared_key::<K>(my_keypair, other_pubkey);
    decrypt_tx_comment_with_shared_key(&shared_key, encrypted_tx_comment)
}

/// Decrypt transaction comment with specified shared key
pub fn decrypt_tx_comment_with_shared_key(
    shared_key: &SharedKey,
    encrypted_tx_comment: &ArrayString<MAX_B64_LEN>,
) -> Result<ArrayString<MAX_MSG_LEN>, DecryptTxCommentErr> {
    let (version, bytes) = verify_magic_value_and_read_version(encrypted_tx_comment)?;

    // Verify version
    if version != V1 {
        return Err(DecryptTxCommentErr::UnsupportedVersion);
    }

    // Verify length for meta data
    if bytes.len() <= META_LEN {
        return Err(DecryptTxCommentErr::TooShort);
    }

    // Read nonce
    let mut nonce = [0; NONCE_LEN];
    nonce.copy_from_slice(&bytes[4..20]);

    // Get encrypted data
    let encrypted_data = &bytes[META_LEN..];

    // Compute encryption key
    let mut encryption_key = ArrayVec::<u8, MAX_ENCRYPTED_LEN>::new();
    unsafe {
        encryption_key.set_len(encrypted_data.len());
    }
    crate::scrypt::scrypt(
        &shared_key.0[..],
        &nonce[..],
        &crate::scrypt::params::ScryptParams {
            log_n: 10,
            r: 8,
            p: 1,
        },
        &mut encryption_key,
    );

    // Decryption
    let mut decrypted_data = ArrayVec::<u8, MAX_ENCRYPTED_LEN>::new();
    for i in 0..encrypted_data.len() {
        decrypted_data.push(encryption_key[i] ^ encrypted_data[i]);
    }

    read_decrypted_data(decrypted_data.as_ref())
}

/// Encrypt transaction comment
pub fn encrypt_tx_comment_v1<K: KeyPair>(
    message_type: u8,
    my_keypair: &K,
    other_pubkey: &PublicKey,
    tx_comment: &ArrayString<MAX_MSG_LEN>,
) -> Result<ArrayString<MAX_B64_LEN>, UnspecifiedRandError> {
    let message_len = tx_comment.len();
    let message_len_plus_one = message_len + 1;

    // Prepare data to encrypt
    let mut data_to_encrypt = ArrayVec::<u8, MAX_ENCRYPTED_LEN>::new();
    data_to_encrypt.push(message_len as u8);
    data_to_encrypt
        .try_extend_from_slice(tx_comment.as_bytes())
        .unwrap_or_else(|_| unsafe { std::hint::unreachable_unchecked() });

    // Generate random extra bytes in data_to_encrypt directly
    let extra_bytes_len = rand::gen_u8()? % (MAX_MSG_LEN - message_len) as u8;
    let data_to_encrypt_len = message_len_plus_one + extra_bytes_len as usize;
    unsafe {
        data_to_encrypt.set_len(data_to_encrypt_len);
    }
    rand::gen_random_bytes(&mut data_to_encrypt[message_len_plus_one..])?;

    // Write meta data
    let mut bytes = ArrayVec::<u8, MAX_LEN>::new();
    bytes.push(MAGIC_VALUE[0]); // prefix
    bytes.push(MAGIC_VALUE[1]); // prefix
    bytes.push(V1);
    bytes.push(message_type); // message type

    // Generate and write nonce
    let nonce = gen_nonce()?;
    unsafe {
        bytes.set_len(META_LEN);
    }
    bytes[4..].copy_from_slice(&nonce[..]);

    // Compute encryption key
    let shared_key = compute_shared_key::<K>(my_keypair, other_pubkey);
    let mut encryption_key = ArrayVec::<u8, MAX_ENCRYPTED_LEN>::new();
    unsafe {
        encryption_key.set_len(data_to_encrypt_len);
    }
    crate::scrypt::scrypt(
        &shared_key.0[..],
        &nonce[..],
        &crate::scrypt::params::ScryptParams {
            log_n: 10,
            r: 8,
            p: 1,
        },
        &mut encryption_key,
    );

    // Encryption with XOR cipher
    for i in 0..data_to_encrypt_len {
        bytes.push(encryption_key[i] ^ data_to_encrypt[i]);
    }

    let mut b64_str = ArrayString::new();
    unsafe {
        b64_str.set_len(MAX_B64_LEN);
    }
    let bytes_written = base64::encode_config_slice(bytes, base64::STANDARD_NO_PAD, unsafe {
        b64_str.as_bytes_mut()
    });
    unsafe {
        b64_str.set_len(bytes_written);
    }

    Ok(b64_str)
}

#[cfg(not(test))]
fn gen_nonce() -> Result<Nonce, UnspecifiedRandError> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::rand::gen_random_bytes(&mut nonce[..])?;
    Ok(nonce)
}
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn gen_nonce() -> Result<Nonce, UnspecifiedRandError> {
    Ok([
        0x7f, 0xf8, 0xbc, 0x19, 0x0a, 0xb7, 0xd5, 0x46, 0x1d, 0xee, 0x47, 0xfc, 0x29, 0xde, 0xc9,
        0xf2,
    ])
}

fn read_decrypted_data(
    decrypted_data: &[u8],
) -> Result<ArrayString<MAX_MSG_LEN>, DecryptTxCommentErr> {
    // Read real message length
    let real_message_length = decrypted_data[0] as usize;

    // Verify real message length
    if real_message_length >= decrypted_data.len() {
        return Err(DecryptTxCommentErr::MaliciousInput);
    }

    std::str::from_utf8(&decrypted_data[1..=real_message_length])
        .map_err(DecryptTxCommentErr::Utf8Err)?
        .try_into()
        .map_err(|_| DecryptTxCommentErr::TooLong)
}

fn verify_magic_value_and_read_version(
    encrypted_tx_comment: &ArrayString<MAX_B64_LEN>,
) -> Result<(u8, ArrayVec<u8, MAX_LEN>), DecryptTxCommentErr> {
    // Decode base64
    let mut bytes = ArrayVec::new();
    unsafe {
        bytes.set_len(MAX_LEN);
    }
    let bytes_written = base64::decode_config_slice(
        encrypted_tx_comment.as_bytes(),
        base64::STANDARD_NO_PAD,
        &mut bytes,
    )
    .map_err(DecryptTxCommentErr::Base64Err)?;
    unsafe {
        bytes.set_len(bytes_written);
    }

    // Verify length for  magic value and version
    if bytes.len() < 3 {
        return Err(DecryptTxCommentErr::TooShort);
    }

    // Verify magic value
    if bytes[0] != MAGIC_VALUE[0] || bytes[1] != MAGIC_VALUE[1] {
        return Err(DecryptTxCommentErr::WrongMagicValue);
    }

    Ok((bytes[2], bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bases::b58::ToBase58,
        keys::{
            ed25519::{KeyPairFromSeed32Generator, PublicKey},
            PublicKey as _,
        },
        seeds::Seed32,
    };
    use unwrap::unwrap;

    #[test]
    fn test_read_malicious_decrypted_data() {
        let decrypted_data = &[42, 1];

        assert!(read_decrypted_data(decrypted_data).is_err());
    }

    #[test]
    fn test_decrypt_tx_comment() -> Result<(), DecryptTxCommentErr> {
        // Generate bob keypair
        let seed_bob = Seed32::new([
            33, 73, 85, 181, 88, 199, 121, 50, 104, 88, 158, 85, 126, 218, 42, 182, 155, 82, 147,
            183, 61, 57, 7, 248, 44, 130, 225, 45, 105, 196, 114, 33,
        ]);
        println!("seed_bob={}", hex::encode(&seed_bob));
        let kp_bob = KeyPairFromSeed32Generator::generate(seed_bob);
        assert_eq!(
            &kp_bob.public_key().to_base58(),
            "8txjWNFZhMJbKPijvnFybeksN1QpKaKJrM4jW8HhnFsX"
        );

        // Get alice pubkey
        let pk_alice = unwrap!(PublicKey::from_base58(
            "EVfy1VoZwbuN7L69kYiHxeosJLh5azkHV8G6TaSLy94r"
        ));

        // Compute thared secret
        let shared_key = compute_shared_key(&kp_bob, &pk_alice);

        // Get encrypted comment
        let encrypted_tx_comment = unwrap!(ArrayString::from("J7YBAH/4vBkKt9VGHe5H/CneyfKdagW5oo8oh6cGBE5PRmb/rJs7LiXal4hnsS6+sry/4Hwny0iFLSEgXuPNIJk2"));

        // Decrypt comment
        let tx_comment = decrypt_tx_comment_with_shared_key(&shared_key, &encrypted_tx_comment)?;

        assert_eq!(
            tx_comment.as_str(),
            "My taylor is rich ? Isn't it ? Un été 42..."
        );

        Ok(())
    }

    #[test]
    fn test_encrypt_tx_comment() {
        // Generate alice keypair
        let seed_alice = Seed32::new([
            12, 106, 21, 208, 0, 77, 36, 164, 15, 101, 3, 48, 13, 73, 113, 3, 47, 176, 87, 255,
            125, 194, 41, 214, 81, 104, 59, 65, 60, 150, 162, 22,
        ]);
        println!("seed_alice={}", hex::encode(&seed_alice));
        let kp_alice = KeyPairFromSeed32Generator::generate(seed_alice);
        assert_eq!(
            &kp_alice.public_key().to_base58(),
            "EVfy1VoZwbuN7L69kYiHxeosJLh5azkHV8G6TaSLy94r"
        );

        // Get bob pubkey
        let pk_bob = unwrap!(PublicKey::from_base58(
            "8txjWNFZhMJbKPijvnFybeksN1QpKaKJrM4jW8HhnFsX"
        ));

        // Create tx comment
        let tx_comment = unwrap!(ArrayString::from(
            "My taylor is rich ? Isn't it ? Un été 42..."
        ));
        println!("tx_comment_len={}", tx_comment.len());

        // Encrypt comment
        let encrypted_comment = unwrap!(encrypt_tx_comment_v1(0, &kp_alice, &pk_bob, &tx_comment));
        println!("encrypted_comment={}", encrypted_comment);
        assert_eq!(
            &encrypted_comment[..88], // 88 b64 chars encode 66 octets (21 mate data + 45 comment)
            "J7YBAH/4vBkKt9VGHe5H/CneyfKdagW5oo8oh6cGBE5PRmb/rJs7LiXal4hnsS6+sry/4Hwny0iFLSEgXuPNIJk2"
        );

        //
    }

    #[test]
    fn test_cryptobox_shared_key() {
        use crate::keys::ed25519::Ed25519KeyPair;
        use crate::keys::inner::KeyPairInner;
        use sodiumoxide::crypto::box_;
        use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey as SodiumPublicKey;
        use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey as SodiumSecretKey;

        let kp1 = unwrap!(Ed25519KeyPair::generate_random());
        let kp2 = unwrap!(Ed25519KeyPair::generate_random());

        let sk1 = X25519SecretKey::from_bytes(kp1.scalar_bytes());
        let sk2 = X25519SecretKey::from_bytes(kp2.scalar_bytes());
        let pk1 = X25519PublicKey::from(&kp1.public_key());
        let pk2 = X25519PublicKey::from(&kp2.public_key());

        let our_precomputed_key =
            box_::precompute(&SodiumPublicKey((pk2.0).0), &SodiumSecretKey(sk1.0));
        let their_precomputed_key =
            box_::precompute(&SodiumPublicKey((pk1.0).0), &SodiumSecretKey(sk2.0));

        assert_eq!(our_precomputed_key.0, their_precomputed_key.0);

        let shared_key = compute_shared_key(&kp1, &kp2.public_key());
        assert_eq!(&shared_key.0[..], &their_precomputed_key.0[..]);
        let shared_key = compute_shared_key(&kp2, &kp1.public_key());
        assert_eq!(&shared_key.0[..], &their_precomputed_key.0[..]);

        let precomputed_key = diffie_hellman(sk1, pk2, |shared_secret| {
            let mut buffer = [0; 32];
            cryptoxide::salsa20::hsalsa20(shared_secret, &[0; 16], &mut buffer);
            buffer
        });
        assert_eq!(&precomputed_key[..], &their_precomputed_key.0[..]);
    }
}
