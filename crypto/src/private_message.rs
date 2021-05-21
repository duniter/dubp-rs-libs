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

//! Private message encryption/decryption
//!
//! ## Encrypt a private message (sender side)
//!
//! **Warning**: Take the time to study which is the authentication policy adapted to **your specific use case**.
//! Choosing an unsuitable authentication policy can be **dramatic for your end users**.
//! Read the documentation of [AuthenticationPolicy](./enum.AuthenticationPolicy.html).
//!
//! ```;
//! use dup_crypto::keys::{
//!     KeyPair, PublicKey,
//!     ed25519::{KeyPairFromSeed32Generator, PublicKey as Ed25519PublicKey}
//! };
//! use dup_crypto::private_message::{ChaChaRounds, AuthenticationPolicy, METADATA_LEN};
//! use dup_crypto::seeds::Seed32;
//!
//! // Take the time to study which is the authentication policy adapted
//! // to your specific use case.
//! // Read `dup_crypto::private_message::AuthenticationPolicy` documentation.
//! let authentication_policy = AuthenticationPolicy::PrivateAuthentication;
//!
//! // Regardless of the authentication policy chosen, the sender's key-pair is required.
//! let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::new([42u8; 32]));
//!
//! // Choose number of chacha rounds.
//! let chacha_rounds = ChaChaRounds::ChaCha20;
//!
//! // Aad value must be known by the software that will decipher the message, it can be the
//! // name of the service followed by the name of the network (name of the currency for example).
//! // This field is only used to ensure that there is no interference between different services
//! // and/or networks.
//! let aad = b"service name - currency name";
//!
//! // Define receiver and message content
//! // The message must be mutable because for performance reasons the encryption is applied
//! // directly to the bytes of the message (the message is never copied).
//! let receiver_public_key = Ed25519PublicKey::from_base58(
//!     "8hgzaeFnjkNCsemcaL4rmhB2999B79BydtE8xow4etB7"
//! ).expect("invalid public key");
//! let message = b"This is a secret message, which can only be read by the recipient.";
//!
//! // It is up to you to create the buffer that will contain the encrypted message.
//! // This gives you the freedom to choose how to allocate the memory space and in
//! // which type of "container" to store the bytes of the encrypted message.
//! // Metadata needed for decryption and authentication will be added to your message,
//! // you must make sure that your buffer has enough capacity to hold this metadata.
//! let mut buffer: Vec<u8> = Vec::with_capacity(message.len() + METADATA_LEN);
//! buffer.extend(&message[..]);
//!
//! // Finally, authenticate and encrypt the message.
//! dup_crypto::private_message::encrypt_private_message(
//!     aad,
//!     authentication_policy,
//!     chacha_rounds,
//!     &mut buffer,
//!     &receiver_public_key,
//!     &sender_key_pair,
//! )?;
//!
//! // Send message to the recipient by any way..
//!
//! # Ok::<(), dup_crypto::private_message::PrivateMessageError>(())
//! ```
//!
//! ## Decrypt a private message (receiver side)
//!
//! ```
//! use dup_crypto::keys::{KeyPair, ed25519::KeyPairFromSeed32Generator};
//! use dup_crypto::private_message::{ChaChaRounds, DecryptedMessage};
//! use dup_crypto::seeds::Seed32;
//!
//! let receiver_key_pair = KeyPairFromSeed32Generator::generate(
//!     Seed32::from_base58("7nY1fYmCXL1vF86ptneeg8r7M6C7G93M8MCfzBCaCtiJ").expect("invalid seed")
//! );
//!
//! let mut encrypted_message = vec![3, 81, 192, 79, 234, // ... several bytes hidden
//! # 127, 151, 145, 237, 209, 209, 213, 219, 29, 249, 21, 217, 231, 216, 147, 105, 39, 180, 181, 92, 97, 215, 153, 65, 104, 221, 236, 96, 151, 136, 3, 100, 109, 170, 117, 137, 66, 225, 189, 200, 38, 151, 219, 60, 78, 17, 146, 69, 35, 92, 186, 192, 69, 187, 44, 201, 163, 53, 16, 151, 212, 172, 120, 151, 241, 42, 79, 11, 77, 54, 21, 30, 206, 105, 94, 195, 177, 80, 58, 96, 28, 27, 99, 164, 39, 87, 49, 143, 185, 7, 137, 138, 189, 60, 98, 208, 169, 168, 236, 13, 86, 74, 177, 60, 197, 45, 222, 135, 193, 130, 161, 192, 56, 168, 169, 97, 8, 33, 101, 202, 180, 239, 178, 42, 139, 226, 59, 22, 228, 43, 245, 236, 204, 106, 86, 218, 88, 238, 215, 219, 4, 38, 88, 90, 42, 250, 27, 236, 204, 73, 53, 179, 39, 7, 124, 187, 126, 81, 4, 117, 244, 114, 88, 52, 214, 86, 168, 213, 201, 114, 248, 145, 212, 164, 189, 78, 8, 201, 178, 85, 12, 25, 248, 193, 247, 13, 103, 15, 50, 197, 17, 41, 93, 164, 36, 87, 97, 215, 216, 207, 183, 21, 236, 114, 227, 88, 235, 86, 72, 183, 49, 69, 176];
//!
//! let DecryptedMessage { message, sender_public_key, signature_opt } =
//!     dup_crypto::private_message::decrypt_private_message(
//!         b"service name - currency name",
//!         ChaChaRounds::ChaCha20,
//!         &mut encrypted_message,
//!         &receiver_key_pair,
//! )?;
//!
//! assert_eq!(
//!     message,
//!     b"Hello, this is a secret message, which can only be read by the recipient.",
//! );
//! assert_eq!{
//!     "5pFCsihCTDbFaysD6jDhvv7wUcZsSKoGWQ3Lm1QU5Z9t",
//!     &sender_public_key.to_string(),
//! }
//! assert_eq!(
//!     signature_opt,
//!     None
//! );
//!
//! # Ok::<(), dup_crypto::private_message::PrivateMessageError>(())
//! ```
//!

mod authentication;

pub use self::authentication::AuthenticationPolicy;

use self::authentication::{
    generate_authentication_proof, verify_authentication_proof, write_anthentication_datas,
};
use crate::keys::ed25519::{
    Ed25519KeyPair, KeyPairFromSeed32Generator, PublicKey as Ed25519PublicKey, Signature,
};
use crate::keys::x25519::{diffie_hellman, X25519PublicKey, X25519SecretKey};
use crate::keys::{KeyPair, PubKeyFromBytesError};
use crate::rand::UnspecifiedRandError;
use crate::seeds::Seed32;
use chacha20poly1305::aead::{AeadInPlace as _, NewAead};
use chacha20poly1305::{ChaCha12Poly1305, ChaCha20Poly1305, ChaCha8Poly1305};
use std::num::NonZeroU32;
use std::{convert::TryFrom, hint::unreachable_unchecked};
use zeroize::Zeroize;

type Key = chacha20poly1305::aead::Key<ChaCha20Poly1305>;
type Nonce =
    chacha20poly1305::aead::Nonce<chacha20poly1305::aead::generic_array::typenum::consts::U12>;
type Tag = chacha20poly1305::aead::Tag<chacha20poly1305::aead::generic_array::typenum::consts::U16>;

/// Metadata length
pub const METADATA_LEN: usize = CLEAR_FOOTER_LEN + AUTHENTICATION_DATAS_LEN;

const AUTHENTICATION_DATAS_LEN: usize = 97;
const CLEAR_FOOTER_LEN: usize = EPHEMERAL_PUBLIC_KEY_LEN + TAG_LEN;
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 3;
const SENDER_PUBLIC_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// Number of ChaCha rounds
#[derive(Clone, Copy, Debug)]
pub enum ChaChaRounds {
    /// 8 rounds
    ChaCha8,
    /// 12 rounds
    ChaCha12,
    /// 20 rounds
    ChaCha20,
}

/// Error at encryption/decryption of a private message
#[derive(Debug)]
pub enum PrivateMessageError {
    /// I/O error
    IoError(std::io::Error),
    /// Invalid ephemeral pubkey
    InvalidEphemeralPubKey(PubKeyFromBytesError),
    /// Invalid sender pubkey
    InvalidSenderPubKey(PubKeyFromBytesError),
    /// Invalid authentication proof : invalid signature
    InvalidAuthenticationProof,
    /// Unspecified aead error
    UnspecifiedAeadError,
    /// Unspecified rand error
    UnspecifiedRandError,
}

impl From<std::io::Error> for PrivateMessageError {
    fn from(e: std::io::Error) -> Self {
        PrivateMessageError::IoError(e)
    }
}

impl From<UnspecifiedRandError> for PrivateMessageError {
    fn from(_: UnspecifiedRandError) -> Self {
        PrivateMessageError::UnspecifiedRandError
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct SharedSecret([u8; 44]);

impl Default for SharedSecret {
    fn default() -> Self {
        SharedSecret([0u8; 44])
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Encrypt private message
pub fn encrypt_private_message<M>(
    additionally_authenticated_data: &[u8],
    authentication_policy: AuthenticationPolicy,
    chacha_rounds: ChaChaRounds,
    message: &mut M,
    receiver_public_key: &Ed25519PublicKey,
    sender_keypair: &Ed25519KeyPair,
) -> Result<(), PrivateMessageError>
where
    M: AsRef<[u8]> + AsMut<[u8]> + Extend<u8>,
{
    // Generate ephemeral ed25519 keypair
    let ephemeral_keypair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

    // Compute DH exchange (ephemeral_secret_key, receiver_public_key)
    // and derive symmetric_key and nonce from shared secret
    let shared_secret = generate_shared_secret(
        ephemeral_keypair.public_key().datas.as_ref(),
        ephemeral_keypair.seed(),
        &receiver_public_key,
    );

    // Write encrypted footer (=authentication datas)
    let encrypted_footer = write_anthentication_datas(
        &sender_keypair.public_key(),
        generate_authentication_proof(
            authentication_policy,
            sender_keypair,
            receiver_public_key,
            message.as_ref(),
        ),
        authentication_policy,
    );
    message.extend(encrypted_footer);

    // Encrypt message
    let tag = encrypt(
        additionally_authenticated_data,
        chacha_rounds,
        message.as_mut(),
        shared_secret,
    )?;

    // write clear footer (tag and ephemeral_public_key)
    let mut clear_footer = arrayvec::ArrayVec::<u8, 48>::new();
    clear_footer
        .try_extend_from_slice(tag.as_ref())
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() }); // It's safe because the tag is 16 bytes long.
    clear_footer
        .try_extend_from_slice(ephemeral_keypair.public_key().datas.as_ref())
        .unwrap_or_else(|_| unsafe { unreachable_unchecked() }); // It's safe because the public key is 32 bytes long.
    message.extend(clear_footer.into_iter());

    Ok(())
}

/// Decrypted message
pub struct DecryptedMessage<'m> {
    /// decrypted message content
    pub message: &'m [u8],
    /// Sender public key
    pub sender_public_key: Ed25519PublicKey,
    /// Optional signature
    pub signature_opt: Option<Signature>,
}

/// Decrypt private message.
/// Return a reference to decrypted bytes and an optional signature.
/// If the authentication method chosen by the sender is `Signature`,
/// then the signature is necessarily returned. The signature is returned
/// to allow subsequent publication of proof that this particular message was sent by the sender.
pub fn decrypt_private_message<'m>(
    additionally_authenticated_data: &[u8],
    chacha_rounds: ChaChaRounds,
    encrypted_message: &'m mut [u8],
    receiver_key_pair: &Ed25519KeyPair,
) -> Result<DecryptedMessage<'m>, PrivateMessageError> {
    // Read clear footer (tag and ephemeral public key)
    let len = encrypted_message.len();
    let clear_footer_begin = len - EPHEMERAL_PUBLIC_KEY_LEN - TAG_LEN;
    let tag_end = len - EPHEMERAL_PUBLIC_KEY_LEN;
    let tag = Tag::from_slice(&encrypted_message[clear_footer_begin..tag_end]).to_owned();
    let sender_ephemeral_public_key =
        Ed25519PublicKey::try_from(&encrypted_message[(len - EPHEMERAL_PUBLIC_KEY_LEN)..])
            .map_err(PrivateMessageError::InvalidEphemeralPubKey)?;

    // Compute DH exchange (receiver_secret_key, ephemeral_public_key)
    // and derive symmetric_key and nonce from shared secret
    let shared_secret = generate_shared_secret(
        &sender_ephemeral_public_key.datas.as_ref(),
        &receiver_key_pair.seed(),
        &sender_ephemeral_public_key,
    );

    // Decrypt message
    decrypt(
        additionally_authenticated_data,
        chacha_rounds,
        &mut encrypted_message[..(len - CLEAR_FOOTER_LEN)],
        shared_secret,
        &tag,
    )?;

    // Verify authentication proof
    let authent_end = clear_footer_begin;
    let authent_begin = authent_end - AUTHENTICATION_DATAS_LEN;
    let (sender_public_key, sig_opt) = verify_authentication_proof(
        receiver_key_pair,
        &encrypted_message[..authent_begin],
        &encrypted_message[authent_begin..authent_end],
    )?;

    Ok(DecryptedMessage {
        message: &encrypted_message[..authent_begin],
        sender_public_key,
        signature_opt: sig_opt,
    })
}

fn generate_shared_secret(
    ephemeral_public_key: &[u8],
    exchange_secret_key: &Seed32,
    exchange_public_key: &Ed25519PublicKey,
) -> SharedSecret {
    diffie_hellman(
        X25519SecretKey::from(exchange_secret_key),
        X25519PublicKey::from(exchange_public_key),
        |key_material| derive(key_material, ephemeral_public_key),
    )
}

#[cfg(target_arch = "wasm32")]
#[cfg(not(tarpaulin_include))]
fn derive(seed: &[u8], salt: &[u8]) -> SharedSecret {
    let mut shared_secret = SharedSecret::default();
    let mut hmac = cryptoxide::hmac::Hmac::new(cryptoxide::sha2::Sha512::new(), seed);
    cryptoxide::pbkdf2::pbkdf2(&mut hmac, salt, PBKDF2_ITERATIONS, shared_secret.as_mut());
    shared_secret
}
#[cfg(not(target_arch = "wasm32"))]
fn derive(seed: &[u8], salt: &[u8]) -> SharedSecret {
    let mut shared_secret = SharedSecret::default();
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        unsafe { NonZeroU32::new_unchecked(PBKDF2_ITERATIONS) },
        salt,
        seed,
        shared_secret.as_mut(),
    );
    shared_secret
}

fn encrypt(
    associated_data: &[u8],
    chacha_rounds: ChaChaRounds,
    message: &mut [u8],
    shared_secret: SharedSecret,
) -> Result<Tag, PrivateMessageError> {
    let symmetric_key = Key::from_slice(&shared_secret.as_ref()[..32]);
    let nonce = Nonce::from_slice(&shared_secret.as_ref()[32..44]);
    match chacha_rounds {
        ChaChaRounds::ChaCha8 => ChaCha8Poly1305::new(symmetric_key)
            .encrypt_in_place_detached(&nonce, associated_data, message)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
        ChaChaRounds::ChaCha12 => ChaCha12Poly1305::new(symmetric_key)
            .encrypt_in_place_detached(&nonce, associated_data, message)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
        ChaChaRounds::ChaCha20 => ChaCha20Poly1305::new(symmetric_key)
            .encrypt_in_place_detached(&nonce, associated_data, message)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
    }
}

fn decrypt(
    associated_data: &[u8],
    chacha_rounds: ChaChaRounds,
    encrypted_message: &mut [u8],
    shared_secret: SharedSecret,
    tag: &Tag,
) -> Result<(), PrivateMessageError> {
    let symmetric_key = Key::from_slice(&shared_secret.as_ref()[..32]);
    let nonce = Nonce::from_slice(&shared_secret.as_ref()[32..44]);

    match chacha_rounds {
        ChaChaRounds::ChaCha8 => ChaCha8Poly1305::new(symmetric_key)
            .decrypt_in_place_detached(&nonce, associated_data, encrypted_message, tag)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
        ChaChaRounds::ChaCha12 => ChaCha12Poly1305::new(symmetric_key)
            .decrypt_in_place_detached(&nonce, associated_data, encrypted_message, tag)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
        ChaChaRounds::ChaCha20 => ChaCha20Poly1305::new(symmetric_key)
            .decrypt_in_place_detached(&nonce, associated_data, encrypted_message, tag)
            .map_err(|_| PrivateMessageError::UnspecifiedAeadError),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::keys::KeyPair;
    use unwrap::unwrap;

    const AAD: &[u8] = b"service name - currency name";
    const MESSAGE: &[u8] =
        b"Hello, this is a secret message, which can only be read by the recipient.";

    #[test]
    fn encrypt_same_message_must_be_different() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let message = MESSAGE;

        let encrypted_message1 =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        let encrypted_message2 =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        assert_ne!(encrypted_message1, encrypted_message2);
        assert_ne!(encrypted_message1[32..37], encrypted_message2[32..37]);

        Ok(())
    }

    #[test]
    fn encrypt_then_decrypt_with_invalid_aad() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let message = MESSAGE;

        let mut encrypted_message =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        println!("encrypted message={:?}", encrypted_message);

        match decrypt_private_message(
            b"invalid aad",
            ChaChaRounds::ChaCha20,
            &mut encrypted_message,
            &receiver_key_pair,
        ) {
            Ok(_) => {
                panic!("Expected error PrivateMessageError::UnspecifiedAeadError, found: Ok(()).")
            }
            Err(PrivateMessageError::UnspecifiedAeadError) => Ok(()),
            Err(e) => panic!(
                "Expected error PrivateMessageError::UnspecifiedAeadError, found: {:?}.",
                e
            ),
        }
    }

    #[test]
    fn encrypt_then_decrypt_with_invalid_algorithm() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let message = MESSAGE;

        let mut encrypted_message =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        println!("encrypted message={:?}", encrypted_message);

        match decrypt_private_message(
            AAD,
            ChaChaRounds::ChaCha12,
            &mut encrypted_message,
            &receiver_key_pair,
        ) {
            Ok(_) => {
                panic!("Expected error PrivateMessageError::UnspecifiedAeadError, found: Ok(()).")
            }
            Err(PrivateMessageError::UnspecifiedAeadError) => Ok(()),
            Err(e) => panic!(
                "Expected error PrivateMessageError::UnspecifiedAeadError, found: {:?}.",
                e
            ),
        }
    }

    #[test]
    fn encrypt_and_decrypt_ok() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(unwrap!(Seed32::from_base58(
            "7nY1fYmCXL1vF86ptneeg8r7M6C7G93M8MCfzBCaCtiJ"
        )));

        let message = MESSAGE;

        let mut encrypted_message =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        println!("encrypted message={:?}", encrypted_message);

        let DecryptedMessage {
            message: decrypted_message,
            sender_public_key,
            signature_opt,
        } = decrypt_private_message(
            AAD,
            ChaChaRounds::ChaCha20,
            &mut encrypted_message,
            &receiver_key_pair,
        )?;

        println!("decrypted message={:?}", decrypted_message);

        assert_eq!(decrypted_message, message);
        assert_eq!(sender_public_key, sender_key_pair.public_key());
        assert_eq!(signature_opt, None);

        Ok(())
    }

    fn test_encrypt(
        message: &[u8],
        receiver_public_key: &Ed25519PublicKey,
        sender_keypair: &Ed25519KeyPair,
    ) -> Result<Vec<u8>, PrivateMessageError> {
        let mut encrypted_message = Vec::new();
        encrypted_message.extend(message);

        encrypt_private_message(
            AAD,
            AuthenticationPolicy::PrivateAuthentication,
            ChaChaRounds::ChaCha20,
            &mut encrypted_message,
            receiver_public_key,
            sender_keypair,
        )?;

        Ok(encrypted_message)
    }
}
