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
//!     ed25519::{KeyPairFromSaltedPasswordGenerator, PublicKey as Ed25519PublicKey, SaltedPassword}
//! };
//! use dup_crypto::private_message::{Aad, Algorithm, AuthenticationPolicy, METADATA_LEN};
//! use dup_crypto::seeds::Seed32;
//!
//! // Take the time to study which is the authentication policy adapted
//! // to your specific use case.
//! // Read `dup_crypto::private_message::AuthenticationPolicy` documentation.
//! let authentication_policy = AuthenticationPolicy::PrivateAuthentication;
//!
//! // Regardless of the authentication policy chosen, the sender's key-pair is required.
//! let sender_key_pair = KeyPairFromSaltedPasswordGenerator::with_default_parameters()
//!     .generate(SaltedPassword::new("sender salt".to_owned(), "sender password".to_owned()));
//!
//! // Choose an encryption algorithm adapted to your specific use case.
//! // Read `dup_crypto::private_message::Algorithm` documentation.
//! let encryption_algo = Algorithm::Chacha20Poly1305;
//!
//! // Aad value must be known by the software that will decipher the message, it can be the
//! // name of the service followed by the name of the network (name of the currency for example).
//! // This field is only used to ensure that there is no interference between different services
//! // and/or networks.
//! let aad = Aad::from(b"service name - currency name");
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
//!     encryption_algo,
//!     authentication_policy,
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
//! use dup_crypto::private_message::{Aad, Algorithm, DecryptedMessage};
//! use dup_crypto::seeds::Seed32;
//!
//! let receiver_key_pair = KeyPairFromSeed32Generator::generate(
//!     Seed32::from_base58("7nY1fYmCXL1vF86ptneeg8r7M6C7G93M8MCfzBCaCtiJ").expect("invalid seed")
//! );
//!
//! let mut encrypted_message = vec![221u8, 252, 176, 127, 197, // ... several bytes hidden
//! # 20, 191, 154, 245, 206, 154, 71, 71,
//! # 169, 240, 50, 142, 231, 143, 239, 55, 31, 117, 197, 66, 90, 232, 14, 108, 203, 188, 70, 123, 75,
//! # 216, 55, 5, 57, 60, 35, 185, 99, 147, 23, 51, 57, 93, 213, 149, 101, 24, 195, 18, 168, 37, 71, 182,
//! # 220, 198, 250, 72, 199, 21, 66, 15, 57, 144, 247, 54, 19, 30, 134, 210, 227, 205, 113, 142, 15, 77,
//! # 76, 223, 132, 38, 237, 100, 139, 227, 115, 49, 216, 102, 120, 124, 84, 208, 85, 242, 141, 216, 145,
//! # 10, 17, 168, 219, 129, 199, 149, 188, 210, 123, 79, 128, 76, 159, 133, 251, 95, 29, 238, 43, 225,
//! # 211, 43, 197, 237, 93, 79, 243, 120, 227, 153, 79, 57, 1, 23, 233, 167, 110, 210, 16, 52, 16, 73, 13,
//! # 214, 16, 223, 17, 175, 228, 211, 151, 79, 227, 14, 56, 135, 77, 73, 36, 22, 115, 77, 201, 114, 38,
//! # 206, 240, 212, 129, 247, 111, 165, 182, 98, 176, 247, 69, 198, 34, 71, 26, 176, 147, 205, 173, 50,
//! # 247, 151, 148, 197, 162, 88, 254, 185, 149, 108, 2, 137, 139, 66, 82, 168, 213, 118, 218, 188, 238,
//! # 147, 89, 156];
//!
//! let DecryptedMessage { message, sender_public_key, signature_opt } =
//!     dup_crypto::private_message::decrypt_private_message(
//!         Aad::from(b"service name - currency name"),
//!         Algorithm::Chacha20Poly1305,
//!         &mut encrypted_message,
//!         &receiver_key_pair,
//! )?;
//!
//! assert_eq!(
//!     message,
//!     &b"This is a secret message, which can only be read by the recipient."[..],
//! );
//! assert_eq!{
//!     "4HbjoXtWu9C2Q5LMu1RcWHS66k4dnvHspBxKWagFG5rJ",
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
pub use ring::aead::Aad;

use self::authentication::{
    generate_authentication_proof, verify_authentication_proof, write_anthentication_datas,
};
use crate::keys::ed25519::{
    Ed25519KeyPair, KeyPairFromSeed32Generator, PublicKey as Ed25519PublicKey, Signature,
};
use crate::keys::x25519::{diffie_hellman, X25519PublicKey, X25519SecretKey};
use crate::keys::{KeyPair, PubkeyFromBytesError};
use crate::rand::UnspecifiedRandError;
use crate::seeds::Seed32;
use ring::aead::{LessSafeKey, Nonce, Tag, UnboundKey};
use ring::pbkdf2;
use std::convert::TryFrom;
use std::num::NonZeroU32;
use zeroize::Zeroize;

/// Metadata length
pub const METADATA_LEN: usize = 129; // EPHEMERAL_PUBLIC_KEY_LEN + AUTHENTICATION_DATAS_LEN

const ITERATIONS: u32 = 3;
const SENDER_PUBLIC_KEY_LEN: usize = 32;
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 32;
const AUTHENTICATION_DATAS_LEN: usize = 97;

/// Private message encryption algorithm
/// If your program is susceptible to running on machines that do not provide hardware
/// acceleration for AES (some phones, embedded devices, old computers, etc) then you
/// should choose `Chacha20Poly1305`. Even on devices with hardware acceleration for AES,
/// the performance of `Chacha20Poly1305` is often equivalent to `Aes256Gcm`, so only choose
/// `Aes256Gcm` if you have strong reasons to do so.
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    /// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
    Aes256Gcm,
    /// ChaCha20-Poly1305 as described in [RFC 7539](https://tools.ietf.org/html/rfc7539).
    Chacha20Poly1305,
}

impl Algorithm {
    fn to_ring_algo(self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes256Gcm => &ring::aead::AES_256_GCM,
            Self::Chacha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }
}

/// Error at encryption/decryption of a private message
#[derive(Debug)]
pub enum PrivateMessageError {
    /// I/O error
    IoError(std::io::Error),
    /// Invalid ephemeral pubkey
    InvalidEphemeralPubkey(PubkeyFromBytesError),
    /// Invalid sender pubkey
    InvalidSenderPubkey(PubkeyFromBytesError),
    /// Invalid authentication proof : invalid signature
    InvalidAuthenticationProof,
    /// Unspecified errror
    Unspecified,
}

impl From<std::io::Error> for PrivateMessageError {
    fn from(e: std::io::Error) -> Self {
        PrivateMessageError::IoError(e)
    }
}

impl From<UnspecifiedRandError> for PrivateMessageError {
    fn from(_: UnspecifiedRandError) -> Self {
        PrivateMessageError::Unspecified
    }
}

impl From<ring::error::Unspecified> for PrivateMessageError {
    fn from(_: ring::error::Unspecified) -> Self {
        PrivateMessageError::Unspecified
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct SharedSecret([u8; 48]);

impl Default for SharedSecret {
    fn default() -> Self {
        SharedSecret([0u8; 48])
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
pub fn encrypt_private_message<A, M>(
    additionally_authenticated_data: Aad<A>,
    algorithm: Algorithm,
    authentication_policy: AuthenticationPolicy,
    message: &mut M,
    receiver_public_key: &Ed25519PublicKey,
    sender_keypair: &Ed25519KeyPair,
) -> Result<(), PrivateMessageError>
where
    A: AsRef<[u8]>,
    M: AsRef<[u8]> + AsMut<[u8]> + Extend<u8>,
{
    // Generate ephemeral ed25519 keypair
    let ephemeral_keypair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

    // Compute DH exchange (ephemeral_secret_key, receiver_public_key)
    // and derive symmetric_key and nonce from shared secret
    let (symmetric_key, nonce) = generate_symmetric_key_and_nonce(
        algorithm,
        ephemeral_keypair.public_key().datas.as_ref(),
        ephemeral_keypair.seed(),
        &receiver_public_key,
    )?;

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
    let tag = encrypt::<A>(
        symmetric_key,
        nonce,
        additionally_authenticated_data,
        message.as_mut(),
    )?;

    // write clear footer (tag and ephemeral_public_key)
    let mut clear_footer = arrayvec::ArrayVec::<[u8; 64]>::new();
    clear_footer
        .try_extend_from_slice(tag.as_ref())
        .expect("too long tag");
    clear_footer
        .try_extend_from_slice(ephemeral_keypair.public_key().datas.as_ref())
        .expect("too long ephemeral_public_key");
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
pub fn decrypt_private_message<'m, A: AsRef<[u8]>>(
    additionally_authenticated_data: Aad<A>,
    algorithm: Algorithm,
    encrypted_message: &'m mut [u8],
    receiver_key_pair: &Ed25519KeyPair,
) -> Result<DecryptedMessage<'m>, PrivateMessageError> {
    // Get ephemeral public key
    let len = encrypted_message.len();
    let ephemeral_public_key = &encrypted_message[(len - EPHEMERAL_PUBLIC_KEY_LEN)..];

    // Compute DH exchange (receiver_secret_key, ephemeral_public_key)
    // and derive symmetric_key and nonce from shared secret
    let (symmetric_key, nonce) = generate_symmetric_key_and_nonce(
        algorithm,
        &ephemeral_public_key,
        &receiver_key_pair.seed(),
        &Ed25519PublicKey::try_from(ephemeral_public_key)
            .map_err(PrivateMessageError::InvalidEphemeralPubkey)?,
    )?;

    // Decrypt message
    decrypt::<A>(
        symmetric_key,
        nonce,
        additionally_authenticated_data,
        &mut encrypted_message[..(len - EPHEMERAL_PUBLIC_KEY_LEN)],
    )?;

    // Verify authentication proof
    let tag_len = algorithm.to_ring_algo().tag_len();
    let authent_end = len - EPHEMERAL_PUBLIC_KEY_LEN - tag_len;
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

fn generate_symmetric_key_and_nonce(
    algorithm: Algorithm,
    ephemeral_public_key: &[u8],
    exchange_secret_key: &Seed32,
    exchange_public_key: &Ed25519PublicKey,
) -> Result<(UnboundKey, Nonce), PrivateMessageError> {
    let shared_secret = diffie_hellman(
        X25519SecretKey::from(exchange_secret_key),
        X25519PublicKey::from(exchange_public_key),
        |key_material| derive(key_material, ephemeral_public_key),
    );

    let symmetric_key = UnboundKey::new(algorithm.to_ring_algo(), &shared_secret.as_ref()[..32])?;
    let nonce = Nonce::try_assume_unique_for_key(&shared_secret.as_ref()[32..44])?;

    Ok((symmetric_key, nonce))
}

fn derive(seed: &[u8], salt: &[u8]) -> SharedSecret {
    let mut shared_secret = SharedSecret::default();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA384,
        NonZeroU32::new(ITERATIONS).expect("ITERATIONS must be > 0"),
        salt,
        seed,
        shared_secret.as_mut(),
    );
    shared_secret
}

fn encrypt<A: AsRef<[u8]>>(
    key: UnboundKey,
    nonce: Nonce,
    aad: Aad<A>,
    message: &mut [u8],
) -> Result<Tag, PrivateMessageError> {
    let key = LessSafeKey::new(key);
    Ok(key.seal_in_place_separate_tag(nonce, aad, message.as_mut())?)
}

fn decrypt<A: AsRef<[u8]>>(
    key: UnboundKey,
    nonce: Nonce,
    aad: Aad<A>,
    encrypted_message: &mut [u8],
) -> Result<(), PrivateMessageError> {
    let key = LessSafeKey::new(key);
    key.open_in_place(nonce, aad, encrypted_message)?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::keys::KeyPair;

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
            Aad::from(b"invalid aad"),
            Algorithm::Chacha20Poly1305,
            &mut encrypted_message,
            &receiver_key_pair,
        ) {
            Ok(_) => panic!("Expected error rivateMessageError::Unspecified, found: Ok(())."),
            Err(PrivateMessageError::Unspecified) => Ok(()),
            Err(e) => panic!(
                "Expected error rivateMessageError::Unspecified, found: {:?}.",
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
            Aad::from(AAD),
            Algorithm::Aes256Gcm,
            &mut encrypted_message,
            &receiver_key_pair,
        ) {
            Ok(_) => panic!("Expected error rivateMessageError::Unspecified, found: Ok(())."),
            Err(PrivateMessageError::Unspecified) => Ok(()),
            Err(e) => panic!(
                "Expected error rivateMessageError::Unspecified, found: {:?}.",
                e
            ),
        }
    }

    #[test]
    fn encrypt_and_decrypt_ok() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let message = MESSAGE;

        let mut encrypted_message =
            test_encrypt(message, &receiver_key_pair.public_key(), &sender_key_pair)?;

        println!("encrypted message={:?}", encrypted_message);

        let DecryptedMessage {
            message: decrypted_message,
            sender_public_key,
            signature_opt,
        } = decrypt_private_message(
            Aad::from(AAD),
            Algorithm::Chacha20Poly1305,
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
            Aad::from(AAD),
            Algorithm::Chacha20Poly1305,
            AuthenticationPolicy::PrivateAuthentication,
            &mut encrypted_message,
            receiver_public_key,
            sender_keypair,
        )?;

        Ok(encrypted_message)
    }
}
