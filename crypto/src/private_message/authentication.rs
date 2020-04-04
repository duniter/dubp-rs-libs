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

//! Handle private message authentication policy

use super::{PrivateMessageError, AUTHENTICATION_DATAS_LEN, SENDER_PUBLIC_KEY_LEN};
use crate::keys::ed25519::{Ed25519KeyPair, PublicKey as Ed25519PublicKey, Signature};
use crate::keys::x25519::{diffie_hellman, X25519PublicKey, X25519SecretKey};
use crate::keys::{KeyPair, PublicKey, Signator};
use ring::digest;
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug)]
/// Authentication policy.
///
/// **Warning**: Take the time to study which is the authentication policy adapted to **your specific use case**.
/// Choosing an unsuitable authentication policy can be **dramatic for your end users**.
pub enum AuthenticationPolicy {
    /// Only the sender and the recipient have proof that the message was written by one of them.
    /// The recipient knows that he is not the author of the message so he has proof that the message was necessarily written by the sender.
    /// If your use case is the encrypted correspondence between machines in a decentralized network,
    /// and you sometimes need to prove that a machine has sent this or that message (to prove for example that it has not honored a commitment),
    /// then choose policy `Signature` instead.
    PrivateAuthentication,
    /// The sender proves that he is the author of the message.
    /// If the message is publicly disclosed, everyone will have proof that the sender is indeed the one who wrote the message.
    /// In certain uses this can be harmful to the sender: in case of conflict with the recipient,
    /// the latter may threaten to disclose their private correspondence to blackmail the sender.
    /// If your use case is private messaging between humans, choose method `PrivateAuthentication` instead.
    Signature,
}

impl Into<u8> for AuthenticationPolicy {
    fn into(self) -> u8 {
        match self {
            Self::PrivateAuthentication => 0,
            Self::Signature => 1,
        }
    }
}

impl From<u8> for AuthenticationPolicy {
    fn from(source: u8) -> Self {
        match source {
            0 => Self::PrivateAuthentication,
            _ => Self::Signature,
        }
    }
}

pub(crate) struct AuthenticationProof([u8; 64]);

impl AsRef<[u8]> for AuthenticationProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn write_anthentication_datas(
    sender_public_key: &Ed25519PublicKey,
    authent_proof: AuthenticationProof,
    authent_policy: AuthenticationPolicy,
) -> impl AsRef<[u8]> + IntoIterator<Item = u8> {
    let mut authent_datas = arrayvec::ArrayVec::<[u8; 128]>::new();
    authent_datas
        .try_extend_from_slice(sender_public_key.datas.as_ref())
        .expect("too long sender public key");
    authent_datas
        .try_extend_from_slice(authent_proof.as_ref())
        .expect("too long authent_proof");
    authent_datas.push(authent_policy.into());
    authent_datas
}

pub(crate) fn generate_authentication_proof(
    authentication_policy: AuthenticationPolicy,
    sender_keypair: &Ed25519KeyPair,
    receiver_public_key: &Ed25519PublicKey,
    message: &[u8],
) -> AuthenticationProof {
    AuthenticationProof(match authentication_policy {
        AuthenticationPolicy::PrivateAuthentication => diffie_hellman(
            X25519SecretKey::from(sender_keypair.seed()),
            X25519PublicKey::from(receiver_public_key),
            |key_material| {
                let mut hash = [0u8; 64];
                let mut ctx = digest::Context::new(&digest::SHA512);
                ctx.update(message.as_ref());
                ctx.update(key_material);
                let digest = ctx.finish();
                hash.copy_from_slice(digest.as_ref());
                hash
            },
        ),
        AuthenticationPolicy::Signature => {
            sender_keypair.generate_signator().sign(message.as_ref()).0
        }
    })
}

pub(crate) fn verify_authentication_proof(
    receiver_key_pair: &Ed25519KeyPair,
    message: &[u8],
    authentication_datas: &[u8],
) -> Result<(Ed25519PublicKey, Option<Signature>), PrivateMessageError> {
    let sender_public_key =
        Ed25519PublicKey::try_from(&authentication_datas[..SENDER_PUBLIC_KEY_LEN])
            .map_err(PrivateMessageError::InvalidSenderPubkey)?;
    let mut authent_proof = AuthenticationProof([0u8; 64]);
    authent_proof.0.copy_from_slice(
        &authentication_datas[SENDER_PUBLIC_KEY_LEN..(AUTHENTICATION_DATAS_LEN - 1)],
    );
    let mut signature_opt = None;
    match AuthenticationPolicy::from(authentication_datas[AUTHENTICATION_DATAS_LEN - 1]) {
        AuthenticationPolicy::PrivateAuthentication => {
            let expected_proof = AuthenticationProof(diffie_hellman(
                X25519SecretKey::from(receiver_key_pair.seed()),
                X25519PublicKey::from(&sender_public_key),
                |key_material| {
                    let mut hash = [0u8; 64];
                    let mut ctx = digest::Context::new(&digest::SHA512);
                    ctx.update(message.as_ref());
                    ctx.update(key_material);
                    let digest = ctx.finish();
                    hash.copy_from_slice(digest.as_ref());
                    hash
                },
            ));
            for i in 0..64 {
                if expected_proof.0[i] != authent_proof.0[i] {
                    return Err(PrivateMessageError::InvalidAuthenticationProof);
                }
            }
        }
        AuthenticationPolicy::Signature => {
            signature_opt = Some(Signature(authent_proof.0));
            sender_public_key
                .verify(message, &Signature(authent_proof.0))
                .map_err(|_| PrivateMessageError::InvalidAuthenticationProof)?;
        }
    }
    Ok((sender_public_key, signature_opt))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::seeds::Seed32;

    const MESSAGE: &[u8] = b"message";

    #[test]
    fn private_authent_ok() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let authent_policy = AuthenticationPolicy::PrivateAuthentication;

        let authent_proof = generate_authentication_proof(
            authent_policy,
            &sender_key_pair,
            &receiver_key_pair.public_key(),
            MESSAGE,
        );

        let authent_datas = write_anthentication_datas(
            &sender_key_pair.public_key(),
            authent_proof,
            authent_policy,
        );

        verify_authentication_proof(&receiver_key_pair, MESSAGE, authent_datas.as_ref())?;

        Ok(())
    }

    #[test]
    fn invalid_sender_pubkey() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let authent_policy = AuthenticationPolicy::PrivateAuthentication;

        let authent_proof = generate_authentication_proof(
            authent_policy,
            &sender_key_pair,
            &receiver_key_pair.public_key(),
            MESSAGE,
        );

        let mut authent_datas: Vec<u8> = write_anthentication_datas(
            &sender_key_pair.public_key(),
            authent_proof,
            authent_policy,
        )
        .as_ref()
        .to_vec();

        let invalid_pubkey_bytes = [
            206u8, 58, 67, 221, 20, 133, 0, 225, 86, 115, 26, 104, 142, 116, 140, 132, 119, 51,
            175, 45, 82, 225, 14, 195, 7, 107, 43, 212, 8, 37, 234, 23,
        ];

        authent_datas[..32].copy_from_slice(&invalid_pubkey_bytes);

        if let Err(PrivateMessageError::InvalidSenderPubkey(_)) =
            verify_authentication_proof(&receiver_key_pair, MESSAGE, authent_datas.as_ref())
        {
            Ok(())
        } else {
            panic!("Expected PrivateMessageError::InvalidSenderPubkey.")
        }
    }

    #[test]
    fn invalid_private_authent_proof() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let authent_policy = AuthenticationPolicy::PrivateAuthentication;

        let authent_proof = generate_authentication_proof(
            authent_policy,
            &receiver_key_pair, // invalid key pair
            &receiver_key_pair.public_key(),
            MESSAGE,
        );

        let authent_datas = write_anthentication_datas(
            &sender_key_pair.public_key(),
            authent_proof,
            authent_policy,
        );

        if let Err(PrivateMessageError::InvalidAuthenticationProof) =
            verify_authentication_proof(&receiver_key_pair, MESSAGE, authent_datas.as_ref())
        {
            Ok(())
        } else {
            panic!("Expected PrivateMessageError::InvalidSenderPubkey.")
        }
    }

    #[test]
    fn invalid_sig_authent_proof() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let authent_policy = AuthenticationPolicy::Signature;

        let authent_proof = generate_authentication_proof(
            authent_policy,
            &receiver_key_pair, // invalid key pair
            &receiver_key_pair.public_key(),
            MESSAGE,
        );

        let authent_datas = write_anthentication_datas(
            &sender_key_pair.public_key(),
            authent_proof,
            authent_policy,
        );

        if let Err(PrivateMessageError::InvalidAuthenticationProof) =
            verify_authentication_proof(&receiver_key_pair, MESSAGE, authent_datas.as_ref())
        {
            Ok(())
        } else {
            panic!("Expected PrivateMessageError::InvalidSenderPubkey.")
        }
    }

    #[test]
    fn sig_authent_ok() -> Result<(), PrivateMessageError> {
        let sender_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);
        let receiver_key_pair = KeyPairFromSeed32Generator::generate(Seed32::random()?);

        let authent_policy = AuthenticationPolicy::Signature;

        let authent_proof = generate_authentication_proof(
            authent_policy,
            &sender_key_pair,
            &receiver_key_pair.public_key(),
            MESSAGE,
        );

        let authent_datas = write_anthentication_datas(
            &sender_key_pair.public_key(),
            authent_proof,
            authent_policy,
        );

        verify_authentication_proof(&receiver_key_pair, MESSAGE, authent_datas.as_ref())?;

        Ok(())
    }
}
