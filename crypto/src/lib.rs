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

//! Manage cryptographic operations for DUniter Protocols and the Duniter eco-system most broadly.
//!
//! `dup` means DUniter Protocols.
//!
//! ## Summary
//!
//!
//! * [Generate wallet with Dubp-Mnemonic](./mnemonic/index.html)
//! * [Handle DEWIF format](./dewif/index.html#handle-dewif-format)
//!   * [Write DEWIF file](./dewif/index.html#write-ed25519-key-pair-in-dewif-file)
//!   * [Read DEWIF file](./dewif/index.html#read-dewif-file)
//! * [Sha256](./hashs/index.html)
//!   * [Compute Sha256 hash](./hashs/index.html#compute-sha256-hash)
//! * [Ed25519](./keys/index.html)
//!   * [Generate and use ed25519 key-pair](./keys/index.html#generate-and-use-ed25519-key-pair)
//! * [BIP32-Ed25519](./keys/ed25519/bip32/index.html)
//!   * [Generate an HD wallet](./keys/ed25519/bip32/index.html#generate-an-hd-wallet)
//!   * [Derive private key and public key](./keys/ed25519/bip32/index.html#derive-private-key-and-public-key)
//! * [Private message encryption with authentification](./private_message/index.html)
//!   * [Encrypt a private message (sender side)](./private_message/index.html#encrypt-a-private-message-sender-side)
//!   * [Decrypt a private message (receiver side)](./private_message/index.html#decrypt-a-private-message-receiver-side)
//!

#![deny(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
#![allow(non_camel_case_types)]

pub mod bases;
#[cfg(feature = "dewif")]
pub mod dewif;
#[cfg(feature = "encrypt_tx_comment")]
pub mod encrypt_tx_comment;
pub mod hashs;
pub mod keys;
#[cfg(feature = "mnemonic")]
pub mod mnemonic;
#[cfg(feature = "private_message")]
pub mod private_message;
pub mod rand;
pub mod scrypt;
pub mod seeds;
pub mod utils;
pub mod xor_cipher;
