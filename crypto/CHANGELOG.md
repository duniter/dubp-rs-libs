# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

- feat(crypto): impl BIP32-Ed25519

## [0.25.2] - 2020-10-09

### Fixed

- base 64 decoding panic with no padded input

## [0.25.1] - 2020-10-08

- optimization: decode bases 16/58/64 strings without heap allocation
- ref: [u8; 64] now implement `Hash` and `PartialEq` (rust 1.47)

## [0.25.1] - 2020-09-26

- doc: `BaseConversionError` is used for base 16 too

## [0.24.0] - 2020-09-12

### Fixed

- benches not executed by latest cargo

## [0.23.0] - 2020-09-02

### Changed

- Feature `x25519` need feature `pubkey_check`

## [0.21.0] - 2020-09-02

### Added

- Enable `rand` feature by default
- Implement Default for `ed25519::Signature`

## [0.20.0] - 2020-09-01

### Added

- Add support for target wasm32-unknown-unknown

## [0.15.0] - 2020-04-03

### Added

- Scrypt KDF can be optional

## [0.14.0] - 2020-04-02

### Fixed

- keys: ed25519 public key methods (as_ref, try_from, to_bytes_vector) must be consistent with bincode serialization/deserialization

## [0.13.0] - 2020-03-04

### Added

- Private message encryption/decryption with authentication

## [0.12.1] - 2020-03-03

### Fixed

- base58: handle base58 string with too many leading zeros (Especially the string `11111111111111111111111111111111111111111111`).

## [0.12.0] - 2020-03-02

### Fixed

- base58: handle leading zeros

## [0.11.1] - 2020-03-01

### Fixed

- ed25519: public key don't have min size. empty public key must be supported.

## [0.11.0] - 2020-02-29

### Changed

- DEWIF: add currency field

## [0.10.0] - 2020-02-20

### Changed

- DEWIF: read_dewif_content() now directly returns an Iterator.

## [0.9.1] - 2020-01-19

### Added

- Read/write DEWIF file content #1
- Aes256 encryption/decryption
- hashs::Hash impl AsRef<[u8]>

### Changed

- Ed25519KeyPair::generate_signator cannot fail.

### Security

- Ed25519KeyPair must not expose seed

## [0.8.0] - 2020-01-16

Initial version.

<!-- next-url -->
[Unreleased]: https://git.duniter.org/libs/dup-rs-libs/compare/v0.25.2...HEAD
[0.25.2]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.25.1...v0.25.2
[0.25.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.25.0...v0.25.1
[0.25.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.24.0...v0.25.0
[0.24.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.23.0...v0.24.0
[0.23.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.21.0...v0.23.0
[0.21.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.20.0...v0.21.0
[0.20.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.15.0...v0.20.0
[0.15.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.14.0...v0.15.0
[0.14.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.13.0...v0.14.0
[0.13.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.12.1...v0.13.0
[0.12.1]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.12.0...v0.12.1
[0.12.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.11.1...v0.12.0
[0.11.1]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.11.0...v0.11.1
[0.11.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.10.0...v0.11.0
[0.10.0]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.9.1...v0.10.0
[0.9.1]: https://git.duniter.org/libs/dup-crypto-rs/compare/v0.8.0...v0.9.1
