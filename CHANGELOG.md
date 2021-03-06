# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.58.0] - 2021-05-31

## [0.57.0] - 2021-05-20

## [0.56.0] - 2021-05-20

## [0.55.1] - 2021-05-19

## [0.54.1] - 2021-05-17

## [0.54.0] - 2021-05-17

## [0.53.1] - 2021-05-05

## [0.53.0] - 2021-05-02

## [0.52.0] - 2021-04-25

## [0.51.1] - 2021-04-18

## [0.51.0] - 2021-04-04

## [0.50.0] - 2021-03-21

## [0.49.0] - 2021-03-19

## [0.48.0] - 2021-03-17

## [0.47.1] - 2021-03-16

## [0.47.0] - 2021-03-09

## [0.46.0] - 2021-03-08

## [0.45.0] - 2021-03-06

## [0.44.1] - 2021-02-27

## [0.44.0] - 2021-02-27

## [0.43.2] - 2021-02-21

## [0.43.1] - 2021-02-21

## [0.43.0] - 2021-02-21

## [0.42.0] - 2021-02-20

## [0.41.1] - 2021-02-14

## [0.41.0] - 2021-02-09

- feat(crypto): dewif: add function read_dewif_meta
- feat(crypto): dewif: add function change_dewif_passphrase

## [0.40.0] - 2021-02-08

- feat(crypto): implement DEWIF v4

## [0.39.1] - 2021-02-07

## [0.39.0] - 2021-02-07

- feat(crypto): impl BIP32-Ed25519

## [0.38.0] - 2021-01-09

## [0.37.1] - 2021-01-08

## [0.37.0] - 2021-01-08

## [0.36.0] - 2020-12-20

- feat(crypto): Hash: add method compute_blake3
- ref(crypto):Hash: remove useless method compute_str

## [0.35.2] - 2020-12-14

## [0.35.1] - 2020-12-14

## [0.35.0] - 2020-12-13

- feat(crypto): impl dubp-mnemonic

## [0.34.0] - 2020-12-11

- feat(wallet): impl Hash for UtxoIdV10

## [0.33.0] - 2020-12-10

- feat(block): add several field accessors
- ref(documents):transaction: method verify not need an owned string

## [0.32.3] - 2020-12-04

- fix(crypto):b58: some rare base 58 string with leading 1 are not correctly handled

## [0.32.2] - 2020-11-26

- fix(wallet): SourceAmount auto impl of Ord is wrong

## [0.32.1] - 2020-11-25

- fix(docs-parser): TransactionOutputV10: handle invalid script without grammar

## [0.32.0] - 2020-11-20

- feat(wallet):script: add method and_and
- feat(documents): gen complex transactions
- feat(block): add method unit_base

## [0.31.0] - 2020-11-16

- feat(documents):tx: add method generate_simple_txs

## [0.30.0] - 2020-11-09

- feat(documents):tx: add method TransactionDocumentV10::verify_comment
- feat(wallet): add const SourceAmount::ZERO
- publish meta crate `dubp` with feature `crypto_scrypt`

## [0.29.0] - 2020-10-17

## [0.28.0] - 2020-10-15

## [0.27.0] - 2020-10-13

## [0.26.0] - 2020-10-09

### Added

- Create meta-crate `dubp`

## [0.25.2] - 2020-10-09

### Fixed

- base 64 decoding panic with no padded input

## [0.25.1] - 2020-10-08

### Optimization

- crypto: decode bases 16/58/64 strings without heap allocation

## [0.25.0] - 2020-09-26

Initial version.

<!-- next-url -->
[Unreleased]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.58.0...HEAD
[0.58.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.57.0...v0.58.0
[0.57.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.56.0...v0.57.0
[0.56.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.55.1...v0.56.0
[0.55.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.54.1...v0.55.1
[0.54.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.54.0...v0.54.1
[0.54.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.53.1...v0.54.0
[0.53.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.53.0...v0.53.1
[0.53.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.52.0...v0.53.0
[0.52.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.51.1...v0.52.0
[0.51.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.51.0...v0.51.1
[0.51.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.50.0...v0.51.0
[0.50.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.49.0...v0.50.0
[0.49.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.48.0...v0.49.0
[0.48.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.47.1...v0.48.0
[0.47.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.47.0...v0.47.1
[0.47.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.46.0...v0.47.0
[0.46.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.45.0...v0.46.0
[0.45.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.44.1...v0.45.0
[0.44.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.44.0...v0.44.1
[0.44.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.43.2...v0.44.0
[0.43.2]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.43.1...v0.43.2
[0.43.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.43.0...v0.43.1
[0.43.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.42.0...v0.43.0
[0.42.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.41.1...v0.42.0
[0.41.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.41.0...v0.41.1
[0.41.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.40.0...v0.41.0
[0.40.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.39.1...v0.40.0
[0.39.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.39.0...v0.39.1
[0.39.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.38.0...v0.39.0
[0.38.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.37.1...v0.38.0
[0.37.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.37.0...v0.37.1
[0.37.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.36.0...v0.37.0
[0.36.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.35.2...v0.36.0
[0.35.2]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.35.1...v0.35.2
[0.35.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.35.0...v0.35.1
[0.35.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.34.0...v0.35.0
[0.34.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.33.0...v0.34.0
[0.33.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.32.3...v0.33.0
[0.32.3]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.32.2...v0.32.3
[0.32.2]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.32.1...v0.32.2
[0.32.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.32.0...v0.32.1
[0.32.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.31.0...v0.32.0
[0.31.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.30.0...v0.31.0
[0.30.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.29.0...v0.30.0
[0.29.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.28.0...v0.29.0
[0.28.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.27.0...v0.28.0
[0.27.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.26.0...v0.27.0
[0.26.0]: https://git.duniter.org/libs/dup-rs-libs/compare/v0.25.2...v0.26.0
[0.25.2]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.25.1...v0.25.2
[0.25.1]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.25.0...v0.25.1
[0.25.0]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.24.0...v0.25.0
