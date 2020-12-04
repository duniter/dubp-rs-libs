# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

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
[Unreleased]: https://git.duniter.org/libs/dubp-rs-libs/compare/v0.32.3...HEAD
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
