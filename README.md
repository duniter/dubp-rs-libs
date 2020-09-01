# DUBP Rust Libraries

[![pipeline status](https://git.duniter.org/libs/dubp-rs-libs/badges/master/pipeline.svg)](https://git.duniter.org/libs/dubp-rs-libs/-/commits/master)
[![codecov](https://codecov.io/gh/duniter/dubp-rs-libs/branch/master/graph/badge.svg)](https://codecov.io/gh/duniter/dubp-rs-libs)
[![dependency status](https://deps.rs/repo/github/duniter/dubp-rs-libs/status.svg)](https://deps.rs/repo/github/duniter/dubp-rs-libs)

Set of libraries implementing the [DUBP] protocol.

- [common](common/README.md) : Provide common tools and types for libraries in this repository.
- [crypto](crypto/README.md) : Manage cryptographic operations (signature, hashs, base58, base64).
- [wallet](wallet/README.md) : Manage wallet script, unlock proofs and sources amount.
- [documents](documents/README.md) : Define [DUBP] Documents: identity, membership, certification, revocation and transaction.
- [documents-parser](documents-parser/README.md) : Provide parser for [DUBP] documents (use a [PEG grammar] via [pest]),
- [block](block/README.md) : Definition of the blocks format in [DUBP] as well as the methods to manipulate them.

[DUBP]: https://git.duniter.org/documents/rfcs/-/blob/master/rfc/0010_Duniter_Blockchain_Protocol_V12.md
[PEG grammar]: https://en.wikipedia.org/wiki/Parsing_expression_grammar
[pest]: https://pest.rs
