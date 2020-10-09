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

## Versioning policy

All crates in this repository are always at the same version. Even if only one crate is modified, they all change version and are all republished. If you need all crates, use the `dubp` meta-crate directly, it re-exports all the others.

Changes between two versions are listed in [CHANGELOG](CHANGELOG.md).

Also, this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## How to publish a new release

Everything is automated via the [cargo-release](https://github.com/sunng87/cargo-release) utility, if you don't already have it, install it:

```bash
cargo install cargo-release
```

Then, to release the version `x.y.z`:

```bash
git checkout master
cargo release x.y.z
git push origin
```

Finally, the gitlab CI will automatically publish all crates on [crates.io](https://crates.io) (if all tests pass of course).
