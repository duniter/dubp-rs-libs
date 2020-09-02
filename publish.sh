#!/bin/sh

cargo publish --manifest-path crypto/Cargo.toml || exit 1
sleep 15
cargo publish --manifest-path common/Cargo.toml || exit 1
sleep 15
cargo publish --manifest-path wallet/Cargo.toml || exit 1
sleep 15
cargo publish --manifest-path documents/Cargo.toml || exit 1
sleep 15
cargo publish --manifest-path documents-parser/Cargo.toml || exit 1
sleep 15
cargo publish --manifest-path block/Cargo.toml || exit 1
