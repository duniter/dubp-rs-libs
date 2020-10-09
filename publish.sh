#!/bin/sh

VERSION_NAME=${CI_COMMIT_TAG#v}
echo "publish v$VERSION_NAME ..."

wait_crate() {
    v=$(curl -s "https://crates.io/api/v1/crates/${1}" | jq '.crate.max_version')
    while [ $v != "\"$VERSION_NAME\"" ]
    do
    echo "${1} not updated, wait …"
    echo $v
    sleep 5
    v=$(curl -s "https://crates.io/api/v1/crates/${1}" | jq '.crate.max_version')
    done
}

cargo publish --manifest-path crypto/Cargo.toml || exit 1
wait_crate "dup-crypto"
cargo publish --manifest-path common/Cargo.toml || exit 1
wait_crate "dubp-common"
cargo publish --manifest-path wallet/Cargo.toml || exit 1
wait_crate "dubp-wallet"
cargo publish --manifest-path documents/Cargo.toml || exit 1
wait_crate "dubp-documents"
cargo publish --manifest-path documents-parser/Cargo.toml || exit 1
wait_crate "dubp-documents-parser"
cargo publish --manifest-path block/Cargo.toml || exit 1
