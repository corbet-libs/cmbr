#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc -Vv
cargo --version
date -u +%FT%TZ
cargo update
python3 .github/check-first-party.py --archive
sha256sum Cargo.lock
printf '%s\n' 'BEGIN_RESOLVED_LOCK_BASE64'
base64 -w 0 Cargo.lock
printf '\n%s\n' 'END_RESOLVED_LOCK_BASE64'
