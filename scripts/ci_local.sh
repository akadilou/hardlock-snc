#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all -- --check
cargo build --locked
cargo build --examples --locked
cargo test --locked --all
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check advisories
cargo deny check bans
cargo deny check licenses
cargo deny check sources
