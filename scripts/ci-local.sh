#!/usr/bin/env bash
set -euo pipefail
export CARGO_TERM_COLOR=always
export RUSTFLAGS="-D warnings"
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup manquant"; exit 2
fi
rustup toolchain install stable >/dev/null 2>&1 || true
rustup toolchain install nightly >/dev/null 2>&1 || true
rustup component add clippy rustfmt --toolchain stable >/dev/null 2>&1 || true
if ! cargo +stable install cargo-deny >/dev/null 2>&1; then true; fi
if ! cargo +stable install cargo-geiger >/dev/null 2>&1; then true; fi
if ! cargo +stable install cargo-tarpaulin >/dev/null 2>&1; then true; fi
if ! cargo +nightly install cargo-fuzz >/dev/null 2>&1; then true; fi
cargo +stable fmt --all --check
cargo +stable clippy --workspace --all-features -- -W clippy::pedantic
cargo +stable test --workspace --all-features --locked
cargo +stable deny check
cargo +stable geiger -q --all-features --output-format Json > target/geiger.json
if [ "${RUN_MIRI:-1}" = "1" ]; then
  rustup component add miri rust-src --toolchain nightly >/dev/null 2>&1 || true
  cargo +nightly miri setup
  cargo +nightly miri test --workspace --all-features
fi
if [ "${COVERAGE:-0}" = "1" ]; then
  mkdir -p target/tarpaulin
  cargo +stable tarpaulin --workspace --all-features --out Xml --output-dir target/tarpaulin
fi
if [ "${RUN_FUZZ:-0}" = "1" ]; then
  cargo +nightly fuzz build
  ASAN_OPTIONS=detect_odr_violation=0:alloc_dealloc_mismatch=0:exitcode=1 \
  UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  cargo +nightly fuzz run wire_unpack --sanitizer=address -- -max_total_time=30
fi
