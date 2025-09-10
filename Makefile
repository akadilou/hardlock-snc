.PHONY: all fmt lint test deny bench fuzz

all: fmt lint test deny

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

deny:
	cargo deny check advisories
	cargo deny check bans
	cargo deny check licenses
	cargo deny check sources

bench:
	cargo bench --bench hpke_bench
	cargo bench --bench aead_bench
	cargo bench --bench argon_bench
