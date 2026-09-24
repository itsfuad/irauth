.PHONY: build test check install validate

build:
	cargo build --release --workspace

test:
	cargo test --workspace

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

validate:
	./scripts/validate-repo.sh

install:
	sudo ./scripts/install.sh --configure
