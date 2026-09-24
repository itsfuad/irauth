.PHONY: build test check fmt install validate

build:
	cargo build --release --workspace

test:
	cargo test --workspace

check:
	cargo check --workspace --all-targets
	cargo clippy --workspace --all-targets
	cargo test --workspace

fmt:
	cargo fmt --all

validate:
	./scripts/validate-repo.sh

install:
	sudo ./scripts/install.sh --configure
