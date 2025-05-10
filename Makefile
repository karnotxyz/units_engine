# Linting commands
ALLOW_DIRTY_FLAG := $(if $(ALLOW_DIRTY),--allow-dirty,)

.PHONY: lint
lint:
	# Rust linting
	cargo fmt 
	cargo clippy --workspace --all-features --no-deps --fix $(ALLOW_DIRTY_FLAG) -- -D warnings
	cargo clippy --workspace --all-features --tests --no-deps --fix $(ALLOW_DIRTY_FLAG) -- -D warnings
	# Code style linting
	npx prettier --write .
	npx markdownlint-cli --config .markdownlint.json .
	npx @taplo/cli@latest fmt --config ./taplo/taplo.toml
