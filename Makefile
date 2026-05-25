# Variables
TARGET = x86_64-unknown-linux-musl
RUST_VERSION = 1.90.0
BINARY_NAME = radsec_server
SBOM_NAME = radius_server_sbom
BUNDLE_DIR = linux-musl-static-release-bundle

# Environment variables for the build step
export CARGO_TERM_COLOR = always
export CC_x86_64_unknown_linux_musl = musl-gcc
export RUSTFLAGS = -C target-feature=+crt-static -C strip=symbols

.PHONY: all setup setup-sys setup-rust setup-tools audit sbom build bundle clean

# The default target runs the full pipeline minus system/tool setup
all: audit sbom build bundle

# ---------------------------------------------------------
# Setup Targets
# ---------------------------------------------------------

setup: setup-sys setup-rust setup-tools

setup-sys:
	@echo "Installing system dependencies (requires sudo)..."
	sudo apt-get update
	sudo apt-get install -y musl-tools cmake clang llvm nasm

setup-rust:
	@echo "Setting up Rust toolchain $(RUST_VERSION) with $(TARGET) target..."
	rustup toolchain install $(RUST_VERSION)
	rustup default $(RUST_VERSION)
	rustup target add $(TARGET)

setup-tools:
	@echo "Installing Cargo security and supply chain tools..."
	cargo install cargo-audit
	cargo install cargo-cyclonedx

# ---------------------------------------------------------
# CI/CD Pipeline Targets
# ---------------------------------------------------------

audit:
	@echo "Running Cargo Audit (CVE Check)..."
	cargo audit

sbom:
	@echo "Generating CycloneDX SBOM..."
	cargo cyclonedx --format json --all-features --override-filename $(SBOM_NAME)

build:
	@echo "Building statically linked release for $(TARGET)..."
	cargo build --release --target $(TARGET)

# Mimics the actions/upload-artifact step by grouping the files
bundle: build sbom
	@echo "Packaging final artifacts into ./$(BUNDLE_DIR)..."
	mkdir -p $(BUNDLE_DIR)
	cp target/$(TARGET)/release/$(BINARY_NAME) $(BUNDLE_DIR)/
	cp $(SBOM_NAME).json $(BUNDLE_DIR)/
	@echo "Release bundle successfully created!"

clean:
	@echo "Cleaning workspace..."
	cargo clean
	rm -rf $(BUNDLE_DIR)
	rm -f $(SBOM_NAME).json
