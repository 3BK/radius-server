# radsec_server

A high-performance, hardened RADIUS-over-TLS (RadSec) server built in Rust. Designed for zero-trust environments, it attempts to eliminate external dependencies for secret management while aligning with the aspirations of NIST SP 800-53, PCI DSS 4.0, NIST STIG, CIS, and ISO 27001.

## Security Architecture

* **Post-Quantum mTLS:** Enforces mutual TLS 1.3 with a FIPS-compliant cryptographic boundary (`aws-lc-rs`), mandating ECDHE with P-384 paired with hybrid Post-Quantum key exchanges.
* **Local Secret Protection:** Eliminates cloud-api attack vectors by reading keys from local volumes while actively enforcing POSIX permission checks (0600/0400) at runtime.
* **Volumetric DoS Defense:** Utilizes an in-memory token-bucket governor keyed by IP address to drop abusive connections before expensive cryptographic handshakes occur.
* **Zero-Surface Containerization:** Statically compiled using `musl` with stripped symbols, producing a minimal, immutable runtime.
* **Structured Audit Logging:** Outputs strict JSONL telemetry to stdout for tamper-resistant ingestion by SIEM tools.

## Project Structure

* **`Makefile`**: Primary build, audit, and packaging orchestrator.
* **`Cargo.toml`**: Minimal-dependency definition with an optimized, stripped, and aborted-panic release profile.
* **`.cargo/config.toml`**: Target configuration forcing static C-runtime linkage.
* **`config.toml`**: Human-readable server configuration.
* **`src/main.rs`**: Application initialization, structured logging, and orchestrator.
* **`src/config.rs`**: Validates TOML ingestion and enforces OS-level private key permissions.
* **`src/crypto.rs`**: Configures FIPS/PQ cryptography, ALPN validation, and mTLS.
* **`src/server.rs`**: High-throughput async connection loop with governor rate-limiting and graceful shutdown.

## Quick Start

### Prerequisites
* Rust 1.90.0+
* `musl-tools`, `clang`, `llvm`, `nasm` (for static compilation)
* `cargo-audit` and `cargo-cyclonedx` (installed via `make setup`)

### Build & Test Workflow
We use a `Makefile` to ensure reproducible, secure builds:

1.  **Initialize Environment:**
    ```bash
    make setup
    ```
2.  **Run Security Audits & Tests:**
    ```bash
    make audit
    cargo test
    ```
3.  **Build Static Release & Generate SBOM:**
    ```bash
    make
    ```
    *This generates the binary and SBOM inside `./linux-musl-static-release-bundle/`.*

### Configuration
The server looks for a configuration file at `/etc/radsec/config.toml` by default. You can override this path using the environment variable:

```bash
export RADSEC_CONFIG=/path/to/your/custom_config.toml
./linux-musl-static-release-bundle/radsec_server
```

## Security Compliance Targets
This implementation is designed to support the following regulatory controls:

* NIST AU-2: Audit event generation via structured JSONL logs.

* PCI DSS Req 10: Tamper-evident logging and auditable system access.

* NIST SC-5: Denial of Service protection via keyed rate-limiting.

* STIG / CIS: Minimal attack surface via static linking and strict file permission validation on secrets.
