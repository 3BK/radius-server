# syntax=docker/dockerfile:1.7

##
## Build stage
## - Uses a modern Rust toolchain compatible with edition 2024.
## - Produces a fully static musl binary.
## - Uses BuildKit cache mounts for faster, reproducible rebuilds.
##
FROM rust:1.86-bookworm AS builder

ARG TARGET_TRIPLE=x86_64-unknown-linux-musl
ARG BIN_NAME=kanidm_radsec_edge

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools \
        clang \
        llvm \
        cmake \
        make \
        pkg-config \
        ca-certificates \
    && rustup target add ${TARGET_TRIPLE} \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/radsec

# Pre-copy manifests first to maximize layer/cache reuse.
COPY Cargo.toml ./
COPY src ./src
COPY tests ./tests

# Build static binary.
# NOTE: if you later add Cargo.lock, also copy it and keep --locked.
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/radsec/target \
    cargo build --release --target ${TARGET_TRIPLE}

# Prepare minimal runtime filesystem layout.
RUN install -d -m 0555 /out/bin \
    && install -d -m 0555 /out/etc/radsec \
    && install -d -m 0555 /out/var/empty \
    && cp /usr/src/radsec/target/${TARGET_TRIPLE}/release/${BIN_NAME} /out/bin/${BIN_NAME} \
    && chmod 0555 /out/bin/${BIN_NAME}

##
## Runtime stage
## - Distroless static runtime keeps attack surface extremely small.
## - Non-root by default.
## - No shell, no package manager.
##
FROM gcr.io/distroless/static-debian12:nonroot

ARG BIN_NAME=kanidm_radsec_edge

# OCI labels (adjust as desired)
LABEL org.opencontainers.image.title="radsec_server" \
      org.opencontainers.image.description="Kanidm-aware EAP-TLS-only RadSec edge" \
      org.opencontainers.image.source="local-build" \
      org.opencontainers.image.licenses="Proprietary-or-local"

# Copy in binary and pre-created runtime directories.
COPY --from=builder --chown=65532:65532 /out/bin/${BIN_NAME} /bin/${BIN_NAME}
COPY --from=builder --chown=65532:65532 /out/etc/radsec /etc/radsec
COPY --from=builder --chown=65532:65532 /out/var/empty /var/empty

# Runtime defaults
ENV RADSEC_CONFIG=/etc/radsec/config.toml \
    RUST_LOG=info

WORKDIR /var/empty

# RadSec listens on TCP 2083 in your config.
EXPOSE 2083/tcp

# Distroless nonroot image already uses a non-root uid/gid.
USER 65532:65532

# Use SIGTERM for graceful shutdown in orchestrators.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/bin/kanidm_radsec_edge"]
