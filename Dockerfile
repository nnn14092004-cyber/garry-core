# Stage 1: Deterministic Pure-Rust Builder
FROM rust:1.82-slim AS builder
WORKDIR /usr/src/garry-core

COPY Cargo.toml ./
COPY src ./src

# Build toàn bộ release target của crate
RUN cargo build --release

# Stage 2: Minimal Air-Gapped Runtime Container
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN useradd -m -u 10001 garryuser && \
    mkdir -p /app/garry_workspace/knowledge /app/.garry && \
    chown -R garryuser:garryuser /app

# Copy binary từ target/release (Cargo tự động lấy binary chính của crate)
COPY --from=builder /usr/src/garry-core/target/release/garry-core /usr/local/bin/garry

USER garryuser
ENTRYPOINT ["/usr/local/bin/garry"]
CMD ["interactive"]