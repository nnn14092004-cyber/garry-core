# Stage 1: Deterministic Pure-Rust Builder
FROM rust:1.82-slim AS builder
WORKDIR /usr/src/garry-core

COPY Cargo.toml ./
COPY src ./src

# Build release binary directly with zero heap overhead
RUN cargo build --release --bin garry

# Stage 2: Minimal Air-Gapped Runtime Container
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN useradd -m -u 10001 garryuser && \
    mkdir -p /app/garry_workspace/knowledge /app/.garry && \
    chown -R garryuser:garryuser /app

COPY --from=builder /usr/src/garry-core/target/release/garry /usr/local/bin/garry

USER garryuser
ENTRYPOINT ["/usr/local/bin/garry"]
CMD ["interactive"]