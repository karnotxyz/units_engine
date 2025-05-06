# Build stage
FROM rust:1.85-slim-bullseye AS builder

# Install build dependencies
RUN set -eux; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a new empty shell project
WORKDIR /usr/src/units_engine
COPY . .

# Build the project
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN set -eux; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl1.1 \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/units_engine/target/release/units_engine /usr/local/bin/units_engine

# Set the entrypoint
ENTRYPOINT ["units_engine"]
