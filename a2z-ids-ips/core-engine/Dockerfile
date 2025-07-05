# Multi-stage build for A2Z IDS/IPS Core Engine
FROM rust:1.75-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Cache dependencies
RUN cargo build --release && rm -rf src target/release/deps/a2z_ids_core*

# Copy source code
COPY src/ ./src/

# Build the application
ARG BUILD_TYPE=release
RUN if [ "$BUILD_TYPE" = "debug" ]; then \
        cargo build; \
    else \
        cargo build --release; \
    fi

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    ca-certificates \
    curl \
    procps \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create a2z-ids user
RUN groupadd -r a2z-ids && useradd -r -g a2z-ids a2z-ids

# Create directories
RUN mkdir -p /var/lib/a2z-ids/{rules,models,pcap,data} \
    && mkdir -p /var/log/a2z-ids \
    && mkdir -p /etc/a2z-ids \
    && chown -R a2z-ids:a2z-ids /var/lib/a2z-ids /var/log/a2z-ids

# Copy binary
ARG BUILD_TYPE=release
COPY --from=builder /app/target/${BUILD_TYPE}/a2z-ids /usr/local/bin/a2z-ids

# Copy default configuration
COPY config/ /etc/a2z-ids/

# Set permissions
RUN chmod +x /usr/local/bin/a2z-ids

# Create healthcheck script
RUN echo '#!/bin/bash\n\
/usr/local/bin/a2z-ids health || exit 1' > /usr/local/bin/healthcheck.sh \
    && chmod +x /usr/local/bin/healthcheck.sh

# Switch to a2z-ids user for non-privileged operations
USER a2z-ids

# Set environment variables
ENV A2Z_CONFIG_PATH=/etc/a2z-ids/config.yaml
ENV A2Z_RULES_PATH=/var/lib/a2z-ids/rules
ENV A2Z_MODELS_PATH=/var/lib/a2z-ids/models
ENV A2Z_LOG_PATH=/var/log/a2z-ids
ENV RUST_LOG=info

# Expose metrics port
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Set working directory
WORKDIR /var/lib/a2z-ids

# Default command
CMD ["/usr/local/bin/a2z-ids", "run", "--config", "/etc/a2z-ids/config.yaml"] 