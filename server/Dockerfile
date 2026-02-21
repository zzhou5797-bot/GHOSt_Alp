# Stage 1: Build
FROM rust:slim AS builder
WORKDIR /usr/src/app

# Copy the workspace configuration and Cargo files
COPY Cargo.toml Cargo.lock ./
COPY shared/Cargo.toml shared/
COPY server/Cargo.toml server/
COPY client/Cargo.toml client/

# Create dummy src files to build dependencies for caching
RUN mkdir -p shared/src server/src client/src \
    && echo "fn main() {}" > server/src/main.rs \
    && echo "fn main() {}" > client/src/main.rs \
    && touch shared/src/lib.rs

# Initialize git if needed by any build scripts, mostly dummy
RUN cargo build --release --bin server || true

# Copy real source code
COPY shared/src/ shared/src/
COPY server/src/ server/src/
# Client is not needed for the server image, but copied to satisfy workspace
COPY client/src/ client/src/

# Touch src files to ensure they are recompiled
RUN find . -name "*.rs" -exec touch {} + && cargo build --release --bin server

# Stage 2: Runtime
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /usr/src/app/target/release/server /usr/local/bin/server

# Expose ports
EXPOSE 8080/udp
EXPOSE 8081/tcp

ENTRYPOINT ["/usr/local/bin/server"]
