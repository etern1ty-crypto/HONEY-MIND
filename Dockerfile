# syntax=docker/dockerfile:1
FROM rust:1.93.1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY config.example.toml ./config.example.toml
COPY deploy/sensor.toml ./deploy/sensor.toml
COPY examples/e2e/minotaur.toml ./examples/e2e/minotaur.toml
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN mkdir -p /etc/minotaur /var/lib/minotaur \
    && chown -R 65532:65532 /etc/minotaur /var/lib/minotaur \
    && chmod 700 /var/lib/minotaur
COPY --from=builder /build/target/release/minotaur /usr/local/bin/minotaur
COPY --chown=65532:65532 deploy/container.toml /etc/minotaur/minotaur.toml
USER 65532:65532
WORKDIR /var/lib/minotaur
EXPOSE 2222 8080 2323 6379 9090
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/minotaur", "healthcheck", "--address", "127.0.0.1:9090"]
ENTRYPOINT ["/usr/local/bin/minotaur"]
CMD ["--config", "/etc/minotaur/minotaur.toml", "run"]
