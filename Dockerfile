# syntax=docker/dockerfile:1

# ---- builder ---------------------------------------------------------------
FROM rust:1.94-slim-bookworm AS builder
WORKDIR /app

# Cache dependencies: build a stub crate with the real manifest first so this
# layer is only invalidated when Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/warden* target/release/warden*

COPY src ./src
# (`tests/` is not needed for a release build)
RUN cargo build --release --locked \
    && strip target/release/warden

# ---- runtime ---------------------------------------------------------------
# debian-slim rather than distroless: it has bash, which gives us a healthcheck
# without adding curl (see HEALTHCHECK) and a shell for `docker exec` debugging.
FROM debian:bookworm-slim AS runtime

# reqwest uses rustls with the platform verifier => the system CA store is
# required at runtime for HTTPS to cvelistV5 / NVD / CISA / FIRST.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin warden \
    && mkdir /data && chown 10001:10001 /data

COPY --from=builder /app/target/release/warden /usr/local/bin/warden

LABEL org.opencontainers.image.source="https://github.com/Jacob-Tate/warden" \
      org.opencontainers.image.description="Self-hosted CVE monitoring feed for AI agents over MCP" \
      org.opencontainers.image.licenses="UNLICENSED"

ENV WARDEN_DB_PATH=/data/warden.db \
    WARDEN_BIND=0.0.0.0:8080 \
    RUST_LOG=info

USER 10001:10001
VOLUME /data
EXPOSE 8080

# /healthz is 200 (ok or stale) or 503 (database unreachable). bash's /dev/tcp
# avoids shipping curl/wget in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["warden"]
CMD ["serve"]
