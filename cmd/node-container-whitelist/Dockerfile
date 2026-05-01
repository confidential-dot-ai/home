FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY build/c8s /usr/local/bin/c8s
RUN chmod +x /usr/local/bin/c8s

ENTRYPOINT ["/usr/local/bin/c8s", "node-container-whitelist"]
