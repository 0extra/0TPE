# ---- Stage 1: build ----
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Makefile 0tpe.conf ./
COPY include ./include
COPY src    ./src

RUN make clean && make otpe-server

# ---- Stage 2: runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/otpe-server /app/otpe-server
COPY --from=builder /build/0tpe.conf   /app/0tpe.conf

EXPOSE 8443/tcp

CMD ["/app/otpe-server", "/app/0tpe.conf"]