# Changelog

All notable changes to this project will be documented in this file.

## [0.1.4] - 2026-10-09

### Changed

- **Migrated from OpenSSL to BoringSSL** — same TLS stack as Chrome
- **Client authentication via TLS client certificates** signed by internal CA
  - Replaces previous X25519 HMAC handshake extension (`0xFFA0`)
  - Fixes active probing vulnerability: previously anyone with the public server key could construct a valid handshake
- **Client recognition moved to ALPN** (`h2,http/1.1,0tpe`)
  - Survives ClientHello normalization by BoringSSL
  - No custom TLS extension needed
- Certificate generation now via `scripts/gen_ca.sh` (creates CA + server + client certificates)

### Added

- `scripts/build_boringssl.sh` — build BoringSSL from source
- `scripts/gen_ca.sh` — internal CA, server cert, client cert
- `certs/` directory for generated certificates

### Removed

- Custom TLS extension `0xFFA0`
- HMAC-based X25519 handshake
- Nonce cache (`src/common/nonce_cache.c`)
- Old `scripts/gen_cert.sh`, `scripts/gen_keys.sh`

### Performance

- 20 parallel curls to wikipedia.org: **20/20 in 2.7 seconds** (was 11s with 14-18/20)

### Security

- **Fixed P0 active probing vulnerability** — server now requires a client certificate signed by its internal CA
- **Improved TLS fingerprint** — BoringSSL ClientHello is much closer to Chrome than OpenSSL

### Unchanged

- 16-byte 0TPE header
- Fallback to www.microsoft.com
- SOCKS5 + HTTP CONNECT + UDP relay
- DNS cache, idle timeout (all v0.1.3 fixes)

## [0.1.3] - 2026-10-06

### Added

- Client-side and server-side DNS cache (30-second TTL, 256 hosts)
- 10-second idle timeout in bidirectional relay
- 5-second grace timeout after one side closes

### Fixed

- **10x latency reduction on parallel connections**: 20 concurrent curl requests took 2 minutes instead of 2 seconds
- **Double-free on shared `SSL_CTX`**: `otpe_tls_free` no longer frees shared context
- **IPv6 connect timeout** reduced from 2 seconds to 300 ms

### Measured

- 20 parallel curl requests: **121 s → 11 s**

## [0.1.2] - 2026-10-05

### Fixed

- Race condition in `getaddrinfo` — server crashed with `Aborted (core dumped)` when 20+ concurrent connections resolved DNS. Root cause: glibc's `getaddrinfo` is not thread-safe with `AI_ADDRCONFIG`. Now serialized via mutex.
- Improper TCP close — connection was closed with `SHUT_RDWR` (sends RST). Now uses `SHUT_WR` (sends FIN).
- Relay deadlock on EOF from either side — now forwards FIN in both directions independently.

### Added

- Docker multi-stage build (31.9 MB image)
- `docker-compose.yml` with read-only rootfs
- `.dockerignore`

## [0.1.1] - 2026-10-05

First public release.

### Added

- Custom 0TPE protocol over TLS
- Reality-lite handshake (X25519 + HMAC-SHA256)
- Anti-replay nonce cache (4096 entries, 60-second window)
- Fallback to `www.microsoft.com` for unrecognized connections
- SOCKS5 TCP + UDP ASSOCIATE
- HTTP CONNECT proxy
- Multi-client server and client (pthreads)
- `otpe://` link generator
- libFuzzer target for ClientHello parser
- GitHub Actions CI
- RTT and throughput benchmarks
- `docs/SPEC.md`, `docs/THREAT_MODEL.md`, `docs/CODE_AUDIT.md`

## [0.1.0] - 2026-10-04

Initial development release.