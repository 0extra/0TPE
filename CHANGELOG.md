# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-10-09

### Fixed

- **Mutual TLS failed with `server certificate verification failed`** — `scripts/gen_ca.sh` did not add `basicConstraints=CA:TRUE` to the internal CA, so OpenSSL 3.x / BoringSSL refused to build a chain from it. Both the client and the server rejected each other's certificates. Regenerate certificates with the updated script.
- **UDP did not work end-to-end** — the server's `handle_client` read the header of the first `OTPE_CMD_UDP` frame and passed control to `handle_udp_session` without consuming the frame's payload. The session then tried to read a second header from stale bytes, `otpe_decode_header` failed, and the connection closed. The first frame's payload is now parsed before entering the session loop.
- **Client UDP session race** — `udp_session_thread` was created with `pthread_detach`, but `udp_find_or_create` called `pthread_join` on slot reuse. Join on a detached thread returns `EINVAL` immediately, and the code then freed `s->tls` and closed `s->server_fd` while the thread was still running (use-after-free). Thread is no longer detached; join works correctly.
- **Client UDP poll missed buffered TLS data** — `udp_session_thread` polled the raw TLS fd without checking `otpe_tls_pending`. If the server wrote two UDP frames back-to-back, the second was stuck in OpenSSL's internal buffer until the poll timeout. Now checks `otpe_tls_pending` before polling, matching `otpe_relay_tls_bidirectional`.
- ClientHello parser buffer for `tls_peek_clienthello` was smaller than the documented limit.

### Added

- **Config validation** (`config_validate_client` / `config_validate_server`) — checks that `server_ip` / `listen_ip` / `sni` / `fallback_sni` are non-empty, that `socks_port != http_port`, that `token` is a valid hex string of at least `OTPE_TOKEN_SIZE * 2` characters, and that all referenced certificate and key files are readable. Errors are reported before the process opens any sockets.
- **`tests/test_udp_stress.c`** — 25 concurrent clients × 10 UDP echo queries through the tunnel, with a local UDP echo server on `127.0.0.1` as the target. No DNS, no external network. Verifies byte-for-byte reply matching and reports per-client success.
- **`tests/run_all.sh`** — one-shot test runner. Builds if needed, starts the server and client under `stdbuf -oL` (so SIGKILL doesn't lose buffered logs), runs unit + integration + fuzz tests, prints a summary, and dumps client/server log tails on failure.
- **`make test`** target.
- Line-buffered log capture in the test runner.

### Changed

- `scripts/gen_ca.sh` now adds `basicConstraints`, `keyUsage` and `extendedKeyUsage` to the CA, the server certificate, and the client certificate:
  - CA: `basicConstraints=critical,CA:TRUE`, `keyUsage=critical,keyCertSign,cRLSign`
  - Server: `basicConstraints=CA:FALSE`, `keyUsage=digitalSignature,keyEncipherment`, `extendedKeyUsage=serverAuth`, SAN for the SNI
  - Client: `basicConstraints=CA:FALSE`, `keyUsage=digitalSignature`, `extendedKeyUsage=clientAuth`
- `Makefile` builds `otpe-test-udp-stress` and exposes the `test` target.
- Token validation accepts hex strings longer than `OTPE_TOKEN_SIZE * 2` characters. `config_token_to_bytes` already used only the first 8 bytes, so existing 32-character tokens in `0tpe.conf` continue to work unchanged.

### Removed

- Silent acceptance of unreadable certificate and key paths (previously failed later, inside the TLS handshake, with a less useful message).

### Unchanged

- 16-byte header, BoringSSL, ALPN marker (`h2,http/1.1,0tpe`), fallback to `www.microsoft.com`
- SOCKS5 + HTTP CONNECT + UDP ASSOCIATE
- DNS cache, idle timeout, grace timeout

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