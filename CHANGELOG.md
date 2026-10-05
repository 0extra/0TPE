# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-10-05

### Added

- Custom 0TPE transport protocol with a 16-byte fixed header
- TLS wrapper on top of OpenSSL 3.x
- Reality-lite handshake: X25519 ECDH + HMAC-SHA256 authentication
- Active probing defense with transparent fallback to `www.microsoft.com`
- Anti-replay protection: timestamp window (±30s) + in-memory nonce cache (4096 entries, 60s window)
- SOCKS5 server (TCP CONNECT + UDP ASSOCIATE)
- HTTP CONNECT proxy on `127.0.0.1:8080`
- Multi-session UDP relay with per-client TLS sessions
- Multi-client support (pthreads, no thread count limit)
- Config file (`0tpe.conf`) with hot-reloadable key=value format
- IPv4 and IPv6 support with automatic fallback
- `otpe://` link generator (`otpe-genlink`)
- Full test suite: `otpe-test`, `otpe-test-crypto`, `otpe-test-udp`
- libFuzzer target for ClientHello parser (63M executions, 0 crashes)
- GitHub Actions CI (build + test + fuzz)
- RTT and throughput benchmarks
- Docker multi-stage build (31.9 MB final image)
- `docker-compose.yml` with read-only rootfs and config mounts

### Protocol

- Version 0x01
- Commands: PING, PONG, CONNECT, UDP
- Frame format documented in `docs/SPEC.md`

### Documentation

- `README.md` — installation, usage, benchmarks
- `docs/SPEC.md` — protocol specification in RFC style
- `docs/THREAT_MODEL.md` — adversaries, capabilities, limitations
- `docs/CODE_AUDIT.md` — internal code review

### Known limitations

- No multiplexing — each connection is a new TLS session
- OpenSSL ClientHello fingerprint differs from Chrome
- No mutual authentication (client does not verify server)
- UDP relay does not support multicast/broadcast