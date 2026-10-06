## [0.1.3] - 2026-10-06

### Added

- Client-side and server-side DNS cache (30s TTL, up to 256 hosts)
- 10-second idle timeout in bidirectional relay (kills stuck connections)
- 5-second grace timeout after one side closes

### Fixed

- **10x latency reduction on parallel connections**: 20 concurrent curl requests took 2 minutes instead of 2 seconds. Root causes were: (a) `SSL_shutdown` blocking on `close_notify` forever, (b) no idle timeout in relay so stuck TLS handshakes held connections until TCP FIN timeout (120s), (c) serialized `getaddrinfo` under global mutex.
- **Double-free on shared SSL_CTX**: server now uses a single pre-initialized `SSL_CTX` shared across all connections. `otpe_tls_free` no longer frees shared context.
- **IPv6 connect timeout too high**: reduced from 2s to 300ms per address.
- **DNS serialization**: `getaddrinfo` under mutex only runs on cache miss.

### Measured

- 20 parallel curl requests: **121s → 11s** (10x speedup)
- 3 parallel requests: 2.1s → 0.55s