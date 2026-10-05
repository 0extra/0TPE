# 0TPE Code Audit

Version: 1
Date: 2026
Scope: `src/common/*`, `src/server/main.c`, `src/client/main.c`
Reviewer: internal (author + AI)
Method: manual source review

This document is an honest engineering review, not a marketing document.
Where behavior is verified by test, the test is cited. Where a risk is
identified, it is marked **RISK**. Where a question remains open, it is
marked **TODO**.

---

## src/common/protocol.c

**Purpose:** encode/decode the 16-byte 0TPE frame header.

**Reviewed functions:**
- `otpe_checksum` — XOR-rotate checksum, single round over 16 bytes.
- `otpe_encode_header` — writes fields in network byte order.
- `otpe_decode_header` — reads fields from network byte order.
- `otpe_validate_header` — checks version only.

**Findings:**

- Checksum is intentionally weak. It catches random bit flips, not
  malicious tampering (payload is inside TLS anyway, so integrity is
  handled by TLS). OK.
- `otpe_validate_header` does not check `command` against known values.
  Unknown commands fall through to `otpe_tls_free(tls)` and connection
  closes. Acceptable.
- No check on `flags` or `reserved` fields. Currently they must be 0 but
  no code enforces this. **Minor.**
- Length field is `uint16`, maximum 65535. Larger payloads must be split
  by caller. Not documented in SPEC. **TODO.**

**Verified tests:** `tests/test_protocol.c` — round-trip encode/decode.

**Overall:** clean, small, no issues found.

---

## src/common/crypto.c

**Purpose:** X25519 key loading, extension build/verify, HMAC-SHA256.

**Reviewed functions:**
- `crypto_load_private_key` / `crypto_load_public_key` — PEM loading.
- `crypto_free_key` — EVP_PKEY_free.
- `derive_shared` — X25519 ECDH.
- `crypto_build_extension` — client side, 60-byte payload.
- `crypto_verify_extension` — server side, HMAC verification + replay check.

**Findings:**

- **RISK (low):** `crypto_load_private_key` does not call
  `PEM_read_PrivateKey` with a password callback. If the key is
  password-protected, loading will fail. Documented as "raw key only".
- `derive_shared` correctly checks `len > *out_len`. No buffer overrun.
- `crypto_build_extension` uses `RAND_bytes` for nonce — correct CSPRNG.
- **RISK (medium):** `crypto_verify_extension` iterates over 61 possible
  timestamps, each computing HMAC-SHA256. Under high load, this is
  61 × HMAC cost per connection. At 10K connections/second, this is
  ~600K HMAC operations/second. Each HMAC on X25519 shared secret is
  ~1–2 μs on modern hardware. So ~1 ms of CPU per connection. Acceptable
  for a hobby server, notable for a large deployment. **TODO: profile.**
- **RISK (low):** `time(NULL)` is used both for timestamp generation and
  verification. If the system clock is set backward during operation,
  previously cached nonces may still be accepted. Unlikely.
- Replay check is done **after** HMAC verification. Correct order —
  HMAC is O(1), replay check is O(4096). Saves CPU on garbage.
- **RISK (medium):** `nonce_cache_check_and_add` returns -1 if the
  cache is full (wait, actually it doesn't; it overwrites the oldest
  slot via ring buffer). Let me re-read... Yes, it uses `g_next_slot =
  (g_next_slot + 1) % CACHE_SIZE;` so it always writes. No failure mode.
  But this means under sustained load, an old nonce can be evicted before
  its 60-second window expires. See THREAT_MODEL section 4.5.
- No explicit zeroing of `shared` after use. The `uint8_t shared[64]`
  variable stays on the stack until function returns. Modern
  `EVP_PKEY_derive` does not zero either. **Minor.**

**Verified tests:** `tests/test_crypto.c` — round-trip, wrong key,
tampered HMAC, short input, garbage input, replay rejection.

**Overall:** correct, but with performance and replay-cache-size caveats
documented.

---

## src/common/nonce_cache.c

**Purpose:** in-memory cache to reject replayed handshakes.

**Reviewed functions:**
- `nonce_cache_init` — clears cache.
- `nonce_cache_check_and_add` — linear scan + insert.

**Findings:**

- **RISK (low):** cache is initialized only via explicit call. If the
  server forgets to call `nonce_cache_init`, the cache is zero-initialized
  (correct because static), but `g_next_slot` is 0. First nonce overwrites
  slot 0. Works but no clean.
- **RISK (medium):** 4096 entries with linear scan is O(n) = 4096
  comparisons per connection. At 10K connections/second, this is 40M
  comparisons/second. Each comparison is `memcmp` on 12 bytes. Roughly
  ~0.5 ms of CPU per connection at full load. **TODO: measure.**
- **RISK (low):** the cache does not use a hash. A single hashed bucket
  would drop to O(1). Change is straightforward: replace the linear scan
  with a simple open-addressing hash table keyed on the first 4 bytes
  of the nonce.
- **RISK (medium):** under high load (>4096 unique handshakes per 60
  seconds), slots are overwritten before their natural expiry. An
  attacker who can generate 5000 unique handshakes in 60 seconds and
  then replay an earlier one will succeed. For a hobby server, unlikely.
  For an adversarial deployment, real.
- **RISK (low):** `memcpy(slot->nonce, nonce, nonce_len)` with `nonce_len ≤ 32`.
  Buffer is 32 bytes. Safe.
- Locking is `pthread_mutex_t` with `PTHREAD_MUTEX_INITIALIZER`. Correct.
- No explicit cleanup of expired entries. Slots just become "stale" and
  get overwritten by ring buffer. Fine.

**Verified tests:** covered indirectly by `tests/test_crypto.c` replay test.

**Overall:** works, but the linear scan and 4096-entry limit are the
weakest points. Not a security hole at typical load.

---

## src/common/tls.c

**Purpose:** OpenSSL wrapper for client and server.

**Reviewed functions:**
- `otpe_tls_init` — `pthread_once` SSL_library_init.
- `otpe_tls_set_server_pubkey` — global pointer for extension callback.
- `otpe_ext_add_cb` — OpenSSL callback for custom extension.
- `otpe_tls_server` — TLS_accept with self-signed cert.
- `otpe_tls_client` — SSL_connect with Chrome-like ciphers + extension.
- `otpe_tls_send` / `otpe_tls_recv` — SSL_write/read.

**Findings:**

- **RISK (medium):** `g_server_pubkey` is a process-global pointer with
  no lock. Set once at startup, read by all threads in
  `otpe_ext_add_cb`. Safe because it's set before any connection is
  accepted. Documented but fragile if code changes.
- **RISK (medium):** `static uint8_t data[OTPE_EXT_DATA_SIZE]` inside
  `otpe_ext_add_cb`. **This is not thread-safe!** If two threads call
  `SSL_connect` on the same process, they both write to the same static
  buffer. **BUG.**

  Wait — is `otpe_ext_add_cb` called from `SSL_connect`? Yes. And the
  client can run multiple `SSL_connect` calls in parallel (one per
  tunnel thread in `establish_tunnel`). **This is a real race condition.**

  Impact: two concurrent client tunnels could produce corrupted
  extensions, or worse, the same extension reused. Server would accept
  the first and reject the second (replay), so behavior is: **one of
  two concurrent tunnels fails to authenticate**. Actually no — replay
  rejection means only one of the two is accepted. So **concurrent
  connections from the same client can intermittently fail.**

  **This bug was not caught because we only tested sequential curl calls.**
  Need to fix: change `static` to thread-local, or allocate per-SSL
  storage.

  **TODO: fix before v0.2.**

- `otpe_tls_server` sets `SSL_CTX_set_min_proto_version(TLS1_2)`.
  Cannot downgrade to TLS 1.0/1.1. Good.
- `otpe_tls_client` sets `SSL_VERIFY_NONE`. Intentional (see THREAT_MODEL 5.5).
- `otpe_tls_client` sets Chrome-like ciphers/groups/sigalgs. Does not
  set extension order or GREASE. Partial fingerprint only.
- `otpe_tls_free` calls `SSL_shutdown` which may block if peer is dead.
  Should use `SSL_shutdown` once and ignore return. Currently blocks.
  **Minor.**
- No call to `SSL_CTX_set_options(..., SSL_OP_NO_RENEGOTIATION)`. A
  server-side renegotiation attack is theoretically possible. OpenSSL 3
  disables renegotiation by default for TLS 1.3. For TLS 1.2, still
  enabled. **Minor.**
- `otpe_tls_send` does not loop on partial writes. `SSL_write` returns
  the number of bytes written, which may be less than `len`. Caller
  must retry. **RISK (low):** currently callers do not retry. Under
  normal conditions, `SSL_write` writes everything, but under memory
  pressure or with large buffers, it can return partial. **TODO:**
  wrap in a loop.

**Verified tests:** indirect — client and server connect, transfer
data via relay, receive expected HTML. But no test for concurrent
connect from the same process. **TODO.**

**Overall:** the static-buffer race in `otpe_ext_add_cb` is the most
serious finding in this audit. It will manifest under concurrent use
(multi-tab browsing, parallel curl). Fix required.

---

## src/common/tls_peek.c

**Purpose:** parse ClientHello without decrypting, to decide fallback.

**Reviewed functions:**
- `rd16` — helper.
- `tls_parse_clienthello` — pure parser on a buffer.
- `tls_peek_clienthello` — MSG_PEEK loop + parse.

**Findings:**

- **RISK (medium):** the peek buffer is 8192 bytes. Real ClientHellos
  are typically 200–600 bytes, but with ECH, ALPS, or large extensions
  they can exceed 8 KB. If the ClientHello is larger, the parser will
  see a truncated record and return -1, triggering fallback. This is
  **fail-safe** (fallback is safe) but means legitimate clients using
  very large ClientHellos would be misrouted.
- **RISK (medium):** `tls_peek_clienthello` uses `recv(MSG_PEEK)` in
  a loop with `usleep(10000)` if new data hasn't arrived. Under
  high load or slow clients, this can spin. Timeout is 3000 ms total.
  Acceptable.
- **RISK (low):** if a client sends a TLS record that spans multiple
  TCP segments (rare but legal), we only see the first segment.
  Realistically ClientHello fits in one segment.
- **RISK (low):** `tls_parse_clienthello` handles only one TLS record.
  If the ClientHello were fragmented across multiple records (only
  possible if > 16 KB, impossible for ClientHello), parse would fail.
- Length field checks: `pos + el > ext_end` — no overflow because
  `pos ≤ 8192`, `el ≤ 65535`, sum ≤ 73727, fits in size_t.
- SNI parsing: checks `5 + nl <= el`, but `nl` can be 0 → SNI empty.
  Empty SNI is handled gracefully (server uses fallback_sni).
- **RISK (low):** extension parsing does not handle GREASE values
  (0x0A0A, 0x1A1A, ..., 0xFAFA) specially. GREASE is ignored (unknown
  extension type → skipped). Correct.

**Verified tests:** `tests/test_protocol.c` does NOT test this.
**Fuzzer** covers it — `fuzz/fuzz_clienthello.c`.

**Overall:** correct, but the 8 KB buffer limit is a real (if rare)
constraint. Should be documented.

---

## src/common/socks5.c

**Purpose:** SOCKS5 handshake on the client.

**Reviewed functions:**
- `read_full`, `write_full` — with poll + EINTR.
- `socks5_handshake` — greeting, request, reply.

**Findings:**

- Handles IPv4 (`ATYP=0x01`), IPv6 (`ATYP=0x04`), domain (`ATYP=0x03`).
  Correct format for IPv6 as `%02x%02x:...:...`. Verified by
  Wikipedia over IPv6.
- **RISK (low):** SOCKS5 handshake timeout is 10 seconds
  (`SOCKS5_TIMEOUT_MS`). If a slow client (browser) takes longer, the
  handshake fails and connection closes. Rare.
- **RISK (low):** no support for `BIND` or `UDP ASSOCIATE` commands,
  only `CONNECT` (0x01). Documented.
- No authentication methods accepted except `0x00` (no auth). Correct
  for local-only listener on `127.0.0.1`.
- Error paths close the fd. No leaks.

**Verified tests:** manual — `curl --socks5-hostname` works for
GitHub, Wikipedia, Cloudflare.

**Overall:** solid.

---

## src/common/http_proxy.c

**Purpose:** HTTP CONNECT handshake on the client.

**Reviewed functions:**
- `read_byte_timeout`, `write_full`, `read_line`.
- `http_connect_handshake` — parses `CONNECT host:port HTTP/1.1`,
  reads headers until empty line, replies `200 Connection established`.

**Findings:**

- Handles IPv4, IPv6 (bracketed `[::1]:443`), domain.
- Reads full request line up to 8191 bytes. If longer, returns -1.
- **RISK (low):** does not support HTTP/1.0 or HTTP/0.9. Only HTTP/1.1.
- **RISK (low):** does not handle `Proxy-Authorization` header. Ignored.
  Correct for local-only.
- Rejects non-CONNECT methods with `405`. Correct.
- **RISK (low):** `read_line` treats `\r\n` only, not bare `\n`.
  Strict but correct per HTTP spec.

**Verified tests:** manual — `curl --proxy http://127.0.0.1:8080`.

**Overall:** solid.

---

## src/common/relay.c

**Purpose:** bidirectional byte relay between TLS and raw fd.

**Reviewed functions:**
- `otpe_set_tcp_nodelay` — sets TCP_NODELAY.
- `otpe_relay_bidirectional` — raw ↔ raw.
- `otpe_relay_tls_bidirectional` — TLS ↔ raw.
- `otpe_connect_timeout` — non-blocking connect with timeout + IPv4/IPv6 ordering.

**Findings:**

- **RISK (medium):** `otpe_relay_tls_bidirectional` uses `poll` on the
  raw TLS fd, but OpenSSL may have already buffered decrypted bytes in
  its internal BIO. The code checks `otpe_tls_pending(tls)` before poll.
  **However:** if `SSL_pending()` returns 0 but OpenSSL has buffered
  a TLS record it hasn't fully decrypted, `poll` will wait. This is
  a known issue with OpenSSL + poll. In practice, `SSL_pending` is
  only accurate for TLS records already in OpenSSL's buffer; raw bytes
  in the socket are seen by poll. Tested with HTTP/2 (h2), which does
  complex framing — worked. **TODO: further test with streaming
  protocols (video, large downloads).**
- **RISK (low):** relay uses `send(MSG_NOSIGNAL)`, which suppresses
  SIGPIPE. Correct.
- No SSL_read / SSL_write partial-write handling in the TLS relay.
  `SSL_write` may return short. If it does, we return -1 and close.
  Should loop. Same issue as `otpe_tls_send`. **TODO.**
- `otpe_connect_timeout`: iterates all IPv4 first, then IPv6 with
  shorter timeout. Correct approach.
- **RISK (low):** `otpe_connect_timeout` uses `SOCK_NONBLOCK` — this
  flag is Linux-specific. On BSD/macOS, use `fcntl(O_NONBLOCK)` after
  socket creation. **TODO: portability.**
- No zeroing of buffers. Buffers are local, freed on return.

**Verified tests:** manual + fuzz not covering relay.

**Overall:** works for typical cases, but the SSL_write partial-write
issue is real. Under normal load it doesn't manifest.

---

## src/common/config.c

**Purpose:** parse `0tpe.conf`.

**Findings:**

- Simple `key = value` parser, `#` comments, trims whitespace.
- No escaped quotes, no multi-line values. OK.
- **RISK (low):** lines longer than 511 chars are truncated by `fgets`,
  and the remainder is treated as a new line. Malformed config could
  parse incorrectly. Not security-critical.
- `strncpy` with size-1 — no null terminator in worst case. Actually
  the destination is zero-initialized by `memset(out, 0, sizeof(*out))`
  in `config_default_*`, so it's fine.

**Verified tests:** manual.

**Overall:** simple, fine.

---

## src/server/main.c

**Purpose:** main loop, accept, fork thread, dispatch.

**Findings:**

- **RISK (low):** threads are detached (`pthread_detach`). No join.
  If a thread panics or exits non-locally, resources leak. Acceptable.
- **RISK (low):** no limit on concurrent threads. Under SYN flood or
  many connections, thread count grows. Should add a max-thread cap
  or use a thread pool.
- `handle_fallback` connects to `sni` or `fallback_sni` on port 443.
  If `sni` is empty (ClientHello without SNI), fallback to configured
  default. Correct.
- **RISK (low):** `handle_fallback` uses `otpe_relay_bidirectional`
  (raw → raw). It does NOT do TLS handshake — it just relays bytes.
  This is intentional (transparent proxy). Verified.
- Log messages contain `[tid %lu]` — no PII, no client IP. OK for
  privacy but hard to debug in production. **TODO: add optional
  client IP logging with a config flag.**
- **RISK (medium):** `handle_client` calls `tls_peek_clienthello` which
  can block for up to 3 seconds on a slow client. Under attack, this
  delays thread cleanup. Acceptable.

**Overall:** works, but lacks resource limits.

---

## src/client/main.c

**Purpose:** SOCKS5 + HTTP CONNECT listeners, tunnel establishment.

**Findings:**

- `establish_tunnel` calls `otpe_tls_client` — same static-buffer race
  as in `otpe_ext_add_cb`. **Same bug as tls.c.**
- **RISK (low):** no reconnect logic. If the server drops, client
  does not retry. Each new SOCKS5 connection opens a fresh tunnel.
- **RISK (low):** `make_listen` uses `INADDR_LOOPBACK` — only listens
  on localhost. Correct default. If user wants LAN access, would need
  config flag. Not implemented.
- `listener_thread` accepts indefinitely. Same thread-count caveat as
  server.
- **RISK (low):** no `SO_REUSEPORT`. If the client is restarted quickly,
  the old socket may be in TIME_WAIT. `SO_REUSEADDR` is set — OK.
- PING path: client sends PING header, expects PONG. Does not test
  extension handling in ping path. Not a bug, but PING is not
  authenticated beyond the TLS session. Acceptable.

**Verified tests:** manual, multi-curl.

**Overall:** works. Same static-buffer race.

---

## Summary of findings

### Critical

1. **Static buffer race in `otpe_ext_add_cb`** (`src/common/tls.c`).
   Fix required. See tls.c section.

### Medium

2. `SSL_write` partial-write not handled in relay and TLS send.
3. `nonce_cache` linear scan O(n) and 4096-entry limit under load.
4. `SSL_shutdown` blocks if peer is dead.
5. 8 KB limit on ClientHello buffer in `tls_peek_clienthello`.
6. No mutual authentication — MITM with valid CA defeats the tunnel.
7. No resource limits on thread count (server and client).

### Low

8. No `SSL_OP_NO_RENEGOTIATION` for TLS 1.2.
9. `SOCK_NONBLOCK` Linux-only in `otpe_connect_timeout`.
10. No client IP logging (privacy-friendly but hard to debug).
11. Time-based HMAC depends on clock accuracy.

### TODO

- Fix finding #1 before v0.2.
- Add benchmark suite to measure #3 and #4 in practice.
- Add concurrency test to `tests/` that runs 100 parallel curl calls.
- Consider hash table for nonce cache.

## Changelog

- v1 (2026) — initial audit.