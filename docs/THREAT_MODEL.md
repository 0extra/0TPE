# 0TPE Threat Model

Version: 1 (draft)
Date: 2026
Based on: source code as of `master` branch
Author: 0extra

## 1. Scope

This document describes what 0TPE protects against, what it does not,
what metadata is visible to an adversary, and which claims are verified
by code/tests versus assumed.

Scope covers:

- 0TPE protocol on the wire (frame format, handshake, fallback)
- Client and server implementations in this repository
- Deployment model: client on user's device, server on VPS

Out of scope:

- Security of the underlying TLS implementation (OpenSSL)
- Security of the OS, VPS provider, or network path
- Endpoint security (malware on client or server)
- Legal and jurisdictional concerns

## 2. Security goals

0TPE aims to provide:

- **G1** — Bypass DPI-based censorship of TCP connections
- **G2** — Camouflage tunneled traffic as legitimate TLS to a real site
- **G3** — Resist active probing by a censor
- **G4** — Authenticate the client to the server without exposing credentials on the wire
- **G5** — Maintain confidentiality and integrity of tunneled data
- **G6** — Reject replayed handshakes

0TPE does NOT aim to provide:

- **N1** — Anonymity from the server operator
- **N2** — Indistinguishability from a real browser under deep fingerprinting
- **N3** — Resistance to a global passive adversary with traffic correlation
- **N4** — Protection against a MITM who can present a valid TLS certificate

## 3. Attacker model

We consider the following adversaries, ordered by capability:

### 3.1 Passive network observer (weak)

Can read all bytes on the wire between client and server. Cannot modify
or drop traffic (or chooses not to).

**Capability:** reads SNI, TLS version, extensions, cipher suites, packet
sizes, timing, connection duration.

### 3.2 Active prober (medium)

Can initiate TCP connections to the server, send arbitrary bytes, and
observe responses. Cannot intercept or modify client-server traffic.

**Capability:** probe server behavior on any port, replay captured
handshakes, send malformed TLS.

### 3.3 On-path DPI (strong)

Can read, modify, drop, and inject traffic between client and server.
May reset connections that match signatures.

**Capability:** all of 3.1 and 3.2, plus active manipulation.

### 3.4 MITM with trusted CA (very strong)

Can present a valid TLS certificate for the decoy SNI (`www.microsoft.com`).

**Capability:** all of 3.3, plus can complete a valid TLS handshake with
the client using a certificate the client trusts.

### 3.5 Global passive adversary (out of scope)

Can observe traffic at multiple points in the network and correlate flows.

**0TPE provides no protection against this adversary.** It is explicitly
out of scope.

## 4. What 0TPE defends against

### 4.1 Passive DPI with SNI-based blocking (against 3.1)

**Defense:** the ClientHello sent by the 0TPE client carries `SNI = www.microsoft.com`
(configurable via `sni` in `0tpe.conf`, function `otpe_tls_client` in `src/common/tls.c`).

A censor that blocks based on SNI sees a connection to Microsoft.

**Status:** verified by tcpdump in `docs/DIAGNOSTICS.md` (screenshot in README).

**Caveat:** a censor that blocks the server's IP address directly (regardless
of SNI) is not defeated by this mechanism.

### 4.2 Certificate-based detection (against 3.1, 3.2)

**Defense:** when a client without a valid 0TPE extension connects,
the server performs a transparent byte-level proxy to the real decoy
site (`handle_fallback` in `src/server/main.c`). The client receives
the decoy's real certificate chain.

**Status:** verified — `openssl s_client` against the server returns
the real Microsoft certificate with issuer `CN = Microsoft TLS G2 RSA CA OCSP 04`.

**Caveat:** this only proves fallback works. It does NOT prove the 0TPE
client is indistinguishable from a browser to a fingerprinting DPI
(see 5.1).

### 4.3 Active probing (against 3.2)

**Defense:** a prober that does not know the server's X25519 private key
cannot produce a valid HMAC in the custom extension. The server routes
such connections to fallback (`handle_client` → `crypto_verify_extension`
returns -1 → `handle_fallback`).

**Status:** verified by unit test `tests/test_crypto.c`:
- wrong key → -1
- tampered HMAC → -1
- truncated input → -1
- garbage input → -1

**Caveat:** a prober who *knows* the extension scheme (public documentation)
and captures a valid ClientHello can replay it. See 4.5.

### 4.4 Client authentication (against 3.1, 3.2)

**Defense:** the client proves knowledge of the server's static X25519
public key without revealing any long-term secret. The ephemeral keypair
is generated fresh per connection (`crypto_build_extension` in `src/common/crypto.c`).

**Status:** verified by unit test — round-trip build/verify succeeds.

**Caveat:** there is NO mutual authentication. The server does not prove
its identity to the client. See 5.5.

### 4.5 Replay attacks (against 3.2)

**Defense:** two layers.

1. **Timestamp window:** the HMAC covers a timestamp; the server accepts
   timestamps in `[now - 30, now + 30]` seconds (`crypto_verify_extension`).
2. **Nonce cache:** every accepted nonce is stored in a 4096-entry LRU-like
   cache for 60 seconds (`nonce_cache_check_and_add` in `src/common/nonce_cache.c`).
   The same nonce is rejected on second use.

**Status:** verified by unit test — same extension is accepted once, rejected
on the second verification.

**Caveat:**
- The nonce cache is **in-memory only**. Server restart clears it.
  A captured ClientHello replayed within ±30 seconds after a restart
  would be accepted once.
- Cache size 4096 means under very high load (>4096 unique handshakes per
  60 seconds), older nonces are evicted. At that rate, replay is theoretically
  possible.
- `nonce_cache_check_and_add` is O(n) linear scan, 4096 comparisons per
  connection. Not a security issue, but a performance note.

### 4.6 Data confidentiality and integrity (against 3.1)

**Defense:** all 0TPE frames are transmitted inside a TLS 1.2/1.3 session.
Eavesdropper sees only encrypted application data.

**Status:** verified — TLS 1.3 with `TLS_AES_256_GCM_SHA384` negotiated
in `otpe_tls_client` (via `SSL_CTX_set_ciphersuites`).

**Caveat:** the *contents* of the extension `0xFFA0` are the encrypted
ephemeral public key + HMAC. The extension *type* is visible in plaintext
in the ClientHello (see 5.1).

## 5. What 0TPE does NOT defend against

### 5.1 Fingerprinting DPI (against 3.3)

**Problem:** OpenSSL's ClientHello differs from Chrome's in:
- order of cipher suites
- set of extensions
- absence of GREASE values
- absence of ALPS, ECH, padding
- signature algorithms list

A DPI with a Chrome ClientHello fingerprint database can distinguish
0TPE from a real Chrome user.

**Mitigation in code:** `otpe_tls_client` sets Chrome-like ciphers,
groups, and sigalgs. This covers roughly 70% of the fingerprint.

**Remaining 30%:** requires BoringSSL or a hand-crafted ClientHello.

**Status:** partially mitigated, not solved.

### 5.2 Custom extension visibility (against 3.1, 3.3)

**Problem:** the extension type `0xFFA0` is visible in plaintext in the
ClientHello. A DPI that specifically blocks or flags connections containing
this extension will detect 0TPE.

**Mitigation:** none currently. The contents are encrypted but the type is not.
This is analogous to Xray Reality's `xtls-rprx-vision` extension, which has
the same issue.

**Mitigation idea (future):** hide the marker inside the standard fields
of a TLS 1.2 ClientHello's Session ID (as Xray does), or use a randomized
extension type derived from the shared secret.

**Status:** known weakness.

### 5.3 Traffic correlation (against 3.5, partially 3.3)

**Problem:** an adversary observing both the client's outbound connection
(SNI = www.microsoft.com) and the server's outbound connection to the real
target (e.g., youtube.com) can correlate by timing.

**Mitigation:** none.

**Status:** out of scope.

### 5.4 DNS leaks (against all)

**Problem:** if the client's DNS resolver sends queries in plaintext (DNS over UDP)
and the resolver is controlled by the censor, the censor knows which domains
the user resolves, even if the traffic is tunneled.

**Mitigation:**
- Client SOCKS5 listener accepts hostnames (via `--socks5-hostname` in curl
  or "Proxy DNS" in Firefox). This makes the *server* resolve DNS, not the client.
- If the client resolves DNS itself (e.g., `--socks5` without hostname),
  the DNS query may leak.

**Status:** documented in README, not enforced by code.

### 5.5 No server authentication (against 3.4)

**Problem:** the client does NOT verify the server's TLS certificate.
`otpe_tls_client` sets `SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL)`.

Why: the server uses a self-signed certificate to complete the TLS
handshake after the Reality-lite extension is accepted. The client cannot
verify it against a public CA.

**Consequence:** a MITM with a valid certificate for the decoy SNI
(e.g., a corporate firewall with a trusted CA) can impersonate the server
to the client. The client sends its HMAC, the MITM cannot decrypt it
(it's inside TLS, but the MITM terminates TLS), and MITM would see the
0TPE protocol in the clear.

**Why this is mitigated in practice:** the MITM must terminate the TLS
session that carries the 0TPE extension. Because the extension is inside
the ClientHello, the MITM sees it before deciding to intercept. If the
MITM is stateless (typical for a censor), it does not know how to
respond and the client's connection fails — a "fail-closed" behavior.

**Real limitation:** against a MITM that *can* terminate TLS (corporate
proxy with CA), 0TPE provides no protection. This is inherent to the
threat model.

**Mitigation idea (future):** server authentication via a second X25519
HMAC in the ServerHello, keyed by the same shared secret.

**Status:** known weakness, documented.

### 5.6 Timing and packet size analysis

**Problem:** packet sizes and inter-packet timing can reveal whether the
connection is used for web browsing, video streaming, or bulk download.

**Mitigation:** none.

**Status:** out of scope.

### 5.7 Port scanning

**Problem:** an adversary scanning for open ports will find port 8443.
Comparing to a real microsoft.com connection on 443, the port differs.
An adversary that only allows traffic to port 443 will block 0TPE.

**Mitigation:** run the server on port 443 (requires root, or `setcap
cap_net_bind_service`).

**Status:** deployment detail, not a protocol issue.

## 6. Metadata visible to a passive observer

Assuming TLS 1.3:

| Item | Visible? | Value |
|---|---|---|
| Server IP | yes | your VPS |
| Server port | yes | 8443 by default |
| SNI | yes | `www.microsoft.com` |
| TLS version | yes | 1.2 or 1.3 |
| Cipher suites offered | yes | Chrome-like (partial) |
| Extensions present | yes | includes `0xFFA0` |
| Extension contents | no | encrypted payload |
| Client certificate | no | none used |
| Destination hostname (real) | no | inside TLS |
| Data payload | no | inside TLS |
| Session duration | yes | |
| Packet sizes and timing | yes | |

## 7. Assumptions

0TPE's security depends on:

1. **The server's X25519 private key is not compromised.** If leaked,
   anyone can generate valid extensions and impersonate a client. No
   detection is possible.

2. **The client's clock is roughly correct.** A drift > 30 seconds
   causes all handshakes to fail. No NTP is enforced by code.

3. **The server's clock is roughly correct.** Same as above.

4. **The decoy site (www.microsoft.com) remains accessible.** If
   blocked by the censor, fallback fails and any probing reveals
   a non-Microsoft response.

5. **The underlying TLS implementation is correct.** OpenSSL 3.x is
   assumed to be free of critical vulnerabilities.

6. **The token in `0tpe.conf` is not treated as a secret.** It is
   transmitted in plaintext inside TLS.

## 8. Verified vs assumed

| Claim | Status | Evidence |
|---|---|---|
| Replay within ±30s rejected | verified | `tests/test_crypto.c` |
| Wrong key rejected | verified | `tests/test_crypto.c` |
| Tampered HMAC rejected | verified | `tests/test_crypto.c` |
| Fallback returns real MS cert | verified | `docs/DIAGNOSTICS.md` |
| Chrome-like cipher suites | verified | `otpe_tls_client` (source) |
| Chrome-like full fingerprint | **not verified** | requires uTLS/BoringSSL |
| Extension marker not detectable | **assumed false** | extension type is plaintext |
| No server authentication | verified | `SSL_VERIFY_NONE` in source |
| Nonce cache across restarts | **not verified** | in-memory only |

## 9. Recommendations for users

- Use `--socks5-hostname` or "Proxy DNS when using SOCKS v5" to avoid DNS leaks.
- Do not reuse the same X25519 keypair across multiple servers.
- Rotate CA and client certificates periodically (`scripts/gen_ca.sh`).
- Run the server behind a CDN if you expect targeted attacks (out of scope here).
- Treat 0TPE as a **practical** tool for bypassing DPI, not as a **high-security** anonymity system.

## 10. Changelog

- v1 (2026) — initial threat model, based on `master` branch.