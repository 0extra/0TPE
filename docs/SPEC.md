# 0TPE Protocol Specification

Version: 1 (draft)
Status: Experimental
Author: 0extra
Date: 2026

## 1. Overview

0TPE (Zero Transfer Protocol Extra) is a lightweight transport protocol designed to
be tunneled over TLS with a Reality-style camouflage mechanism. It is not a
replacement for TLS — it is a *payload protocol* that runs inside an established
TLS session.

The protocol is optimized for:

- Minimal per-packet overhead (16-byte fixed header)
- Fast handshake with piggybacking of the first payload
- Compatibility with active probing defense (fallback to a decoy site)
- TCP and UDP relaying over a single TLS session

## 2. Conventions

- All multi-byte integer fields are transmitted in **big-endian** (network byte order).
- `uint8` — unsigned 8-bit integer.
- `uint16` — unsigned 16-bit integer.
- `uint32` — unsigned 32-bit integer.
- The key words MUST, SHOULD, MAY are used as defined in RFC 2119.

## 3. Transport

0TPE runs on top of a reliable, ordered, byte-stream transport. In practice this
is TCP, wrapped inside TLS 1.2 or TLS 1.3.

Port assignments:

- Server default port: **8443/TCP** (any TCP port MAY be used)
- Client SOCKS5 listener: **1080/TCP** (local)
- Client HTTP CONNECT listener: **8080/TCP** (local)
- Client UDP relay listener: **dynamic UDP port**, announced via SOCKS5 UDP ASSOCIATE

## 4. Frame format

Every 0TPE frame consists of a fixed 16-byte header followed by an optional
payload. The payload length is given by the `length` field of the header.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    version    |    command    |     flags     |   reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          length           |          checksum         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          token (8 bytes)                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.1 Field descriptions

| Field      | Size    | Description                                                   |
|------------|---------|---------------------------------------------------------------|
| `version`  | 1 byte  | Protocol version. Current version is `0x01`.                  |
| `command`  | 1 byte  | Command identifier (see Section 5).                           |
| `flags`    | 1 byte  | Bit flags. Reserved for future use, MUST be `0x00`.           |
| `reserved` | 1 byte  | Reserved. MUST be `0x00`.                                     |
| `length`   | 2 bytes | Length of the payload in bytes. Maximum value: 65535.         |
| `checksum` | 2 bytes | XOR-based rolling checksum over the entire 16-byte header.    |
| `token`    | 8 bytes | Session token (opaque). See Section 6.                        |

### 4.2 Checksum algorithm

The checksum covers the 16-byte header, including the checksum field itself,
which is treated as zero during computation.

```
uint16_t checksum(const uint8_t* buffer, size_t size) {
    uint16_t sum = 0xFFFF;
    for (size_t i = 0; i < size; i++) {
        sum ^= buffer[i];
        sum = (sum << 1) | (sum >> 15);
    }
    return sum;
}
```

The checksum field MUST be set to zero before computing, and MUST be written
into bytes 6–7 of the header before transmission.

## 5. Commands

| Value  | Name              | Direction        | Description                            |
|--------|-------------------|------------------|----------------------------------------|
| `0x01` | `OTPE_CMD_TCP`    | Client → Server  | Reserved. Plain TCP stream marker.     |
| `0x02` | `OTPE_CMD_UDP`    | Bidirectional    | UDP datagram over the tunnel.          |
| `0x03` | `OTPE_CMD_STREAM` | Client → Server  | Reserved. Stream setup without target. |
| `0x10` | `OTPE_CMD_PING`   | Client → Server  | Liveness probe.                        |
| `0x11` | `OTPE_CMD_PONG`   | Server → Client  | Response to PING.                      |
| `0x20` | `OTPE_CMD_CONNECT`| Client → Server  | Request to establish a TCP tunnel.     |

## 6. Token

The 8-byte `token` field is an opaque session identifier. It is not used for
cryptographic authentication — authentication is provided by the Reality-lite
extension (Section 7).

## 7. Reality-lite handshake

Before any 0TPE frame is transmitted, the client performs a TLS handshake with a
custom extension whose type is `0xFFA0`. The server inspects the ClientHello
*before* the TLS handshake completes, via `MSG_PEEK`, to decide whether the
connection belongs to a 0TPE client or a foreign party.

### 7.1 Client extension payload

The extension payload is exactly 60 bytes:

```
+---------------------------+
| ephemeral X25519 pubkey   |  32 bytes
+---------------------------+
| nonce                     |  12 bytes
+---------------------------+
| HMAC-SHA256 tag           |  16 bytes (truncated)
+---------------------------+
```

### 7.2 Shared secret derivation

1. The server publishes a static X25519 public key (`keys/server.pub`).
2. The client generates an ephemeral X25519 keypair.
3. The shared secret is computed as `X25519(client_eph_priv, server_pub)`.
4. The HMAC key is the 32-byte shared secret.

### 7.3 HMAC message

The HMAC is computed over:

```
nonce (12 bytes) || timestamp (8 bytes, big-endian, UNIX time)
```

The HMAC-SHA256 output is truncated to the first 16 bytes.

### 7.4 Server verification

The server:

1. Reads the extension payload.
2. Computes the shared secret with its static private key.
3. Tries to verify the HMAC against timestamps in the range
   `[now - 30, now + 30]` seconds.
4. If any candidate HMAC matches — the connection is treated as a 0TPE client.
5. Otherwise — fallback (Section 8).

### 7.5 Anti-replay

The ±30-second timestamp window limits replay attacks. Additionally, the
server stores every accepted nonce in a 4096-entry in-memory cache for 60
seconds and rejects a second use of the same nonce. See `src/common/nonce_cache.c`.

## 8. Fallback behavior

If the ClientHello does not contain a valid 0TPE extension, the server MUST
transparently proxy the connection to a real decoy site (default:
`www.microsoft.com:443`). This proxy:

- Does NOT decrypt the TLS session.
- Forwards bytes verbatim in both directions.
- Is used both for active probing defense and to serve legitimate traffic
  (e.g., if a browser accidentally connects to the server's port).

The decoy site's certificate chain, ALPN, and application response MUST match
what a real connection to the decoy would produce.

## 9. CONNECT command (TCP)

1. **Client → Server**: `OTPE_CMD_CONNECT` frame with payload:

   ```
   +-------------------------------+
   | port (2 bytes, big-endian)    |
   +-------------------------------+
   | host (variable, UTF-8 string) |
   +-------------------------------+
   ```

   - `host` MAY be a domain name, IPv4 literal, or IPv6 literal.
   - The `length` field in the header equals `2 + strlen(host)`.
   - The `host` field is NOT null-terminated.

2. **Server**: resolves `host`, opens a TCP connection to `host:port`,
   and starts relaying bytes between the TLS session and the new socket.

3. The server does NOT send an explicit acknowledgment frame. Any subsequent
   bytes from either side are relayed as-is.

4. The tunnel is terminated when either side closes the connection, or on
   transport error.

## 10. UDP command

The `OTPE_CMD_UDP` frame carries one UDP datagram in each direction. Unlike
CONNECT, UDP does not establish a persistent tunnel — each frame is
independent.

### 10.1 Client → Server payload

```
+-------------------------------------+
| host length (1 byte)                |
+-------------------------------------+
| host (variable, UTF-8 string)       |
+-------------------------------------+
| port (2 bytes, big-endian)          |
+-------------------------------------+
| data length (2 bytes, big-endian)   |
+-------------------------------------+
| data (variable)                     |
+-------------------------------------+
```

- `host length` MUST be in the range 1–255.
- The `length` field in the header equals
  `1 + host_len + 2 + 2 + data_len`.

### 10.2 Server → Client payload

Identical format. The `host` and `port` fields reflect the origin of the
response (the remote UDP peer), not the target that the client requested.

### 10.3 Server behavior

For each incoming `OTPE_CMD_UDP` frame, the server:

1. Creates a temporary UDP socket.
2. Sends the payload to `host:port`.
3. Waits up to 5 seconds for a reply.
4. Encodes the reply into a `OTPE_CMD_UDP` frame and sends it back.
5. Closes the socket.

This is a **stateless per-datagram relay**. It does not maintain NAT-like
state for long-lived UDP flows (e.g., QUIC connections or long VoIP calls).

### 10.4 Client behavior

The client exposes a SOCKS5 UDP ASSOCIATE endpoint:

1. Application sends `UDP ASSOCIATE` to `127.0.0.1:1080` (SOCKS5).
2. Client responds with its dynamic UDP port.
3. Application sends UDP datagrams to that port, wrapped in SOCKS5 UDP
   request format.
4. Client unwraps, converts to `OTPE_CMD_UDP`, and sends via TLS.
5. Server sends a reply; client re-wraps it in SOCKS5 UDP format and sends
   back to the application.

## 11. PING/PONG

To check liveness:

1. Client sends `OTPE_CMD_PING` with empty payload (`length = 0`).
2. Server replies with `OTPE_CMD_PONG`, empty payload, same token.
3. Client measures round-trip time.

Servers MAY rate-limit PING frames to prevent abuse.

## 12. Error handling

0TPE has no explicit error frame. On failure, the underlying TLS connection is
closed. The client distinguishes failures by observing:

- TLS connection closure (either side closed)
- TCP RST (rare)
- Timeouts

## 13. Version negotiation

Currently, only version `0x01` is defined. A server that receives a frame with
an unknown version MUST close the connection.

## 14. Security considerations

- **No transport encryption at 0TPE layer.** All encryption is provided by the
  underlying TLS session.
- **Reality-lite is not mutual authentication.** It authenticates the client to
  the server, not vice versa.
- **Active probing defense is best-effort.** A targeted attacker who knows the
  exact extension type `0xFFA0` and HMAC scheme could theoretically detect a
  0TPE server by capturing ClientHellos. Timestamp + nonce cache mitigates
  replay but not detection.
- **Fingerprint divergence.** The TLS ClientHello produced by OpenSSL differs
  from a real browser's ClientHello. A sophisticated DPI with fingerprinting
  may detect 0TPE traffic.
- **UDP is stateful only within a single datagram round-trip.** Long-lived UDP
  flows (QUIC, VoIP) will not work efficiently because each datagram is a
  separate socket on the server.

## 15. Future work

- Multiplexing (`OTPE_CMD_MUX`, `0x03`) — multiple logical streams over one
  TLS session.
- Stateful UDP flow tracking on the server (a per-flow hash table).
- Native IPv6 address encoding in payloads (currently as text literals).
- Compression of repeated hostnames.
- Full Chrome/Firefox ClientHello emulation.

## 16. Reference implementation

The reference implementation is written in C and lives in this repository:

- `src/common/protocol.c` — frame encoding/decoding
- `src/common/crypto.c` — X25519 + HMAC
- `src/common/tls_peek.c` — ClientHello parser
- `src/common/nonce_cache.c` — replay protection
- `src/common/socks5.c` — SOCKS5 handshake (TCP + UDP)
- `src/common/uri.c` — `otpe://` link parsing/generation
- `src/server/main.c` — server
- `src/client/main.c` — client

## 17. Changelog

- **v1 (2026, draft)** — initial specification.