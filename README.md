# 0TPE — Zero Transfer Protocol Extra

A custom proxy protocol on top of TLS with camouflage to a real website (Reality-compatible).

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![build](https://img.shields.io/badge/build-passing-brightgreen)

## What it is

0TPE is a protocol for bypassing DPI and censorship. From the outside, traffic looks like a normal HTTPS session to a well-known site (default: `www.microsoft.com`). Active probing — when a censor connects to your server as a regular client — receives the **real response from Microsoft**. Impersonation is impossible.

## Features

- Custom transport protocol with a minimal 16-byte header
- TLS wrapper on top of OpenSSL
- X25519-encrypted handshake — only a matching client is recognized by the server
- Fallback: foreign connections are transparently proxied to a real decoy site
- Anti-replay: HMAC with timestamp ±30s + in-memory nonce cache (4096 entries, 60s window)
- SOCKS5 (TCP + UDP ASSOCIATE) and HTTP CONNECT on the client
- Multi-client server and client (pthreads)
- Config file — change ports/SNI/token without recompiling
- IPv4 + IPv6 with automatic fallback
- Link generator (`otpe://...`)
- Fuzz-tested TLS ClientHello parser (63M executions, 0 crashes)
- GitHub Actions CI

## Benchmarks (local loopback)

Tested on a laptop with a modern x86_64 CPU, OpenSSL 3.x, TCP_NODELAY enabled.

### RTT (round-trip time)

```
=== 0TPE RTT benchmark ===
iterations: 1000 (ok=1000)
min:  0.025 ms
p50:  0.025 ms
p95:  0.039 ms
p99:  0.062 ms
max:  0.453 ms
avg:  0.029 ms
```

29 microseconds average RTT over TLS + 0TPE + relay on loopback.

### Throughput

```
=== 0TPE throughput benchmark ===
raw bytes:   104858154
payload:     104857600
elapsed:     7.200 s
throughput:  13.89 MB/s (111.11 Mbps)
```

111 Mbps single-stream throughput over TLS + 0TPE + relay on loopback. On a real VPS with a gigabit uplink, 100–500 Mbps end-to-end is realistic.

## Dependencies

- GCC
- OpenSSL 3.x (dev headers)
- pthreads (built into glibc)

### Ubuntu / Debian / Mint

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install gcc make openssl-devel
```

### Arch / Manjaro

```bash
sudo pacman -S base-devel openssl
```

### Alpine

```bash
sudo apk add build-base openssl-dev
```

## Build

```bash
# 1. Generate TLS certificate
chmod +x scripts/gen_cert.sh
./scripts/gen_cert.sh

# 2. Generate X25519 keys for Reality-lite
chmod +x scripts/gen_keys.sh
./scripts/gen_keys.sh

# 3. Build everything
make clean && make && make bench
```

Binaries produced:

- `otpe-server` — the server
- `otpe-client` — the client (SOCKS5 + HTTP CONNECT + UDP)
- `otpe-ping` — ping over 0TPE
- `otpe-genlink` — generate `otpe://` links
- `otpe-test` — protocol unit tests
- `otpe-test-crypto` — X25519 + HMAC + replay tests
- `otpe-test-udp` — end-to-end UDP over 0TPE test
- `bench-rtt` — RTT benchmark
- `bench-throughput` — throughput benchmark

## VPS installation

```bash
# On VPS (Ubuntu 22.04+)
sudo apt update && sudo apt install build-essential libssl-dev git
git clone <your-repo> 0TPE
cd 0TPE
./scripts/gen_cert.sh
./scripts/gen_keys.sh
make

# Run as a systemd service
sudo tee /etc/systemd/system/0tpe-server.service > /dev/null <<EOF
[Unit]
Description=0TPE Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/0TPE
ExecStart=/root/0TPE/otpe-server /root/0TPE/0tpe.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now 0tpe-server
```

**Don't forget** to copy `keys/server.pub` to the client machine — it is needed for the Reality-lite handshake.

## Opening the port on the VPS

If you use ufw:

```bash
sudo ufw allow 8443/tcp
```

Or via iptables:

```bash
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

## Client configuration

Copy `keys/server.pub` into the `keys/` folder on the client, edit `0tpe.conf`:

```ini
server_ip           = YOUR_VPS_IP
server_port         = 8443
socks_port          = 1080
http_port           = 8080
sni                 = www.microsoft.com
token               = 550e8400e29b41d4a716446655440000
reality_pubkey_file = keys/server.pub
```

Run:

```bash
./otpe-client
```

You will see:

```
0TPE client -> <IP>:8443 (SNI=www.microsoft.com)
  SOCKS5 on 127.0.0.1:1080
  HTTP   on 127.0.0.1:8080
  Reality pubkey: keys/server.pub
  UDP    on 127.0.0.1:<port>
```

## Usage

### curl through SOCKS5 (TCP)

```bash
curl -s --socks5-hostname 127.0.0.1:1080 https://example.com -o /tmp/page.html
```

**Important:** use `--socks5-hostname`, not `--socks5`. The former passes the hostname to the server, which then resolves IPv4/IPv6 itself.

### curl through HTTP CONNECT

```bash
curl -s --proxy http://127.0.0.1:8080 https://example.com -o /tmp/page.html
```

### DNS over UDP through the tunnel

```bash
./otpe-test-udp
```

### Firefox

Settings → Network Settings → Manual proxy configuration:

- SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5, **check "Proxy DNS when using SOCKS v5"** — mandatory
- or HTTP Proxy: `127.0.0.1:8080`, "Also use for HTTPS" ✅

### Telegram Desktop

Settings → Advanced → Connection type → Use custom proxy:

- Type: SOCKS5
- Hostname: `127.0.0.1`, Port: `1080`

### git

```bash
git -c http.proxy=socks5h://127.0.0.1:1080 clone https://github.com/user/repo.git
```

## Link format

```bash
./otpe-genlink 0tpe.conf MyServer
# otpe://550e8400e29b41d4@127.0.0.1:8443?sni=www.microsoft.com#MyServer
```

## Testing

```bash
make clean && make

./otpe-test         # protocol frame encode/decode
./otpe-test-crypto  # X25519, HMAC, replay rejection
./otpe-test-udp     # UDP over 0TPE (needs server + client running)
```

Fuzzing:

```bash
make fuzz
./fuzz/fuzz_clienthello fuzz/corpus -max_total_time=300
```

Benchmarks:

```bash
make bench
./bench-rtt 0tpe.conf 1000
./bench-throughput 0tpe.conf 100
```

## Architecture

```
[Browser] --SOCKS5/HTTP--> [otpe-client] --0TPE+TLS+Reality--> [otpe-server] --TCP/UDP--> [target]
                              (your PC)         (wire)              (VPS)
```

- **otpe-client** listens on `127.0.0.1:1080` (SOCKS5), `127.0.0.1:8080` (HTTP CONNECT), and a dynamic UDP port
- Sends `CONNECT host:port` or `UDP host:port` commands via the 0TPE header
- **otpe-server** connects to the target and relays bytes in both directions

## How Reality-lite works

1. The client sends a TLS ClientHello with SNI=`www.microsoft.com` and a custom extension `0xFFA0`
2. The extension contains: ephemeral X25519 public key + nonce + HMAC-SHA256 (with timestamp)
3. The server reads the ClientHello **before** the TLS handshake via `MSG_PEEK` and verifies the HMAC
4. If HMAC matches → the server acts as a 0TPE server
5. If not → the server **transparently proxies** the connection to the real `www.microsoft.com:443`
6. The censor sees a real TLS session, real certificate, real response — impersonation is impossible

## Security

- X25519 server keys **must not be published**. `keys/server.key` — server-side only
- `keys/server.pub` — safe to distribute to clients
- Token in `0tpe.conf` — not critical, but better not to publish
- Certificate (`certs/server.crt`) — self-signed, the client does not verify it, because camouflage is provided by the Reality-lite extension

## Limitations

- Against a **targeted** DPI with Chrome fingerprinting (e.g., Russian RKN with active analysis) it may not work — OpenSSL cannot fully reproduce Chrome's ClientHello. Requires BoringSSL or uTLS.
- No multiplexing — each connection is a new TLS session to the server.
- UDP relay does not support multicast or broadcast.

## Diagnostics

### Verify the server responds as Microsoft

```bash
echo | openssl s_client -connect <VPS_IP>:8443 -servername www.microsoft.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer
```

Expected:

```
subject=C=US, ST=WA, L=Redmond, O=Microsoft Corporation, CN=www.microsoft.com
issuer=C=US, O=Microsoft Corporation, CN=Microsoft TLS G2 RSA CA OCSP 04
```

### Ping check

```bash
./otpe-ping <VPS_IP> 8443 10
```

### Server logs

- `[tid ...] OTPE client, SNI=...` — our client recognized
- `[UDP tid ...] -> 8.8.8.8:53 (29 bytes)` — UDP relay working
- `[fallback] -> www.microsoft.com:443` — foreign connection redirected to fallback

## Project structure

```
.github/workflows/   — CI
bench/               — RTT and throughput benchmarks
certs/               — TLS certificate (generated)
docs/                — SPEC.md, THREAT_MODEL.md, CODE_AUDIT.md
fuzz/                — libFuzzer target + corpus
include/             — header files
keys/                — X25519 keys (generated)
scripts/             — gen_cert.sh, gen_keys.sh
src/
  common/            — shared code
  client/            — client entry point
  server/            — server entry point
  ping/              — otpe-ping
  tools/             — genlink
tests/               — unit tests
0tpe.conf            — default config
Makefile
README.md
LICENSE
COPYING
```

## License

GNU General Public License v3.0 — see the [LICENSE](LICENSE) file.