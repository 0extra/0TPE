# 0TPE

A lightweight transport protocol over TLS with camouflage to a real website.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![build](https://github.com/0extra/0TPE/actions/workflows/build.yml/badge.svg)](https://github.com/0extra/0TPE/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/0extra/0TPE)](https://github.com/0extra/0TPE/releases)

## What it is

0TPE is a lightweight transport protocol for building secure proxy tunnels. It runs on top of **BoringSSL** — the same TLS stack used by Chrome — and authenticates clients with standard **TLS client certificates**. From the outside, traffic looks like a normal HTTPS session to a well-known site (default: `www.microsoft.com`). An outside observer probing the server receives the **real response from Microsoft**, so the protocol cannot be distinguished from a legitimate mirror.

## Use cases

- **Privacy on untrusted networks** — public Wi-Fi, hotels, airports
- **Remote access** — reach your home or office network from anywhere
- **Geo-restrictions** — access streaming services as if you were in another country
- **Development and testing** — view your services from different regions
- **Secure tunneling between your own devices**

## Features

- Custom transport protocol with a minimal **16-byte header**
- **BoringSSL** — same TLS library Chrome uses
- **Mutual authentication** via TLS client certificates signed by an internal CA
- Client recognition via **ALPN** (`h2,http/1.1,0tpe`)
- Transparent fallback: unrecognized connections proxied to a real decoy site
- SOCKS5 (TCP + UDP ASSOCIATE) and HTTP CONNECT on the client
- Multi-client server and client (pthreads)
- DNS cache (30-second TTL, 256 hosts)
- 10-second idle timeout in relay
- Config file — change ports/SNI without recompiling
- Config validation at startup — readable certs, port conflicts, token format
- IPv4 + IPv6 with automatic fallback
- Link generator (`otpe://...`)
- Fuzz-tested ClientHello parser
- UDP echo stress test — 250 queries, 0% loss on loopback
- GitHub Actions CI
- Docker multi-stage build

## Benchmarks (loopback)

### RTT (round-trip time, 1000 iterations)

```
=== 0TPE RTT benchmark ===
iterations: 1000 (ok=1000)
min:  0.024 ms
p50:  0.024 ms
p95:  0.039 ms
p99:  0.057 ms
max:  0.295 ms
avg:  0.028 ms
```

28 microseconds average RTT over BoringSSL + 0TPE + relay on loopback.

### Parallel connections

20 concurrent curl requests through the SOCKS5 proxy:

```
20 parallel: OK=20 FAIL=0
2.748 total
```

20/20 in 2.7 seconds. Down from 11 seconds in v0.1.3.

## Dependencies

- GCC
- BoringSSL (built from source)
- CMake, Ninja, Go (for building BoringSSL)
- pthreads

### Ubuntu / Debian / Mint

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build golang
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install gcc make cmake ninja-build golang
```

### Arch / Manjaro

```bash
sudo pacman -S base-devel cmake ninja go
```

### Alpine

```bash
sudo apk add build-base cmake ninja go
```

## Build

```bash
# 1. Build BoringSSL (only once, ~15 minutes)
chmod +x scripts/build_boringssl.sh
./scripts/build_boringssl.sh

# 2. Generate internal CA, server certificate, and client certificate
chmod +x scripts/gen_ca.sh
./scripts/gen_ca.sh

# 3. Build 0TPE
make clean && make && make bench

# 4. Run the full test suite (builds, starts server+client, tears down)
make test
```

Binaries produced:

- `otpe-server` — the server
- `otpe-client` — the client (SOCKS5 + HTTP CONNECT + UDP)
- `otpe-ping` — ping over 0TPE
- `otpe-genlink` — generate `otpe://` links
- `otpe-test` — protocol unit tests
- `otpe-test-crypto` — X25519 DH tests
- `otpe-test-udp` — end-to-end UDP over 0TPE test
- `otpe-test-udp-stress` — 25×10 UDP echo stress test
- `bench-rtt` — RTT benchmark
- `bench-throughput` — throughput benchmark

## VPS installation

```bash
sudo apt update && sudo apt install build-essential cmake ninja-build golang git
git clone https://github.com/0extra/0TPE.git
cd 0TPE
./scripts/build_boringssl.sh
./scripts/gen_ca.sh
make

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

Or with Docker:

```bash
docker compose up -d
docker compose logs -f
```

**Copy these files to each client machine:**

- `certs/client.crt` — client certificate
- `certs/client.key` — client private key

Keep `certs/ca.key` on the server only.

## Opening the port on the VPS

```bash
sudo ufw allow 8443/tcp
```

Or via iptables:

```bash
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

## Client setup

Copy `certs/client.crt` and `certs/client.key` into the `certs/` folder on the client. Edit `0tpe.conf`:

```ini
server_ip        = YOUR_VPS_IP
server_port      = 8443
socks_port       = 1080
http_port        = 8080
sni              = www.microsoft.com
token            = 550e8400e29b41d4a716446655440000
client_cert_file = certs/client.crt
client_key_file  = certs/client.key
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
  Client cert: certs/client.crt
  TLS retries: 3
  UDP    on 127.0.0.1:<port>
```

## Usage

### curl through SOCKS5 (TCP)

```bash
curl -s --socks5-hostname 127.0.0.1:1080 https://example.com -o /tmp/page.html
```

Use `--socks5-hostname`, not `--socks5`. The former passes the hostname to the server, which resolves IPv4/IPv6 itself.

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

- SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5
- Check "Proxy DNS when using SOCKS v5"
- or HTTP Proxy: `127.0.0.1:8080`, "Also use for HTTPS"

### Chromium

```bash
chromium --proxy-server="socks5://127.0.0.1:1080" \
         --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
         --proxy-bypass-list="<-loopback>" \
         --user-data-dir=/tmp/chromium-0tpe
```

To reduce log noise from background Google services:

```bash
chromium --proxy-server="socks5://127.0.0.1:1080" \
         --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
         --proxy-bypass-list="<-loopback>" \
         --disable-background-networking \
         --disable-component-update \
         --disable-sync \
         --no-first-run \
         --user-data-dir=/tmp/chromium-0tpe
```

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
```

Produces a link like:

```
otpe://550e8400e29b41d4@127.0.0.1:8443?sni=www.microsoft.com#MyServer
```

## Testing

Full suite — builds if needed, starts server and client, runs every test, tears down:

```bash
make test
```

Individual tests:

```bash
make clean && make

./otpe-test               # protocol encode/decode
./otpe-test-crypto        # X25519 DH
./otpe-test-udp           # DNS over UDP end-to-end
./otpe-test-udp-stress    # 25 clients x 10 echo queries
./otpe-ping 127.0.0.1 8443 20
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
[Browser] --SOCKS5/HTTP--> [otpe-client] --0TPE+BoringSSL--> [otpe-server] --TCP/UDP--> [target]
                              (your PC)         (wire)              (VPS)
```

- **otpe-client** listens on `127.0.0.1:1080` (SOCKS5), `127.0.0.1:8080` (HTTP CONNECT), and a dynamic UDP port
- Sends `CONNECT host:port` or `UDP host:port` commands via the 0TPE header
- **otpe-server** connects to the target and relays bytes in both directions with a 10-second idle timeout and a 5-second grace timeout

## How it works

1. Client connects to the server over TLS (BoringSSL)
2. Client sends a **client certificate** signed by the internal CA
3. Client also advertises **ALPN** `h2,http/1.1,0tpe` — the server uses this to recognize it as a 0TPE client
4. If both checks pass, the server enters 0TPE mode
5. If either fails, the server **transparently proxies** the connection to `www.microsoft.com:443`
6. An outside observer sees a real TLS session with a real Microsoft certificate

## Security

- `certs/ca.key` — CA private key, keep it on the server only
- `certs/client.key` — client private key, keep it on client machines only
- `certs/server.key` — server private key, keep it on the server
- Token in `0tpe.conf` — not critical, but better not to publish

## Limitations

- No multiplexing — each connection opens a new TLS session
- UDP relay keeps per-session state for up to 64 concurrent targets
- Idle timeout is 10 seconds — some applications that hold idle connections will see them dropped and reconnect

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

- `[tid ...] 0TPE client, SNI=...` — client recognized
- `[UDP tid ...] -> 8.8.8.8:53 (29 bytes)` — UDP relay working
- `[fallback] -> www.microsoft.com:443` — unrecognized connection redirected to fallback
- `[relay] idle timeout (10009 ms no data)` — stuck connection cleaned up
- `[tid ...] TLS failed (client cert rejected?)` — client certificate not signed by CA
- `config: <file> not readable: <path>` — a certificate, key, or CA file is missing or unreadable
- `config: token must be 16 hex chars` — token in `0tpe.conf` is not a valid hex string of at least 16 characters

## Project structure

```
.github/workflows/   — CI
bench/               — RTT and throughput benchmarks
certs/               — CA, server, client certificates (generated)
docs/                — SPEC.md, THREAT_MODEL.md, CODE_AUDIT.md
fuzz/                — libFuzzer target + corpus
include/             — header files
scripts/             — build_boringssl.sh, gen_ca.sh, build_release.sh
src/
  common/            — shared code
  client/            — client entry point
  server/            — server entry point
  ping/              — otpe-ping
  tools/             — genlink
tests/               — unit, integration, and stress tests (run_all.sh)
0tpe.conf            — default config
Makefile
README.md
LICENSE
```

## Name

**0TPE** — a short, unique identifier. The leading `0` comes from the author's handle.

## License

GNU General Public License v3.0 — see the [LICENSE](LICENSE) file.