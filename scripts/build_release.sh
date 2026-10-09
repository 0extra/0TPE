#!/bin/bash
set -e

VERSION="${1:-v0.1.4}"
ARCH="linux-x86_64"
DIST="dist"

echo "=== Building 0TPE $VERSION for $ARCH ==="

make clean
make release

rm -rf "$DIST"
mkdir -p "$DIST"

SERVER_NAME="otpe-server-$VERSION-$ARCH"
SERVER_DIR="$DIST/$SERVER_NAME"

mkdir -p "$SERVER_DIR/scripts"

cp otpe-server  "$SERVER_DIR/"
cp 0tpe.conf    "$SERVER_DIR/0tpe.conf"
cp LICENSE      "$SERVER_DIR/"
cp COPYING      "$SERVER_DIR/"
cp Dockerfile   "$SERVER_DIR/"
cp .dockerignore "$SERVER_DIR/"
cp docker-compose.yml "$SERVER_DIR/"
cp -r src include Makefile "$SERVER_DIR/"

cp scripts/gen_ca.sh            "$SERVER_DIR/scripts/"
cp scripts/build_boringssl.sh   "$SERVER_DIR/scripts/"

cat > "$SERVER_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
set -e

cd "$(dirname "$0")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== 0TPE Server ===${NC}"
echo ""

if [ ! -f certs/ca.crt ]; then
    echo -e "${YELLOW}[1/2] Generating CA and certificates...${NC}"
    chmod +x scripts/gen_ca.sh
    ./scripts/gen_ca.sh
else
    echo -e "${GREEN}[1/2] CA and certificates already exist${NC}"
fi

echo ""

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
        echo -e "${YELLOW}[2/2] Starting via docker compose...${NC}"
        docker compose down --remove-orphans 2>/dev/null || true
        docker rm -f otpe-server 2>/dev/null || true
        docker compose up -d --build
        sleep 2
        echo ""
        echo -e "${GREEN}=== 0TPE Server is running (docker compose) ===${NC}"
        echo ""
        echo "  Logs:    docker compose logs -f"
        echo "  Stop:    docker compose down"
        echo "  Restart: docker compose restart"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo -e "${YELLOW}[2/2] Starting via docker-compose (v1)...${NC}"
        docker-compose down --remove-orphans 2>/dev/null || true
        docker rm -f otpe-server 2>/dev/null || true
        docker-compose up -d --build
        sleep 2
        echo ""
        echo -e "${GREEN}=== 0TPE Server is running (docker-compose) ===${NC}"
    else
        echo -e "${YELLOW}[2/2] Docker found but no compose. Running natively.${NC}"
        ./otpe-server 0tpe.conf
        exit 0
    fi
else
    echo -e "${YELLOW}[2/2] Docker not available. Running natively.${NC}"
    echo ""
    ./otpe-server 0tpe.conf
    exit 0
fi

echo ""
echo -e "${GREEN}=== Client setup ===${NC}"
echo ""
echo "Copy these files to your client machine:"
echo -e "  ${YELLOW}certs/client.crt${NC}"
echo -e "  ${YELLOW}certs/client.key${NC}"
echo ""
echo "Then in the client's 0tpe.conf set:"
echo "  server_ip = <this server's IP>"
echo "  server_port = 8443"
echo ""

PUBLIC_IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo "<your-public-ip>")
echo -e "Detected public IP: ${GREEN}$PUBLIC_IP${NC}"
echo ""
echo "Make sure port 8443/tcp is open in your firewall:"
echo "  sudo ufw allow 8443/tcp"
echo ""
STARTEOF

chmod +x "$SERVER_DIR/start.sh"

cat > "$SERVER_DIR/README.txt" << 'READMEEOF'
0TPE Server
===========

Quick start
-----------

    tar xzf otpe-server-v0.1.4-linux-x86_64.tar.gz
    cd otpe-server-v0.1.4-linux-x86_64
    ./start.sh

That's it. The script will:
  - Generate internal CA, server certificate, and client certificate
  - Start the server via Docker (if available) or natively
  - Show you which files to copy to each client

After startup, copy these to each client machine:
  - certs/client.crt
  - certs/client.key

Open port 8443/tcp in your firewall.

Manual usage (without start.sh)
--------------------------------

Native:
    ./scripts/gen_ca.sh
    ./otpe-server 0tpe.conf

Docker:
    ./scripts/gen_ca.sh
    docker compose up -d
    docker compose logs -f

Documentation
-------------

https://github.com/0extra/0TPE

License
-------

GPLv3 — see LICENSE.
READMEEOF

CLIENT_NAME="otpe-client-$VERSION-$ARCH"
CLIENT_DIR="$DIST/$CLIENT_NAME"

mkdir -p "$CLIENT_DIR/certs"

cp otpe-client  "$CLIENT_DIR/"
cp otpe-genlink "$CLIENT_DIR/"
cp 0tpe.conf    "$CLIENT_DIR/0tpe.conf"
cp LICENSE      "$CLIENT_DIR/"
cp COPYING      "$CLIENT_DIR/"

cat > "$CLIENT_DIR/certs/README.txt" << 'CREADMEEOF'
Put your client certificate and key here:

  client.crt
  client.key

You get these files from the server after running ./start.sh there
(look in the server's certs/ directory).
CREADMEEOF

cat > "$CLIENT_DIR/start.sh" << 'CLIENTEOF'
#!/bin/bash
set -e

cd "$(dirname "$0")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== 0TPE Client ===${NC}"
echo ""

if [ ! -f certs/client.crt ] || [ ! -f certs/client.key ]; then
    echo -e "${RED}ERROR: certs/client.crt or certs/client.key not found.${NC}"
    echo ""
    echo "Copy these files from your server's certs/ directory:"
    echo "  client.crt"
    echo "  client.key"
    echo ""
    echo "Then run ./start.sh again."
    exit 1
fi

if ! grep -q "^server_ip" 0tpe.conf; then
    echo -e "${RED}ERROR: 0tpe.conf does not have server_ip.${NC}"
    exit 1
fi

SERVER_IP=$(grep "^server_ip" 0tpe.conf | head -1 | sed 's/.*= *//' | tr -d ' ')
echo "  Server:       $SERVER_IP:8443"
echo "  SOCKS5 port:  1080"
echo "  HTTP port:    8080"
echo ""
echo "Configure your browser to use:"
echo "  SOCKS5: 127.0.0.1:1080  (enable 'Proxy DNS when using SOCKS v5')"
echo "  or HTTP: 127.0.0.1:8080"
echo ""

./otpe-client 0tpe.conf
CLIENTEOF

chmod +x "$CLIENT_DIR/start.sh"

cat > "$CLIENT_DIR/README.txt" << 'CREADMEEOF'
0TPE Client
===========

Quick start
-----------

1. Get these files from your server:
     certs/client.crt
     certs/client.key
   Copy them into this folder's certs/ directory.

2. Edit 0tpe.conf and set server_ip to your server's IP:

       server_ip = 1.2.3.4

3. Run:

       ./start.sh

4. Configure your browser (Firefox, Chromium):

   Firefox:
     Settings → Network Settings → Manual proxy
     SOCKS Host: 127.0.0.1   Port: 1080   SOCKS v5
     "Proxy DNS when using SOCKS v5"

   Chromium:
     chromium --proxy-server="socks5://127.0.0.1:1080" \
              --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"

Documentation
-------------

https://github.com/0extra/0TPE

License
-------

GPLv3 — see LICENSE.
CREADMEEOF

cd "$DIST"
tar czf "$SERVER_NAME.tar.gz" "$SERVER_NAME"
tar czf "$CLIENT_NAME.tar.gz" "$CLIENT_NAME"
sha256sum *.tar.gz > SHA256SUMS

echo ""
echo "=== Done ==="
ls -la *.tar.gz SHA256SUMS
echo ""
cat SHA256SUMS