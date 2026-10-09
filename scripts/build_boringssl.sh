#!/bin/bash
set -e

BORINGSSL_DIR="${1:-/opt/boringssl}"

if [ -d "$BORINGSSL_DIR/build" ] && [ -f "$BORINGSSL_DIR/build/ssl/libssl.a" ]; then
    echo "BoringSSL already built at $BORINGSSL_DIR"
    exit 0
fi

sudo mkdir -p "$BORINGSSL_DIR"
sudo chown "$USER:$USER" "$BORINGSSL_DIR"
cd "$BORINGSSL_DIR"

if [ ! -d .git ]; then
    git clone https://boringssl.googlesource.com/boringssl .
fi

mkdir -p build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja

echo "BoringSSL built at $BORINGSSL_DIR/build"