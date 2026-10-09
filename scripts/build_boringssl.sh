#!/bin/bash
set -e

BORINGSSL_DIR="${1:-/opt/boringssl}"

if [ -d "$BORINGSSL_DIR/build" ] && [ -f "$BORINGSSL_DIR/build/libssl.a" ]; then
    echo "BoringSSL already built at $BORINGSSL_DIR"
    exit 0
fi

if [ ! -d "$BORINGSSL_DIR" ]; then
    mkdir -p "$BORINGSSL_DIR" 2>/dev/null || {
        sudo mkdir -p "$BORINGSSL_DIR"
        sudo chown "$(id -u):$(id -g)" "$BORINGSSL_DIR"
    }
fi

cd "$BORINGSSL_DIR"

if [ ! -d .git ]; then
    git clone https://boringssl.googlesource.com/boringssl .
fi

mkdir -p build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja

echo "BoringSSL built at $BORINGSSL_DIR/build"