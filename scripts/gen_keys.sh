#!/bin/bash
set -e
mkdir -p keys

if [ ! -f keys/server.key ]; then
    openssl genpkey -algorithm X25519 -out keys/server.key
    openssl pkey -in keys/server.key -pubout -out keys/server.pub
    echo "Server keys generated."
fi

if [ ! -f keys/client.key ]; then
    openssl genpkey -algorithm X25519 -out keys/client.key
    openssl pkey -in keys/client.key -pubout -out keys/client.pub
    echo "Client keys generated."
fi

if [ ! -f keys/authorized_keys ]; then
    cp keys/client.pub keys/authorized_keys
    echo "Authorized keys list created (with current client)."
fi

echo ""
echo "  server.key   — private (server only)"
echo "  server.pub   — public (copy to all clients)"
echo "  client.key   — private (client only)"
echo "  client.pub   — public (add to server authorized_keys)"
echo "  authorized_keys — list of allowed client public keys"