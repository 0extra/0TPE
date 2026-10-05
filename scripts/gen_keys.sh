#!/bin/bash
set -e
mkdir -p keys
if [ ! -f keys/server.key ]; then
    openssl genpkey -algorithm X25519 -out keys/server.key
    openssl pkey -in keys/server.key -pubout -out keys/server.pub
    echo "X25519 keys generated."
    echo "  private: keys/server.key"
    echo "  public:  keys/server.pub"
else
    echo "Keys already exist."
fi