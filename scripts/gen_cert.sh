#!/bin/bash
set -e
mkdir -p certs
if [ ! -f certs/server.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout certs/server.key \
        -out certs/server.crt \
        -days 3650 \
        -subj "/CN=www.microsoft.com" \
        -addext "subjectAltName=DNS:www.microsoft.com,DNS:microsoft.com"
    echo "Certificate generated."
fi