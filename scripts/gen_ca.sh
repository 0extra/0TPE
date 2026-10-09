#!/bin/bash
set -e
mkdir -p certs

# --- CA ---
if [ ! -f certs/ca.key ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out certs/ca.key
    openssl req -x509 -new -key certs/ca.key -days 3650 \
        -subj "/CN=0TPE Internal CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out certs/ca.crt
    echo "CA generated."
fi

# --- Server cert ---
if [ ! -f certs/server.key ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out certs/server.key
    openssl req -new -key certs/server.key \
        -subj "/CN=www.microsoft.com" \
        -out certs/server.csr
    openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -days 3650 \
        -extfile <(printf "subjectAltName=DNS:www.microsoft.com,DNS:microsoft.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") \
        -out certs/server.crt
    rm certs/server.csr
    echo "Server certificate generated."
fi

# --- Client cert ---
if [ ! -f certs/client.key ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out certs/client.key
    openssl req -new -key certs/client.key \
        -subj "/CN=0TPE Client" \
        -out certs/client.csr
    openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
        -CAcreateserial -days 3650 \
        -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth") \
        -out certs/client.crt
    rm certs/client.csr
    echo "Client certificate generated."
fi

echo ""
echo "  certs/ca.crt       — CA certificate"
echo "  certs/ca.key       — CA private key (keep secret!)"
echo "  certs/server.crt   — server certificate"
echo "  certs/server.key   — server private key"
echo "  certs/client.crt   — client certificate"
echo "  certs/client.key   — client private key"