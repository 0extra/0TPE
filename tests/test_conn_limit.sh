#!/bin/bash
set -u
cd "$(dirname "$0")/.."

MAX="${1:-2}"
HOLD="${2:-8}"
PORT=$((20000 + RANDOM % 10000))

CONF=$(mktemp /tmp/0tpe-limit-XXXX.conf)
LOG=$(mktemp /tmp/0tpe-limit-XXXX.log)

cat > "$CONF" <<EOF
listen_ip       = 127.0.0.1
listen_port     = $PORT
max_connections = $MAX
cert_file       = certs/server.crt
key_file        = certs/server.key
ca_file         = certs/ca.crt
fallback_sni    = www.microsoft.com
log_level       = info
EOF

echo "=== Connection limit test (max=$MAX, port=$PORT) ==="

STDBUF=""
if [ -z "${ASAN_OPTIONS:-}" ]; then
    STDBUF="stdbuf -oL -eL"
fi

$STDBUF ./otpe-server "$CONF" > "$LOG" 2>&1 &
SERVER_PID=$!
sleep 0.7

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "FAIL: server did not start"
    tail -5 "$LOG"
    rm -f "$CONF" "$LOG"
    exit 1
fi

echo "Opening $MAX long-lived TCP connections to 127.0.0.1:$PORT..."

PIDS=()
for ((i=1; i<=MAX; i++)); do
    ( exec 3<>/dev/tcp/127.0.0.1/$PORT; sleep "$HOLD" ) &
    PIDS+=($!)
done

sleep 1
echo "Opening one more (should be rejected)..."

( exec 4<>/dev/tcp/127.0.0.1/$PORT; sleep 1 ) 2>/dev/null
sleep 0.5

RESULT=1
if grep -q "connection limit reached" "$LOG"; then
    echo "PASS: server logged 'connection limit reached'"
    RESULT=0
else
    echo "FAIL: no 'connection limit reached' in server log"
    echo "--- server log ---"
    cat "$LOG"
fi

for pid in "${PIDS[@]}"; do kill $pid 2>/dev/null; done
kill $SERVER_PID 2>/dev/null
wait 2>/dev/null
rm -f "$CONF" "$LOG"

exit $RESULT