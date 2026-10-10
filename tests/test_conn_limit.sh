#!/bin/bash
set -u
cd "$(dirname "$0")/.."

MAX="${1:-2}"
HOLD="${2:-10}"

echo "=== Connection limit test (max=$MAX, hold=${HOLD}s) ==="

pkill -9 otpe-server 2>/dev/null
pkill -9 otpe-client 2>/dev/null
sleep 0.3

# temporary config with small limit
cp 0tpe.conf /tmp/0tpe.conf.bak
sed -i "s/^max_connections.*/max_connections = $MAX/" 0tpe.conf

stdbuf -oL -eL ./otpe-server 0tpe.conf > /tmp/otpe-limit.log 2>&1 &
SERVER_PID=$!
sleep 0.5

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "FAIL: server did not start"
    tail -5 /tmp/otpe-limit.log
    mv /tmp/0tpe.conf.bak 0tpe.conf
    exit 1
fi

echo "Opening $MAX long-lived raw TCP connections to 127.0.0.1:8443..."

PIDS=()
for ((i=1; i<=MAX; i++)); do
    ( exec 3<>/dev/tcp/127.0.0.1/8443; sleep "$HOLD" ) &
    PIDS+=($!)
done

sleep 1
echo "Now trying to open one more (should be rejected)..."

# this connection should be accepted by kernel but immediately closed by server
( exec 4<>/dev/tcp/127.0.0.1/8443; sleep 1; exec 4<&-; exec 4>&- ) 2>/dev/null
sleep 0.5

# check server log
if grep -q "connection limit reached" /tmp/otpe-limit.log; then
    echo "PASS: server logged 'connection limit reached'"
    RESULT=0
else
    echo "FAIL: no 'connection limit reached' in server log"
    echo "--- server log ---"
    cat /tmp/otpe-limit.log
    RESULT=1
fi

# cleanup
for pid in "${PIDS[@]}"; do kill $pid 2>/dev/null; done
kill $SERVER_PID 2>/dev/null
wait 2>/dev/null
mv /tmp/0tpe.conf.bak 0tpe.conf

exit $RESULT