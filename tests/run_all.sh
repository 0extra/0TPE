#!/bin/bash
set -u
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
FAILED_TESTS=()

run_test() {
    local name="$1"
    shift
    printf "  %-34s" "$name"

    local out_file
    out_file=$(mktemp)

    if "$@" > "$out_file" 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS+1))
        rm -f "$out_file"
    else
        echo -e "${RED}FAIL${NC}"
        echo "      --- command output ---"
        sed 's/^/      /' "$out_file" | tail -20
        rm -f "$out_file"
        FAIL=$((FAIL+1))
        FAILED_TESTS+=("$name")
    fi
}

run_test_retry() {
    local name="$1"
    local attempts="$2"
    shift 2
    printf "  %-34s" "$name"

    local out_file
    out_file=$(mktemp)
    local success=0

    for ((i=1; i<=attempts; i++)); do
        if "$@" > "$out_file" 2>&1; then
            success=1
            break
        fi
        sleep 0.5
    done

    if [ $success -eq 1 ]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS+1))
        rm -f "$out_file"
    else
        echo -e "${RED}FAIL${NC} (after $attempts attempts)"
        echo "      --- command output (last attempt) ---"
        sed 's/^/      /' "$out_file" | tail -20
        rm -f "$out_file"
        FAIL=$((FAIL+1))
        FAILED_TESTS+=("$name")
    fi
}

skip_test() {
    printf "  %-34s${YELLOW}SKIP${NC} (%s)\n" "$1" "$2"
    SKIP=$((SKIP+1))
}

dump_diagnostics() {
    echo ""
    echo "=== Diagnostics ==="
    echo "--- client log (last 30) ---"
    tail -30 /tmp/otpe-client.log 2>/dev/null | sed 's/^/  /'
    echo "--- server log (last 30) ---"
    tail -30 /tmp/otpe-server.log 2>/dev/null | sed 's/^/  /'
}

echo "=== 0TPE test suite ==="
echo ""

if [ ! -x ./otpe-server ] || [ ! -x ./otpe-client ] || [ ! -x ./otpe-test ]; then
    echo "Building..."
    make clean >/dev/null 2>&1
    make >/dev/null 2>&1 || { echo -e "${RED}Build failed${NC}"; exit 1; }
fi

echo "--- Unit tests ---"
run_test "protocol round-trip"   ./otpe-test
run_test "crypto DH"             ./otpe-test-crypto

echo ""
echo "--- Integration tests ---"

pkill -9 otpe-server 2>/dev/null
pkill -9 otpe-client 2>/dev/null
sleep 0.3

stdbuf -oL -eL ./otpe-server 0tpe.conf > /tmp/otpe-server.log 2>&1 &
SERVER_PID=$!
sleep 0.5

stdbuf -oL -eL ./otpe-client 0tpe.conf > /tmp/otpe-client.log 2>&1 &
CLIENT_PID=$!
sleep 0.5

cleanup() {
    kill $CLIENT_PID 2>/dev/null
    kill $SERVER_PID 2>/dev/null
    wait $CLIENT_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
}
trap cleanup EXIT INT TERM

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start:${NC}"
    tail -10 /tmp/otpe-server.log
    exit 1
fi
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo -e "${RED}Client failed to start:${NC}"
    tail -10 /tmp/otpe-client.log
    exit 1
fi

run_test "ping (20 packets)"     ./otpe-ping 127.0.0.1 8443 20
run_test "UDP end-to-end"        ./otpe-test-udp
run_test "UDP stress (25x10)"    ./otpe-test-udp-stress
run_test_retry "HTTP CONNECT"   3 curl -sS --max-time 20 --proxy http://127.0.0.1:8080 https://example.com -o /dev/null
run_test_retry "SOCKS5 TCP"     3 curl -sS --max-time 20 --socks5-hostname 127.0.0.1:1080 https://example.com -o /dev/null

echo ""
echo "--- Fuzzing ---"
if command -v clang >/dev/null 2>&1; then
    if make fuzz >/dev/null 2>&1; then
        mkdir -p fuzz/corpus
        printf "  %-34s" "clienthello fuzz (30s)"
        if timeout 40 ./fuzz/fuzz_clienthello fuzz/corpus -max_total_time=30 >/dev/null 2>&1; then
            echo -e "${GREEN}PASS${NC}"
            PASS=$((PASS+1))
        else
            echo -e "${RED}FAIL${NC}"
            FAIL=$((FAIL+1))
            FAILED_TESTS+=("clienthello fuzz")
        fi
    else
        skip_test "clienthello fuzz" "build failed"
    fi
else
    skip_test "clienthello fuzz" "no clang"
fi

echo ""
echo "=== Summary ==="
echo -e "  ${GREEN}PASS: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
    echo -e "  ${RED}FAIL: $FAIL${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "    - $t"
    done
else
    echo "  FAIL: 0"
fi
if [ $SKIP -gt 0 ]; then
    echo -e "  ${YELLOW}SKIP: $SKIP${NC}"
fi

if [ $FAIL -gt 0 ]; then
    dump_diagnostics
    exit 1
fi