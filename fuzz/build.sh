#!/bin/bash
set -e

if ! command -v clang >/dev/null 2>&1; then
    echo "clang not found. install clang first."
    exit 1
fi

mkdir -p fuzz/corpus

clang -fsanitize=fuzzer,address,undefined \
      -Iinclude -g -O1 \
      -o fuzz/fuzz_clienthello \
      fuzz/fuzz_clienthello.c \
      src/common/tls_peek.c

echo "built fuzz/fuzz_clienthello"
echo "run: ./fuzz/fuzz_clienthello fuzz/corpus -max_total_time=300"