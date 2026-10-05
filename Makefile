CC = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude -g
LDFLAGS = -lssl -lcrypto -lpthread

FUZZ_CC = clang
FUZZ_CFLAGS = -fsanitize=fuzzer,address,undefined -Iinclude -g -O1

SRC_COMMON = src/common/protocol.c src/common/relay.c src/common/tls.c src/common/socks5.c src/common/config.c src/common/http_proxy.c src/common/tls_peek.c src/common/crypto.c src/common/nonce_cache.c src/common/uri.c
SRC_SERVER = src/server/main.c $(SRC_COMMON)
SRC_CLIENT = src/client/main.c $(SRC_COMMON)
SRC_PING   = src/ping/main.c   $(SRC_COMMON)
SRC_GENLINK = src/tools/genlink.c $(SRC_COMMON)
SRC_TEST_PROTO  = tests/test_protocol.c $(SRC_COMMON)
SRC_TEST_CRYPTO = tests/test_crypto.c   $(SRC_COMMON)
SRC_TEST_UDP    = tests/test_udp.c
SRC_BENCH_THROUGHPUT = bench/throughput.c $(SRC_COMMON)
SRC_BENCH_RTT = bench/rtt.c $(SRC_COMMON)

all: otpe-server otpe-client otpe-ping otpe-genlink otpe-test otpe-test-crypto otpe-test-udp

otpe-server: $(SRC_SERVER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-client: $(SRC_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-ping: $(SRC_PING)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-genlink: $(SRC_GENLINK)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-test: $(SRC_TEST_PROTO)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-test-crypto: $(SRC_TEST_CRYPTO)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

otpe-test-udp: $(SRC_TEST_UDP)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench-rtt: $(SRC_BENCH_RTT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench-throughput: $(SRC_BENCH_THROUGHPUT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench: bench-rtt bench-throughput

fuzz: fuzz/fuzz_clienthello.c src/common/tls_peek.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o fuzz/fuzz_clienthello fuzz/fuzz_clienthello.c src/common/tls_peek.c

fuzz-run: fuzz
	mkdir -p fuzz/corpus
	./fuzz/fuzz_clienthello fuzz/corpus -max_total_time=300
	
clean:
	rm -f otpe-server otpe-client otpe-ping otpe-genlink otpe-test otpe-test-crypto otpe-test-udp bench-rtt bench-throughput fuzz/fuzz_clienthello

fuzz-clean:
	rm -f fuzz/fuzz_clienthello
	rm -rf fuzz/corpus

.PHONY: all clean fuzz fuzz-run fuzz-clean bench