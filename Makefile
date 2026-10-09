USE_BORINGSSL ?= 1
BORINGSSL_DIR ?= /opt/boringssl

CC = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude -g
LDFLAGS =
LIBS    = -lpthread

ifeq ($(USE_BORINGSSL),1)
    CFLAGS  += -I$(BORINGSSL_DIR)/include
    LIBS    := -Wl,--start-group \
               $(BORINGSSL_DIR)/build/libssl.a \
               $(BORINGSSL_DIR)/build/libcrypto.a \
               -Wl,--end-group \
               -lstdc++ \
               $(LIBS)
else
    LIBS    := -lssl -lcrypto $(LIBS)
endif

FUZZ_CC = clang
FUZZ_CFLAGS = -fsanitize=fuzzer,address,undefined -Iinclude -g -O1

SRC_COMMON = src/common/protocol.c src/common/relay.c src/common/tls.c src/common/socks5.c src/common/config.c src/common/http_proxy.c src/common/tls_peek.c src/common/crypto.c src/common/dns_cache.c src/common/uri.c src/common/udp_stateful.c
SRC_SERVER = src/server/main.c $(SRC_COMMON)
SRC_CLIENT = src/client/main.c $(SRC_COMMON)
SRC_PING   = src/ping/main.c   $(SRC_COMMON)
SRC_GENLINK = src/tools/genlink.c $(SRC_COMMON)
SRC_TEST_PROTO  = tests/test_protocol.c $(SRC_COMMON)
SRC_TEST_CRYPTO = tests/test_crypto.c   $(SRC_COMMON)
SRC_TEST_UDP    = tests/test_udp.c
SRC_TEST_UDP_STRESS = tests/test_udp_stress.c
SRC_BENCH_THROUGHPUT = bench/throughput.c $(SRC_COMMON)
SRC_BENCH_RTT = bench/rtt.c $(SRC_COMMON)

all: otpe-server otpe-client otpe-ping otpe-genlink otpe-test otpe-test-crypto otpe-test-udp otpe-test-udp-stress

otpe-server: $(SRC_SERVER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-client: $(SRC_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-ping: $(SRC_PING)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-genlink: $(SRC_GENLINK)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-test: $(SRC_TEST_PROTO)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-test-crypto: $(SRC_TEST_CRYPTO)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-test-udp: $(SRC_TEST_UDP)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

otpe-test-udp-stress: $(SRC_TEST_UDP_STRESS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

bench-rtt: $(SRC_BENCH_RTT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

bench-throughput: $(SRC_BENCH_THROUGHPUT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

bench: bench-rtt bench-throughput

release: all bench
	strip --strip-all otpe-server otpe-client otpe-genlink otpe-ping bench-rtt bench-throughput

fuzz: fuzz/fuzz_clienthello.c src/common/tls_peek.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o fuzz/fuzz_clienthello fuzz/fuzz_clienthello.c src/common/tls_peek.c

fuzz-run: fuzz
	mkdir -p fuzz/corpus
	./fuzz/fuzz_clienthello fuzz/corpus -max_total_time=300

test: all
	./tests/run_all.sh

clean:
	rm -f otpe-server otpe-client otpe-ping otpe-genlink otpe-test otpe-test-crypto otpe-test-udp otpe-test-udp-stress bench-rtt bench-throughput fuzz/fuzz_clienthello

fuzz-clean:
	rm -f fuzz/fuzz_clienthello
	rm -rf fuzz/corpus

.PHONY: all clean fuzz fuzz-run fuzz-clean bench release test