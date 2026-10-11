# FUSE-T installs headers/libs under /usr/local.
CC       ?= clang
CXX      ?= clang++
SAN      ?= -fsanitize=address,undefined
CFLAGS   ?= -Wall -Wextra -g $(SAN) -D_FILE_OFFSET_BITS=64
CXXFLAGS ?= -std=c++17 -Wall -Wextra -g $(SAN)
FUSE_INC := -I/usr/local/include -I/usr/local/include/fuse
# The dylib's install name is @rpath/libfuse-t.dylib, so the binary needs an
# rpath entry telling dyld where to search at launch.
FUSE_LIB := -L/usr/local/lib -lfuse-t -Wl,-rpath,/usr/local/lib

all: build/tierfs build/tierfs-backend build/hellofs build/tierctl build/tierfs-device

build/metastore.o: core/metastore.cpp core/metastore.hpp core/tierclient.h core/sqlutil.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/chunkcache.o: core/chunkcache.cpp core/chunkcache.hpp core/sqlutil.hpp core/hash.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/tierctl: tools/tierctl.cpp build/chunkcache.o
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

build/ledger.o: core/ledger.cpp core/ledger.hpp core/sqlutil.hpp core/hash.hpp core/crashpoint.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/ledger_test: tests/ledger_test.cpp build/ledger.o build/ledger_helper
	$(CXX) $(CXXFLAGS) tests/ledger_test.cpp build/ledger.o -o $@ -lsqlite3

build/ledger_helper: tests/ledger_helper.cpp build/ledger.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

# Crypto: OpenSSL, linked statically so nothing but the macOS system libraries is needed at run time.
OPENSSL_DIR ?= /opt/homebrew/opt/openssl@3
OPENSSL_INC := -I$(OPENSSL_DIR)/include
OPENSSL_LIB := $(OPENSSL_DIR)/lib/libcrypto.a

build/crypto.o: core/crypto.cpp core/crypto.hpp core/wire.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -c $< -o $@

build/keychain_mac.o: core/keychain_mac.cpp core/crypto.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/devicestore.o: core/devicestore.cpp core/devicestore.hpp core/crypto.hpp core/sqlutil.hpp core/crashpoint.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -c $< -o $@

build/deviceclient.o: core/deviceclient.cpp core/deviceclient.hpp core/devicestore.hpp core/net.hpp core/wire.hpp core/crypto.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -c $< -o $@

build/replicator.o: core/replicator.cpp core/replicator.hpp core/ledger.hpp core/deviceclient.hpp core/crypto.hpp core/crashpoint.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) -c $< -o $@

build/repl_helper: tests/repl_helper.cpp build/replicator.o build/ledger.o build/deviceclient.o build/devicestore.o build/crypto.o
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/repl_helper.cpp build/replicator.o build/ledger.o build/deviceclient.o build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

build/replicator_test: tests/replicator_test.cpp build/replicator.o build/ledger.o build/deviceclient.o build/devicestore.o build/crypto.o build/repl_helper
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/replicator_test.cpp build/replicator.o build/ledger.o build/deviceclient.o build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

test-replicator: build/replicator_test build/tierfs-device
	./build/replicator_test

build/devicenet_test: tests/devicenet_test.cpp build/deviceclient.o build/devicestore.o build/crypto.o
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/devicenet_test.cpp build/deviceclient.o build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

test-device: build/devicenet_test build/tierfs-device
	./build/devicenet_test

build/tierfs-device: backend/device_server.cpp build/devicestore.o build/crypto.o core/wire.hpp
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) backend/device_server.cpp build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

build/devicestore_test: tests/devicestore_test.cpp build/devicestore.o build/crypto.o build/device_helper
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/devicestore_test.cpp build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

build/device_helper: tests/device_helper.cpp build/devicestore.o build/crypto.o
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/device_helper.cpp build/devicestore.o build/crypto.o $(OPENSSL_LIB) -lsqlite3 -o $@

build/crypto_test: tests/crypto_test.cpp tests/crypto_kat.hpp build/crypto.o build/keychain_mac.o
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) tests/crypto_test.cpp build/crypto.o build/keychain_mac.o $(OPENSSL_LIB) -framework Security -framework CoreFoundation -o $@

build/metastore_test: tests/metastore_test.cpp build/metastore.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

build/chunkcache_test: tests/chunkcache_test.cpp build/chunkcache.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

build/client_test: tests/client_test.cpp build/tierclient.o build/metastore.o build/chunkcache.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

# Needs the backend binary. Builds the whole client with ThreadSanitizer too.
test-client: build/client_test build/tierfs-backend build/tierctl
	./build/client_test

test-tsan: build/tierfs-backend
	@mkdir -p build/tsan
	$(CXX) -std=c++17 -g -O1 -fsanitize=thread tests/client_test.cpp core/tierclient.cpp core/metastore.cpp core/chunkcache.cpp -o build/tsan/client_test -lsqlite3
	./build/tsan/client_test

test-unit: build/metastore_test build/chunkcache_test build/ledger_test build/crypto_test build/devicestore_test
	./build/metastore_test | tail -1
	./build/chunkcache_test | tail -1
	./build/ledger_test | tail -1
	./build/crypto_test | tail -1
	./build/devicestore_test

build/tierfs-backend: backend/server.cpp core/wire.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@

build/tierclient.o: core/tierclient.cpp core/tierclient.h core/wire.hpp core/chunkcache.hpp core/metastore.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/tierfs.o: mount/tierfs.c core/tierclient.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(FUSE_INC) -c $< -o $@

# Linked with the C++ compiler so libc++ comes along for the client library.
build/tierfs: build/tierfs.o build/tierclient.o build/metastore.o build/chunkcache.o
	$(CXX) $(SAN) $^ -o $@ $(FUSE_LIB) -lsqlite3

build/hellofs: mount/hellofs.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(FUSE_INC) $< -o $@ $(FUSE_LIB)

clean:
	rm -rf build

.PHONY: all clean test-unit test-client test-tsan
