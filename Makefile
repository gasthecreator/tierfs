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

all: build/tierfs build/tierfs-backend build/hellofs build/tierctl

build/metastore.o: core/metastore.cpp core/metastore.hpp core/tierclient.h core/sqlutil.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/chunkcache.o: core/chunkcache.cpp core/chunkcache.hpp core/sqlutil.hpp core/hash.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/tierctl: tools/tierctl.cpp build/chunkcache.o
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $^ -o $@ -lsqlite3

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

test-unit: build/metastore_test build/chunkcache_test
	./build/metastore_test | tail -1
	./build/chunkcache_test

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
