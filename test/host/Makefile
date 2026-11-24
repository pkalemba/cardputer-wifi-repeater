# Host unit tests for the hardware independent parts of the firmware.
#   make -C test/host        build and run
#   make -C test/host clean
CXX ?= g++
CC ?= gcc
SANITIZE := -fsanitize=address,undefined -fno-omit-frame-pointer
CXXFLAGS ?= -std=gnu++17 -O1 -g -Wall -Wextra -Werror $(SANITIZE)
CFLAGS ?= -std=c99 -O1 -g -Wall -Wextra -Werror $(SANITIZE)
SRC_DIR := ../../src
SOURCES := test_main.cpp $(SRC_DIR)/netutil.cpp $(SRC_DIR)/wifi_menu.cpp

.PHONY: run clean
run: build/tests
	./build/tests

# Vendored QR code generator (C)
build/qrcodegen.o: $(SRC_DIR)/qrcodegen/qrcodegen.c $(SRC_DIR)/qrcodegen/qrcodegen.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c -o $@ $<

build/tests: $(SOURCES) build/qrcodegen.o $(SRC_DIR)/netutil.h $(SRC_DIR)/wifi_menu.h
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -o $@ $(SOURCES) build/qrcodegen.o

clean:
	rm -rf build
