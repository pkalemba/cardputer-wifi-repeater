# Host unit tests for the hardware independent parts of the apps.
#   make -C test/host        build and run
#   make -C test/host clean
CXX ?= g++
CC ?= gcc
SANITIZE := -fsanitize=address,undefined -fno-omit-frame-pointer
CXXFLAGS ?= -std=gnu++17 -O1 -g -Wall -Wextra -Werror $(SANITIZE)
CFLAGS ?= -std=c99 -O1 -g -Wall -Wextra -Werror $(SANITIZE)

LIB := ../../lib/cardputer/src
REPEATER := ../../apps/wifi-repeater/src
TRACKERS := ../../apps/tracker-detector/src
ROOMSCAN := ../../apps/room-scanner/src

SOURCES := test_main.cpp test_trackers.cpp test_roomscan.cpp \
	$(REPEATER)/netutil.cpp $(REPEATER)/wifi_menu.cpp $(LIB)/keymap.cpp \
	$(TRACKERS)/trackers.cpp $(ROOMSCAN)/roomscan.cpp
HEADERS := test.h $(REPEATER)/netutil.h $(REPEATER)/wifi_menu.h $(LIB)/keymap.h \
	$(TRACKERS)/trackers.h $(ROOMSCAN)/roomscan.h $(ROOMSCAN)/oui_table.h
INCLUDES := -I$(LIB) -I$(REPEATER) -I$(TRACKERS) -I$(ROOMSCAN)

.PHONY: run clean
run: build/tests
	./build/tests

# Vendored QR code generator (C)
build/qrcodegen.o: $(LIB)/qrcodegen/qrcodegen.c $(LIB)/qrcodegen/qrcodegen.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c -o $@ $<

build/tests: $(SOURCES) $(HEADERS) build/qrcodegen.o
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SOURCES) build/qrcodegen.o

clean:
	rm -rf build
