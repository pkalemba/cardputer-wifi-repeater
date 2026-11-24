# Host unit tests for the hardware independent parts of the firmware.
#   make -C test/host        build and run
#   make -C test/host clean
CXX ?= g++
CXXFLAGS ?= -std=gnu++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
SRC_DIR := ../../src
SOURCES := test_main.cpp $(SRC_DIR)/netutil.cpp $(SRC_DIR)/wifi_menu.cpp

.PHONY: run clean
run: build/tests
	./build/tests

build/tests: $(SOURCES) $(SRC_DIR)/netutil.h $(SRC_DIR)/wifi_menu.h
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -o $@ $(SOURCES)

clean:
	rm -rf build
