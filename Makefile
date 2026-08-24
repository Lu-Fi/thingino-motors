# Simple Makefile for ingenic-motor
# - Builds motor and motor-daemon
# - Links against libjct for JSON parsing/config support
#
# Usage examples:
#   make                          # native build (expects libjct in default paths)
#   make CROSS_COMPILE=mipsel-linux-gnu- SYSROOT=/opt/mipsel-sysroot
#   make JCT_PREFIX=/opt/libjct   # explicit lib/include directories for libjct

CC       ?= cc
CFLAGS   ?= -Wall -Wextra -O2
LDFLAGS  ?=

# Cross-compilation (use CROSS_COMPILE=triplet-), e.g.:
#   make CROSS_COMPILE=mipsel-linux-gnu- SYSROOT=/opt/mipsel-sysroot
CROSS_COMPILE ?=
SYSROOT       ?=
JCT_PREFIX    ?=

ifneq ($(strip $(CROSS_COMPILE)),)
CC     := $(CROSS_COMPILE)gcc
AR     := $(CROSS_COMPILE)ar
RANLIB := $(CROSS_COMPILE)ranlib
STRIP  := $(CROSS_COMPILE)strip
endif

ifneq ($(strip $(SYSROOT)),)
CFLAGS  += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

ifneq ($(strip $(JCT_PREFIX)),)
INCLUDE_DIRS += -I$(JCT_PREFIX)/include
LIB_DIRS     += -L$(JCT_PREFIX)/lib
endif

LIBS += -ljct

SRC_DIR  := src
TEST_DIR := tests
BINARIES := motor motor-daemon

# ws.c/sha1.c/sha256.c are generic protocol+hash code with no motors
# knowledge and no libjct dependency, which is what lets the self-test below
# link them on their own.
OBJS     := $(SRC_DIR)/motor.o $(SRC_DIR)/motor-daemon.o \
            $(SRC_DIR)/sha1.o $(SRC_DIR)/sha256.o $(SRC_DIR)/ws.o \
            $(TEST_DIR)/ws_selftest.o

.PHONY: all deps clean distclean format selftest check

all: deps $(BINARIES)

deps:
	@echo "Using libjct from the current toolchain/sysroot"

motor: $(SRC_DIR)/motor.o | deps
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_DIRS) $(LIBS) $(LDFLAGS)

motor-daemon: $(SRC_DIR)/motor-daemon.o | deps
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_DIRS) $(LIBS) $(LDFLAGS)

# Self-test for the parts that can be exercised without a motor: SHA-1,
# SHA-256, base64, the RFC 6455 Sec-WebSocket-Accept vector, frame
# encode/parse and the query-string parser. Links no libjct and no motor
# code, so it builds and runs natively on the development host even though
# the daemon itself only builds against the target sysroot.
selftest: $(TEST_DIR)/ws_selftest
$(TEST_DIR)/ws_selftest: $(TEST_DIR)/ws_selftest.o $(SRC_DIR)/sha1.o \
                         $(SRC_DIR)/sha256.o $(SRC_DIR)/ws.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

check: selftest
	./$(TEST_DIR)/ws_selftest

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(INCLUDE_DIRS) -c -o $@ $<

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) -c -o $@ $<

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SRC_DIR)/*.c $(SRC_DIR)/*.h; \
	else \
		echo "clang-format not found; skipping format"; \
	fi

clean:
	rm -f $(OBJS) $(BINARIES) $(TEST_DIR)/ws_selftest
	rm -f *.o *.a *.so $(SRC_DIR)/*.o $(TEST_DIR)/*.o

distclean: clean
	rm -rf third_party

