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

# The WebSocket frontend. ws.c/sha1.c/sha256.c are generic protocol+hash
# code with no motors knowledge and no libjct dependency, which is what lets
# the self-test below link them on their own.
WS_OBJS  := $(SRC_DIR)/sha1.o $(SRC_DIR)/sha256.o $(SRC_DIR)/ws.o \
            $(SRC_DIR)/ws_token.o $(SRC_DIR)/motor-ws.o

OBJS     := $(SRC_DIR)/motor.o $(SRC_DIR)/motor-daemon.o $(WS_OBJS)

# The daemon is threaded (async move workers, and now the WS listener and one
# thread per WS client), and motor-daemon.c uses libm.
DAEMON_LIBS := -lpthread -lm

.PHONY: all deps clean distclean format selftest check

all: deps $(BINARIES)

deps:
	@echo "Using libjct from the current toolchain/sysroot"

motor: $(SRC_DIR)/motor.o | deps
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_DIRS) $(LIBS) $(LDFLAGS)

motor-daemon: $(SRC_DIR)/motor-daemon.o $(WS_OBJS) | deps
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_DIRS) $(LIBS) $(DAEMON_LIBS) $(LDFLAGS)

# Self-test for the parts that can be exercised without a motor: SHA-1,
# SHA-256, base64, the RFC 6455 Sec-WebSocket-Accept vector, frame
# encode/parse and the query-string parser. Links no libjct and no motor
# code, so it runs natively on the development host even though the daemon
# itself only builds against the target sysroot.
#
# Built with HOSTCC and straight from sources rather than reusing $(SRC_DIR)
# objects: `make CROSS_COMPILE=...` leaves MIPS .o files in that directory,
# and a shared object tree would make `make check` in the same checkout try
# to link them with the host linker. Keeping the test self-contained means
# the two builds never collide, and `make check CROSS_COMPILE=...` still
# runs the test on the machine you are sitting at.
HOSTCC ?= cc

selftest: $(TEST_DIR)/ws_selftest
$(TEST_DIR)/ws_selftest: $(TEST_DIR)/ws_selftest.c $(SRC_DIR)/sha1.c \
                         $(SRC_DIR)/sha256.c $(SRC_DIR)/ws.c
	$(HOSTCC) -Wall -Wextra -O2 -I$(SRC_DIR) -o $@ $^

check: selftest
	./$(TEST_DIR)/ws_selftest

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

