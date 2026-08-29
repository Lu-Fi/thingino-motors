# Simple Makefile for ingenic-motor
# - Builds motor and motor-daemon
# - Links against libjct for JSON parsing/config support
#
# Usage examples:
#   make                          # native build (expects libjct in default paths)
#   make CROSS_COMPILE=mipsel-linux-gnu- SYSROOT=/opt/mipsel-sysroot
#   make JCT_PREFIX=/opt/libjct   # explicit lib/include directories for libjct

CC       ?= cc
# -ffunction-sections/-fdata-sections (paired with -Wl,--gc-sections below)
# let the linker drop any function or global that ends up unreferenced -
# measured on the real target build (thingino-motors.mk's -Os -s daemon
# link): 62904 -> 55224 bytes, -7680 bytes (-12.2%), with the same symbols
# reachable from main. Pure dead-code elimination, no behavior change: it
# only removes things nothing calls (confirmed here by diffing nm output
# before/after - the WS listener, token check and JSON depth guard all stay).
CFLAGS   ?= -Wall -Wextra -O2 -ffunction-sections -fdata-sections
LDFLAGS  ?= -Wl,--gc-sections

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
#
# WS=0 builds the daemon without any of it - no listener, no token store,
# ~25 KB less text. That configuration is not hypothetical: the thingino
# package that consumes this tree gates the same five files behind a Kconfig
# option (BR2_PACKAGE_THINGINO_MOTORS_WS) and compiles the .c files directly
# instead of calling this Makefile, so it has to be buildable here as well or
# nobody notices when an unguarded reference breaks it. -DMOTORS_WS is what
# motor-daemon.c keys its #ifdefs off; both builds must stay warning-clean.
# WS_DEFS is kept out of CFLAGS on purpose. CFLAGS is declared with ?= so a
# caller can replace it wholesale (`make CFLAGS="-Wall -Os"`), and a
# command-line assignment overrides every += in this file - which would have
# silently dropped -DMOTORS_WS and produced a daemon that links the whole
# listener and then never starts it. Appending it at the compile rule instead
# makes that impossible.
WS       ?= 1

# wss:// (WS_TLS=1). Off by default because it is the one thing in this tree
# with a dependency beyond libjct - mbedTLS - and `make` on a bare development
# host must keep working without it. The thingino package turns it on from its
# own Kconfig option (BR2_PACKAGE_THINGINO_MOTORS_WS_TLS), where the dependency
# is declared and therefore guaranteed present.
#
# WS=0 WS_TLS=1 is not a configuration: without the listener there is nothing
# to wrap, so the nesting below silently ignores it rather than half-building.
WS_TLS   ?= 0

ifeq ($(WS),0)
WS_OBJS  :=
WS_DEFS  :=
WS_LIBS  :=
else
WS_OBJS  := $(SRC_DIR)/sha1.o $(SRC_DIR)/sha256.o $(SRC_DIR)/ws.o \
            $(SRC_DIR)/ws_token.o $(SRC_DIR)/motor-ws.o
WS_DEFS  := -DMOTORS_WS
WS_LIBS  :=
ifeq ($(WS_TLS),1)
WS_OBJS  += $(SRC_DIR)/ws_tls.o
WS_DEFS  += -DMOTORS_WS_TLS
# x509 and crypto explicitly, not just -lmbedtls: certificate parsing and the
# DRBG live in the other two, and a static or --as-needed link will not pull
# them in transitively.
WS_LIBS  := -lmbedtls -lmbedx509 -lmbedcrypto
endif
endif

OBJS     := $(SRC_DIR)/motor.o $(SRC_DIR)/motor-daemon.o $(WS_OBJS)

# The daemon is threaded (async move workers, and now the WS listener and one
# thread per WS client), and motor-daemon.c uses libm.
DAEMON_LIBS := -lpthread -lm $(WS_LIBS)

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
	$(CC) $(CFLAGS) $(WS_DEFS) $(INCLUDE_DIRS) -c -o $@ $<

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

