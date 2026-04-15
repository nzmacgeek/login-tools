# login-tools Makefile — builds for BlueyOS (i386, static musl-blueyos libc)
#
# Quick start on a BlueyOS build host (sysroot at /opt/blueyos-sysroot):
#   make
#
# Quick start on a fresh host:
#   make musl          # clones nzmacgeek/musl-blueyos and builds into build/musl/
#   make               # builds all binaries (static i386 ELF)
#
# Override the musl sysroot:
#   make MUSL_PREFIX=/path/to/sysroot

# ---------------------------------------------------------------------------
# Musl sysroot detection
# ---------------------------------------------------------------------------
BUILD_DIR ?= build

# Prefer the system-wide BlueyOS sysroot (/opt/blueyos-sysroot) when present;
# this is where BlueyOS build hosts install musl-blueyos by default.
# Fall back to the local build/musl tree for fresh/CI environments.
BLUEYOS_SYSROOT ?= /opt/blueyos-sysroot
ifeq ($(shell [ -d "$(BLUEYOS_SYSROOT)" ] && echo yes),yes)
  MUSL_PREFIX ?= $(BLUEYOS_SYSROOT)
else
  MUSL_PREFIX ?= $(BUILD_DIR)/musl
endif

MUSL_INCLUDE := $(MUSL_PREFIX)/include
MUSL_LIB     := $(MUSL_PREFIX)/lib

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
# Use the musl-gcc wrapper from the sysroot when present — it wires up the
# correct specs file, CRT objects, and library path automatically.
# Fall back to plain gcc if musl has not yet been built.
ifneq ($(wildcard $(MUSL_PREFIX)/bin/musl-gcc),)
  CC := $(MUSL_PREFIX)/bin/musl-gcc
else
  CC := gcc
endif

# ---------------------------------------------------------------------------
# Flags — static i386 ELF against musl-blueyos
#
# crypt() is part of musl's libc — no separate -lcrypt needed.
# ---------------------------------------------------------------------------
CFLAGS  = -m32 -std=gnu11 -Wall -Wextra -O2 -D_GNU_SOURCE \
          -Isrc -Wno-unused-result -fno-stack-protector \
          -isystem $(MUSL_INCLUDE)

LDFLAGS = -m32 -static -no-pie -Wl,-m,elf_i386 -L$(MUSL_LIB) -lc

LIBDIR  = src/lib
SRCDIR  = src
BINDIR  = pkg/payload/usr/bin
SBINDIR = pkg/payload/usr/sbin

LIB_SRCS = \
    $(LIBDIR)/util.c \
    $(LIBDIR)/shadow.c \
    $(LIBDIR)/passwd_file.c \
    $(LIBDIR)/group_file.c \
    $(LIBDIR)/policy.c \
    $(LIBDIR)/faillock.c

LIB_OBJS = $(LIB_SRCS:.c=.o)

# Tools that require the full libauth stack (shadow, passwd, crypt, policy…)
TOOLS_AUTH_BIN  = passwd login chsh
TOOLS_AUTH_SBIN = setup-root useradd userdel usermod \
                  groupadd groupdel groupmod userlock

# Tools that only need POSIX libc — no shadow/crypt dependency.
TOOLS_SIMPLE_BIN = chmod chown chgrp

TOOLS_BIN  = $(TOOLS_AUTH_BIN) $(TOOLS_SIMPLE_BIN)
TOOLS_SBIN = $(TOOLS_AUTH_SBIN)

BIN_TARGETS  = $(addprefix $(BINDIR)/,  $(TOOLS_BIN))
SBIN_TARGETS = $(addprefix $(SBINDIR)/, $(TOOLS_SBIN))

.PHONY: all clean musl musl-check

all: musl-check $(BINDIR) $(SBINDIR) $(BIN_TARGETS) $(SBIN_TARGETS)

# ---------------------------------------------------------------------------
# Musl sysroot check — fails with a helpful message if not present
# ---------------------------------------------------------------------------
define check_musl
	@if [ ! -d "$(MUSL_INCLUDE)" ] || [ ! -f "$(MUSL_LIB)/libc.a" ]; then \
		echo ""; \
		echo "  [MUSL] musl sysroot not found under $(MUSL_PREFIX)"; \
		echo "         expected:"; \
		echo "           $(MUSL_INCLUDE)/  (headers)"; \
		echo "           $(MUSL_LIB)/libc.a  (static library)"; \
		echo ""; \
		echo "  To build musl-blueyos:"; \
		echo "    make musl"; \
		echo "  Or point at an existing sysroot:"; \
		echo "    make MUSL_PREFIX=/path/to/musl-sysroot"; \
		echo ""; \
		exit 1; \
	fi
endef

musl-check:
	$(call check_musl)

# ---------------------------------------------------------------------------
# Musl — clone nzmacgeek/musl-blueyos and build for i386
# ---------------------------------------------------------------------------
musl:
	@bash tools/build-musl.sh --prefix=$(MUSL_PREFIX)

# Auth tools: link against the full libauth object set + musl libc
$(addprefix $(BINDIR)/,  $(TOOLS_AUTH_BIN)):  $(BINDIR)/%:  $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(addprefix $(SBINDIR)/, $(TOOLS_AUTH_SBIN)): $(SBINDIR)/%: $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Simple POSIX tools: link only their own object, no libauth.
$(addprefix $(BINDIR)/, $(TOOLS_SIMPLE_BIN)): $(BINDIR)/%: $(SRCDIR)/%.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic compile rule
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR) $(SBINDIR):
	mkdir -p $@

clean:
	rm -f $(LIB_OBJS) $(SRCDIR)/*.o
	rm -f $(BIN_TARGETS) $(SBIN_TARGETS)
