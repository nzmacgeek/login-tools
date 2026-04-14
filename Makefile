CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -D_GNU_SOURCE -Isrc -Wno-unused-result
LDFLAGS = -lcrypt

# Set STATIC=1 to build static binaries (required for musl early-boot systems
# where the dynamic linker is not yet available).
#   make STATIC=1
#   make CC=x86_64-linux-musl-gcc STATIC=1
ifeq ($(STATIC),1)
CFLAGS  += -static
LDFLAGS += -static
endif

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
# These build correctly against musl without libcrypt.
TOOLS_SIMPLE_BIN = chmod chown chgrp

TOOLS_BIN  = $(TOOLS_AUTH_BIN) $(TOOLS_SIMPLE_BIN)
TOOLS_SBIN = $(TOOLS_AUTH_SBIN)

BIN_TARGETS  = $(addprefix $(BINDIR)/,  $(TOOLS_BIN))
SBIN_TARGETS = $(addprefix $(SBINDIR)/, $(TOOLS_SBIN))

.PHONY: all clean

all: $(BINDIR) $(SBINDIR) $(BIN_TARGETS) $(SBIN_TARGETS)

# Auth tools: link against the full libauth object set + libcrypt
$(addprefix $(BINDIR)/,  $(TOOLS_AUTH_BIN)):  $(BINDIR)/%:  $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(addprefix $(SBINDIR)/, $(TOOLS_AUTH_SBIN)): $(SBINDIR)/%: $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Simple POSIX tools: link only their own object, no libauth, no -lcrypt.
# Compatible with musl libc and suitable for static early-boot images.
$(addprefix $(BINDIR)/, $(TOOLS_SIMPLE_BIN)): $(BINDIR)/%: $(SRCDIR)/%.o
	$(CC) $(CFLAGS) -o $@ $^

# Generic compile rule
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR) $(SBINDIR):
	mkdir -p $@

clean:
	rm -f $(LIB_OBJS) $(SRCDIR)/*.o
	rm -f $(BIN_TARGETS) $(SBIN_TARGETS)
