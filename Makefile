CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -D_GNU_SOURCE -Isrc -Wno-unused-result
LDFLAGS = -lcrypt

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

TOOLS_BIN  = passwd login chsh
TOOLS_SBIN = setup-root useradd userdel usermod \
             groupadd groupdel groupmod userlock

BIN_TARGETS  = $(addprefix $(BINDIR)/,  $(TOOLS_BIN))
SBIN_TARGETS = $(addprefix $(SBINDIR)/, $(TOOLS_SBIN))

.PHONY: all clean

all: $(BINDIR) $(SBINDIR) $(BIN_TARGETS) $(SBIN_TARGETS)

# Link each tool against the shared library objects
$(BINDIR)/%: $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SBINDIR)/%: $(SRCDIR)/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic compile rule
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINDIR) $(SBINDIR):
	mkdir -p $@

clean:
	rm -f $(LIB_OBJS) $(SRCDIR)/*.o
	rm -f $(BIN_TARGETS) $(SBIN_TARGETS)
