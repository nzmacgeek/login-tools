AM_CPPFLAGS = -Isrc -D_GNU_SOURCE -Wno-unused-result -fno-stack-protector -isystem $(MUSL_INCLUDE)
AM_CFLAGS = -m32 -std=gnu11 -Wall -Wextra -O2
AM_LDFLAGS = -m32 -static -no-pie -Wl,-m,elf_i386 -L$(MUSL_LIB) -lc

AUTH_COMMON_SOURCES = \
    src/lib/util.c \
    src/lib/shadow.c \
    src/lib/passwd_file.c \
    src/lib/group_file.c \
    src/lib/policy.c \
    src/lib/faillock.c

bin_PROGRAMS = passwd login chsh chmod chown chgrp
sbin_PROGRAMS = setup-root useradd userdel usermod groupadd groupdel groupmod userlock

passwd_SOURCES = src/passwd.c $(AUTH_COMMON_SOURCES)
login_SOURCES = src/login.c $(AUTH_COMMON_SOURCES)
chsh_SOURCES = src/chsh.c $(AUTH_COMMON_SOURCES)

setup_root_SOURCES = src/setup-root.c $(AUTH_COMMON_SOURCES)
useradd_SOURCES = src/useradd.c $(AUTH_COMMON_SOURCES)
userdel_SOURCES = src/userdel.c $(AUTH_COMMON_SOURCES)
usermod_SOURCES = src/usermod.c $(AUTH_COMMON_SOURCES)
groupadd_SOURCES = src/groupadd.c $(AUTH_COMMON_SOURCES)
groupdel_SOURCES = src/groupdel.c $(AUTH_COMMON_SOURCES)
groupmod_SOURCES = src/groupmod.c $(AUTH_COMMON_SOURCES)
userlock_SOURCES = src/userlock.c $(AUTH_COMMON_SOURCES)

chmod_SOURCES = src/chmod.c
chown_SOURCES = src/chown.c
chgrp_SOURCES = src/chgrp.c

securityconfdir = $(sysconfdir)/security
dist_securityconf_DATA = pkg/payload/etc/security/pwpolicy.conf

sysrootdir = @SYSROOT@

install-exec-hook:
	chmod u+s "$(DESTDIR)$(bindir)/passwd" \
	           "$(DESTDIR)$(bindir)/login"  \
	           "$(DESTDIR)$(bindir)/chsh"
	$(MKDIR_P) "$(DESTDIR)/sbin"
	ln -sfn /usr/bin/login "$(DESTDIR)/sbin/login"

uninstall-hook:
	rm -f "$(DESTDIR)/sbin/login"

install-sysroot:
	$(MAKE) DESTDIR="$(sysrootdir)" prefix=/usr sysconfdir=/etc install

uninstall-sysroot:
	$(MAKE) DESTDIR="$(sysrootdir)" prefix=/usr sysconfdir=/etc uninstall
