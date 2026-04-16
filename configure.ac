AC_PREREQ([2.69])
AC_INIT([login-tools], [1.0.0], [https://github.com/nzmacgeek/blueyos/issues], [login-tools])
AC_CONFIG_SRCDIR([src/login.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects no-dependencies])

AC_PROG_INSTALL

AC_ARG_WITH(
    [musl-prefix],
    [AS_HELP_STRING([--with-musl-prefix=PATH], [Path to musl-blueyos sysroot (default: /opt/blueyos-sysroot if present, else ./build/musl)])],
    [MUSL_PREFIX="$withval"],
    [if test -d /opt/blueyos-sysroot; then
         MUSL_PREFIX="/opt/blueyos-sysroot"
     else
         MUSL_PREFIX="$ac_pwd/build/musl"
     fi]
)

AC_ARG_WITH(
    [sysroot],
    [AS_HELP_STRING([--with-sysroot=PATH], [Target BlueyOS sysroot install path (default: /opt/blueyos-sysroot)])],
    [SYSROOT="$withval"],
    [SYSROOT="/opt/blueyos-sysroot"]
)

MUSL_INCLUDE="$MUSL_PREFIX/include"
MUSL_LIB="$MUSL_PREFIX/lib"

dnl Use the musl-blueyos gcc wrapper as the compiler.
dnl Only override CC if the caller hasn't already set it.
if test -z "$CC"; then
    MUSL_CC="$MUSL_PREFIX/bin/musl-gcc"
    if test -x "$MUSL_CC"; then
        CC="$MUSL_CC"
    else
        dnl Fall back to musl-gcc in PATH (e.g. a system-wide install).
        AC_PATH_PROG([MUSL_GCC_IN_PATH], [musl-gcc])
        if test -n "$MUSL_GCC_IN_PATH"; then
            CC="$MUSL_GCC_IN_PATH"
        else
            AC_MSG_ERROR([musl-gcc not found in $MUSL_PREFIX/bin or PATH.
  Build musl-blueyos first:
    ./tools/build-musl.sh --prefix=build/musl
  Then re-run:
    ./configure --with-musl-prefix=build/musl
  Or pass CC explicitly:
    ./configure CC=/path/to/musl-gcc])
        fi
    fi
fi

AC_PROG_CC

AC_SUBST([MUSL_PREFIX])
AC_SUBST([MUSL_INCLUDE])
AC_SUBST([MUSL_LIB])
AC_SUBST([SYSROOT])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
