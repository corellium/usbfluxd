#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.64)
AC_INIT([usbfluxd], [1.2.1], [https://corellium.com],, [https://corellium.com])
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip check-news])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_CONFIG_SRCDIR([usbfluxd/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES(libplist, libplist >= 2.2.0,
  [
    AC_DEFINE([HAVE_LIBPLIST], [1], [Use libplist])
    LIBPLIST=libplist
  ], [
    PKG_CHECK_MODULES(libplist, libplist-2.0 >= 2.2.0, [
    LIBPLIST=libplist-2.0
    AC_DEFINE([HAVE_LIBPLIST_2_0], [1], [Use libplist-2.0])
  ])],
)
AC_CHECK_LIB(pthread, [pthread_create, pthread_mutex_lock], [AC_SUBST(libpthread_LIBS,[-lpthread])], [AC_MSG_ERROR([libpthread is required to build usbfluxd])])

AC_SEARCH_LIBS([fmin], [m])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strcasecmp strdup strerror strndup stpcpy localtime_r])
AC_CHECK_FUNCS([ppoll clock_gettime])

# Check for operating system
AC_MSG_CHECKING([whether to enable WIN32 build settings])
AC_LDADD=
case ${host_os} in
  *mingw32*|*cygwin*)
    win32=true
    AC_MSG_RESULT([yes])
    AC_CHECK_TOOL([WINDRES], [windres], AC_MSG_ERROR([windres not found]))
    AC_SUBST(WINDRES)
    ;;
  darwin*)
    win32=false
    AC_MSG_RESULT([no])
    # No support for launchd yet
    AC_DEFINE(HAVE_CFNETWORK, 1, [Define to enable CFNetwork support])
    AC_LDADD="-framework CoreFoundation -framework CFNetwork"
    ;;
  *)
    win32=false
    AC_MSG_RESULT([no])
    PKG_CHECK_MODULES(avahi_client, avahi-client >= 0.6.32, have_avahi=yes, have_avahi=no)
    if test "x$have_avahi" = "xyes"; then
      AC_DEFINE(HAVE_AVAHI_CLIENT, 1, [Define to enable avahi-client support])
    fi
    ;;
esac
AC_SUBST(AC_LDADD)
AM_CONDITIONAL(WIN32, test x$win32 = xtrue)

AC_ARG_WITH([static-libplist],
            [AS_HELP_STRING(["--with-static-libplist[=/path/to/static/libplist"]],
            [link against a static libplist])],
            [with_static_libplist=$withval],
            [with_static_libplist=yes])
if test "x$with_static_libplist" != "xno"; then
  if test "x$with_static_libplist" = "xyes"; then
    STATIC_LIBPLIST="`pkg-config --libs-only-L ${LIBPLIST} |sed 's/^..//; s/[ ]*$/\/${LIBPLIST}.a/'`"
  else
    STATIC_LIBPLIST="$with_static_libplist"
  fi
  if ! test -f "$STATIC_LIBPLIST"; then
    AC_MSG_ERROR([The file ${STATIC_LIBPLIST} passed to --with-static-libplist does not exist])
  fi
  AC_SUBST(libplist_LIBS, [$STATIC_LIBPLIST])
fi

AS_COMPILER_FLAGS(GLOBAL_CFLAGS, "-g -Wall -Wextra -Wmissing-declarations -Wredundant-decls -Wshadow -Wpointer-arith  -Wwrite-strings -Wswitch-default -Wno-unused-parameter")
AC_SUBST(GLOBAL_CFLAGS)

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_OUTPUT([
Makefile
usbfluxd/Makefile
tools/Makefile
])

echo "
Configuration for $PACKAGE $VERSION:
-------------------------------------------

  install prefix ............: $prefix

  Now type 'make' to build $PACKAGE $VERSION,
  and then 'make install' for installation.
"
