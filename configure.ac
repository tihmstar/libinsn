AC_PREREQ([2.69])
AC_INIT([libinsn], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++ "
        ;;
esac


CXXFLAGS+=" -std=c++14 -O3 -fPIC"
CFLAGS+=" -std=c11 -fPIC"
CXXFLAGS+=" -D EXPECTIONNAME=INSNexception"

# Checks for libraries.
LIBGENERAL_REQUIRES_STR="libgeneral >= 32"
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])


# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

LT_INIT

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libinsn/Makefile
		             libinsn.pc])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
"
echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
