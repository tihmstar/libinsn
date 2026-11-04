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
AC_PROG_CXX([clang++])
AC_PROG_CC([clang])

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++ "
        ;;
  *mingw32*|*cygwin*|*msys*)
  AC_MSG_RESULT([${host_os}])
  win32=true
  LDFLAGS+=" -no-undefined"
      ;;
esac

CXXFLAGS+=" -std=c++23 -fPIC"
CFLAGS+=" -std=c23 -fPIC"
CXXFLAGS+=" -D EXPECTIONNAME=INSNexception"

# Checks for libraries.
LIBGENERAL_REQUIRES_STR="libgeneral >= 238"
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

AC_ARG_WITH([sanitizers],
            [AS_HELP_STRING([--with-sanitizers],
            [build libplist with sanitizers (default is no)])],
            [build_sanitizers=${withval}],
            [])            

if test "$debug_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -DDEBUG=1"
  CXXFLAGS+=" -g -O0 -DDEBUG=1"
fi

if test "x$build_sanitizers" = "xyes"; then
    AS_COMPILER_FLAG([-fsanitize=address], [
        SANITIZER_FLAGS+=" -fsanitize=address"
        ASAN_AVAILABLE=yes
    ], [])
    if test "$ASAN_AVAILABLE" = "yes"; then
        AS_COMPILER_FLAG([-fsanitize=address -fsanitize-address-use-after-scope], [
            SANITIZER_FLAGS+=" -fsanitize-address-use-after-scope"
        ], [])
        SANITIZERS+="ASAN "
    fi

    AS_COMPILER_FLAG([-fsanitize=undefined], [
        SANITIZER_FLAGS+=" -fsanitize=undefined"
        UBSAN_AVAILABLE=yes
    ], [])

    if test "$UBSAN_AVAILABLE" = "yes"; then
        SANITIZERS+="UBSAN "
    fi

    if test -z "$SANITIZER_FLAGS"; then
        AC_MSG_ERROR([compiler doesn't support -fsanitize=address nor -fsanitize=undefined])
    fi

    COVERAGE_CHECKS="trace-pc-guard trace-cmp edge"
    for COV_CHECK in $COVERAGE_CHECKS; do
        AS_COMPILER_FLAG([-fsanitize-coverage=$COV_CHECK], [
            if test -z "$SAN_COV_FLAGS"; then
                SAN_COV_FLAGS="$COV_CHECK"
            else
                SAN_COV_FLAGS+=",$COV_CHECK"
            fi
        ], [])
    done
    if test -n "$SAN_COV_FLAGS"; then
        SANITIZER_FLAGS+=" -fsanitize-coverage=$SAN_COV_FLAGS"
        SANITIZERS+="+coverage "
    else
        AC_MSG_WARN([No sanitizer coverage supported by compiler])
    fi


    CFLAGS+=" $SANITIZER_FLAGS"
    CXXFLAGS+=" $SANITIZER_FLAGS"
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

# Check for functions
AC_CHECK_FUNCS([memmem])

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
  Enabled sanitizers ......: $SANITIZERS
"
echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
