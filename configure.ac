dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-sgsn],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[osmocom-net-gprs@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl patching ${archive_cmds} to affect generation of file "libtool" to fix linking with clang
AS_CASE(["$LD"],[*clang*],
  [AS_CASE(["${host_os}"],
     [*linux*],[archive_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'])])

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl use a defined standard across all builds and don't depend on compiler default
CFLAGS="$CFLAGS -std=gnu11"

dnl checks for libraries
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.10.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 1.10.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl >= 1.10.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 1.10.0)
PKG_CHECK_MODULES(LIBOSMOGB, libosmogb >= 1.10.0)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 1.6.0)
PKG_CHECK_MODULES(LIBOSMOGSUPCLIENT, libosmo-gsup-client >= 1.8.0)
PKG_CHECK_MODULES(LIBGTP, libgtp >= 1.12.0)

# Enable/disable 3G aka IuPS + IuCS support?
AC_ARG_ENABLE([iu], [AS_HELP_STRING([--enable-iu], [Build 3G support, aka IuPS and IuCS interfaces])],
    [osmo_ac_iu="$enableval"],[osmo_ac_iu="no"])
if test "x$osmo_ac_iu" = "xyes" ; then
    PKG_CHECK_MODULES(LIBOSMOSIGTRAN, libosmo-sigtran >= 1.9.0)
    PKG_CHECK_MODULES(LIBASN1C, libasn1c >= 0.9.30)
    PKG_CHECK_MODULES(LIBOSMORANAP, libosmo-ranap >= 1.6.0)
    AC_DEFINE(BUILD_IU, 1, [Define if we want to build IuPS and IuCS interfaces support])
fi
AM_CONDITIONAL(BUILD_IU, test "x$osmo_ac_iu" = "xyes")
AC_SUBST(osmo_ac_iu)

PKG_CHECK_MODULES(LIBCARES, libcares)

dnl checks for header files
AC_HEADER_STDC

dnl Checks for typedefs, structures and compiler characteristics

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

CPPFLAGS="$CPPFLAGS -Wall -Wno-trigraphs"
CFLAGS="$CFLAGS -Wall -Wno-trigraphs"

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi

AC_DEFUN([CHECK_TM_INCLUDES_TM_GMTOFF], [
  AC_CACHE_CHECK(
    [whether struct tm has tm_gmtoff member],
    osmo_cv_tm_includes_tm_gmtoff,
    [AC_LINK_IFELSE([
      AC_LANG_PROGRAM([
        #include <time.h>
      ], [
        time_t t = time(NULL);
        struct tm* lt = localtime(&t);
        int off = lt->tm_gmtoff;
      ])
    ],
    osmo_cv_tm_includes_tm_gmtoff=yes,
    osmo_cv_tm_includes_tm_gmtoff=no
    )]
  )
  if test "x$osmo_cv_tm_includes_tm_gmtoff" = xyes; then
    AC_DEFINE(HAVE_TM_GMTOFF_IN_TM, 1,
              [Define if struct tm has tm_gmtoff member.])
  fi
])

CHECK_TM_INCLUDES_TM_GMTOFF

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AC_CHECK_PROG(PYTHON3_AVAIL,python3,yes)
	 if test "x$PYTHON3_AVAIL" != "xyes" ; then
		AC_MSG_ERROR([Please install python3 to run the VTY/CTRL tests.])
	fi
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install https://gitea.osmocom.org/cellular-infrastructure/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

# Generate manuals
AC_ARG_ENABLE(manuals,
	[AS_HELP_STRING(
		[--enable-manuals],
		[Generate manual PDFs [default=no]],
	)],
	[osmo_ac_build_manuals=$enableval], [osmo_ac_build_manuals="no"])
AM_CONDITIONAL([BUILD_MANUALS], [test x"$osmo_ac_build_manuals" = x"yes"])
AC_ARG_VAR(OSMO_GSM_MANUALS_DIR, [path to common osmo-gsm-manuals files, overriding pkg-config and "../osmo-gsm-manuals"
	fallback])
if test x"$osmo_ac_build_manuals" = x"yes"
then
	# Find OSMO_GSM_MANUALS_DIR (env, pkg-conf, fallback)
	if test -n "$OSMO_GSM_MANUALS_DIR"; then
		echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from env)"
	else
		OSMO_GSM_MANUALS_DIR="$($PKG_CONFIG osmo-gsm-manuals --variable=osmogsmmanualsdir 2>/dev/null)"
		if test -n "$OSMO_GSM_MANUALS_DIR"; then
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from pkg-conf)"
		else
			OSMO_GSM_MANUALS_DIR="../osmo-gsm-manuals"
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (fallback)"
		fi
	fi
	if ! test -d "$OSMO_GSM_MANUALS_DIR"; then
		AC_MSG_ERROR("OSMO_GSM_MANUALS_DIR does not exist! Install osmo-gsm-manuals or set OSMO_GSM_MANUALS_DIR.")
	fi

	# Find and run check-depends
	CHECK_DEPENDS="$OSMO_GSM_MANUALS_DIR/check-depends.sh"
	if ! test -x "$CHECK_DEPENDS"; then
		CHECK_DEPENDS="osmo-gsm-manuals-check-depends"
	fi
	if ! $CHECK_DEPENDS; then
		AC_MSG_ERROR("missing dependencies for --enable-manuals")
	fi

	# Put in Makefile with absolute path
	OSMO_GSM_MANUALS_DIR="$(realpath "$OSMO_GSM_MANUALS_DIR")"
	AC_SUBST([OSMO_GSM_MANUALS_DIR])
fi

# https://www.freedesktop.org/software/systemd/man/daemon.html
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

dnl Generate the output
AM_CONFIG_HEADER(config.h)

AC_OUTPUT(
    include/Makefile
    include/osmocom/Makefile
    include/osmocom/gtphub/Makefile
    include/osmocom/sgsn/Makefile
    src/Makefile
    src/gprs/Makefile
    src/sgsn/Makefile
    src/gtphub/Makefile
    tests/Makefile
    tests/atlocal
    tests/gprs/Makefile
    tests/gprs_routing_area/Makefile
    tests/sgsn/Makefile
    tests/gtphub/Makefile
    tests/xid/Makefile
    tests/sndcp_xid/Makefile
    tests/slhc/Makefile
    tests/v42bis/Makefile
    doc/Makefile
    doc/examples/Makefile
    doc/manuals/Makefile
    contrib/Makefile
    contrib/systemd/Makefile
    Makefile)
