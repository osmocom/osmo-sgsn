AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = v42bis_test.ok

check_PROGRAMS = v42bis_test

v42bis_test_SOURCES = v42bis_test.c

v42bis_test_LDADD = \
	$(top_builddir)/src/sgsn/v42bis.o \
	$(LIBOSMOCORE_LIBS)


